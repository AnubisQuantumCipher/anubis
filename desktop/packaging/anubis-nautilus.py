# ANUBIS entries in the Nautilus context menu.
#
# Three items, and the split between them is the whole point:
#
#   "Encrypt with ANUBIS..."  hands the paths to the desktop application,
#                             because encryption needs a recipient and choosing
#                             one is a decision, not a default.
#   "Encrypt to myself"       runs the engine directly, because there is exactly
#                             one sane recipient in that case and asking would
#                             be ceremony.
#   "Decrypt with ANUBIS"     hands the container to the application, which owns
#                             the overwrite gate and shows the header before
#                             anything is written.
#
# This file performs no cryptography. It spawns `anubis` or `anubis-desktop`
# and gets out of the way. It never passes a passphrase, never reads a key, and
# never writes a file itself.
#
# Installed to ~/.local/share/nautilus-python/extensions/. Nautilus imports it
# at startup, so a change needs `nautilus -q`.

import os
import shutil
import subprocess

import gi

gi.require_version("Nautilus", "4.1")
from gi.repository import Nautilus, GObject, Gio

CONTAINER_MIME = "application/vnd.anubis.container"
CONTAINER_SUFFIX = ".anubis"


def _engine():
    """The encryption engine, or None.

    Resolved by content, not by name. There is more than one program called
    `anubis` -- a language toolchain of the same name has held this very path
    on this machine -- and spawning the wrong one from a context menu would be
    silent. `--help` parses arguments and nothing else.
    """
    candidates = [
        os.path.expanduser("~/.cargo/bin/anubis"),
        os.path.expanduser("~/.local/bin/anubis"),
        "/usr/local/bin/anubis",
        "/usr/bin/anubis",
    ]
    found = shutil.which("anubis")
    if found:
        candidates.append(found)

    for path in candidates:
        if not (os.path.isfile(path) and os.access(path, os.X_OK)):
            continue
        try:
            out = subprocess.run(
                [path, "--help"], capture_output=True, text=True, timeout=2
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if "post-quantum file encryption" in out.lower():
            return path
    return None


def _app():
    return shutil.which("anubis-desktop")


def _own_recipient(engine):
    """This machine's first identity, as a recipient key. None if there is no
    identity yet -- in which case "Encrypt to myself" has no meaning and is not
    offered, rather than being offered and then failing."""
    try:
        import json

        out = subprocess.run(
            [engine, "status", "--json"], capture_output=True, text=True, timeout=5
        ).stdout
        for line in out.splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("kind") == "status":
                ids = rec.get("identities") or []
                if ids:
                    return ids[0].get("recipient")
        return None
    except (OSError, subprocess.SubprocessError):
        return None


def _is_container(f):
    return (
        f.get_mime_type() == CONTAINER_MIME
        or f.get_name().endswith(CONTAINER_SUFFIX)
    )


def _local_pairs(files):
    """(path, file) pairs for the local regular files in the selection.

    Paired at the source. Filtering paths and files separately and zipping
    them back together misaligns the two lists the moment anything is
    dropped -- a directory in a mixed selection would shift every later
    path onto the wrong file object, and the wrong menu item onto the
    wrong target."""
    out = []
    for f in files:
        if f.get_uri_scheme() != "file" or f.is_directory():
            continue
        path = f.get_location().get_path()
        if path:
            out.append((path, f))
    return out


def _spawn(argv):
    try:
        Gio.Subprocess.new(argv, Gio.SubprocessFlags.NONE)
    except GObject.GError:
        pass


def _open_in_app(_menu, paths):
    app = _app()
    if not app:
        return
    # The application is single instance: a second launch hands its argument to
    # the running window. One call per path, so a multi-selection ends up with
    # the last one loaded rather than N windows.
    for path in paths:
        _spawn([app, path])


def _encrypt_to_self(_menu, paths):
    engine = _engine()
    if not engine:
        return
    recipient = _own_recipient(engine)
    if not recipient:
        return
    for path in paths:
        # No --force. An existing output is the engine's to refuse; a context
        # menu is the last place that should be allowed to overwrite silently.
        _spawn([
            engine, "encrypt",
            "-r", recipient,
            "-o", path + CONTAINER_SUFFIX,
            path,
        ])


class AnubisMenuProvider(GObject.GObject, Nautilus.MenuProvider):
    def get_file_items(self, files):
        pairs = _local_pairs(files)
        if not pairs:
            return []

        containers = [p for p, f in pairs if _is_container(f)]
        plain = [p for p, f in pairs if not _is_container(f)]

        items = []

        if containers and _app():
            item = Nautilus.MenuItem(
                name="Anubis::decrypt",
                label="Decrypt with ANUBIS",
                tip="Open in the ANUBIS Vault to inspect the header and decrypt",
                icon="dev.anubis.Vault",
            )
            item.connect("activate", _open_in_app, containers)
            items.append(item)

        if plain:
            if _app():
                item = Nautilus.MenuItem(
                    name="Anubis::encrypt",
                    label="Encrypt with ANUBIS…",
                    tip="Choose recipients in the ANUBIS Vault",
                    icon="dev.anubis.Vault",
                )
                item.connect("activate", _open_in_app, plain)
                items.append(item)

            engine = _engine()
            if engine and _own_recipient(engine):
                item = Nautilus.MenuItem(
                    name="Anubis::encrypt_self",
                    label="Encrypt to myself",
                    tip="Encrypt to this machine's own identity, in place",
                )
                item.connect("activate", _encrypt_to_self, plain)
                items.append(item)

        return items

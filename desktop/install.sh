#!/usr/bin/env bash
# Build and install ANUBIS Vault into a prefix, then refresh the desktop
# databases so the launcher and the .anubis file association pick it up.
#
# Defaults to ~/.local, which needs no root and is already on the session's
# XDG_DATA_DIRS. Pass a prefix to install elsewhere:
#
#   ./install.sh                 -> ~/.local
#   ./install.sh /usr/local      -> system-wide (needs write access)
set -euo pipefail

PREFIX="${1:-$HOME/.local}"
SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SRC_DIR/build"

echo "==> building"
configure() {
  cmake -S "$SRC_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" >/dev/null
}
# Qt's OpenGL probe (WrapOpenGL) has been observed to fail spuriously on the
# very first configure in a fresh build directory and then succeed unchanged
# on the next run. One guarded retry keeps that flake from reading as a
# broken package; a real configuration error still fails, twice and loudly.
if ! configure; then
  echo "==> configure failed; retrying once"
  configure
fi
cmake --build "$BUILD_DIR" --parallel

echo "==> installing to $PREFIX"
cmake --install "$BUILD_DIR" >/dev/null

# Each of these is best-effort. A missing cache tool means the entry shows up
# on the next login instead of immediately, which is not worth failing over.
echo "==> refreshing desktop databases"
if command -v update-desktop-database >/dev/null; then
  update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
fi
if command -v update-mime-database >/dev/null; then
  update-mime-database "$PREFIX/share/mime" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null; then
  gtk-update-icon-cache -qtf "$PREFIX/share/icons/hicolor" 2>/dev/null || true
fi

echo
echo "installed:"
echo "  binary        $PREFIX/bin/anubis-desktop"
echo "  desktop entry $PREFIX/share/applications/dev.anubis.Vault.desktop"
echo "  app icon      $PREFIX/share/icons/hicolor/scalable/apps/dev.anubis.Vault.svg"
echo "  mime types    application/vnd.anubis.container (with its own icon), text/x-anubis"
echo "  nautilus      $PREFIX/share/nautilus-python/extensions/anubis.py (needs nautilus-python)"
echo

# The program is a renderer; without the engine it can only draw an install
# hint. Say so at install time rather than letting the first launch be the
# first anyone hears of it.
if ! command -v anubis >/dev/null && [ ! -x "$HOME/.cargo/bin/anubis" ] \
    && [ ! -x "$HOME/.local/bin/anubis" ]; then
  echo "NOTE: the anubis engine was not found on PATH."
  echo "      This application performs no cryptography of its own; it drives"
  echo "      the engine. Install it with:"
  echo
  if [ -d "$SRC_DIR/../crates/anubis-cli" ]; then
    echo "        cargo install --path $SRC_DIR/../crates/anubis-cli"
  else
    echo "        cargo install --git https://github.com/AnubisQuantumCipher/anubis anubis-cli"
  fi
  echo
fi

case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "NOTE: $PREFIX/bin is not on your PATH." ;;
esac

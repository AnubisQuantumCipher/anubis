# khephri.anubis

The Omarchy bar surface for **ANUBIS** — post-quantum file encryption.

<img src="https://raw.githubusercontent.com/AnubisQuantumCipher/anubis/main/docs/screenshots/bar-plugin.png" alt="The dropdown: identity fingerprints, recent operations, Open ANUBIS Vault" width="420" align="right">

A compact bar indicator and a bar-anchored dropdown. The plugin reads the
`anubis` engine's JSON and draws it. It holds no key material, derives no
secret, performs no cryptography, and reaches no verification verdict of its
own.

```
manifest.json   plugin metadata, bar-widget settings schema
Panel.qml       the bar face and its dropdown
Service.qml     engine driver -- one instance per session, read-only
Model.js        pure helpers -- formatting, parsing, tone mapping
```

## What this is, and what it is not

**This surface is a READOUT.** Everything that changes state — encrypt,
decrypt, keygen, the recipient address book — lives in the **ANUBIS Vault**
desktop application (`anubis-desktop`), one click away.

That split is deliberate. A dropdown is a surface any stray click dismisses,
which makes it the wrong place for a multi-step operation and a worse place for
a confirmation gate. So the dropdown answers the questions you would otherwise
open the app for, and hands you the app for everything else.

Until v2.0.0 this plugin carried a 2904-line full-screen cockpit that was
near-identical to the application's. Two copies of one honesty-audited surface,
in two directories with nothing keeping them in sync, is a defect waiting to
happen — a fix landing in one and silently missing the other. v3.0.0 keeps the
bar presence a window cannot provide and gives the cockpit to the app.

## Installing

The plugin is only a renderer; it needs the engine.

```
cargo install --git https://github.com/AnubisQuantumCipher/anubis anubis-cli
```

Until that succeeds the dropdown renders an install hint rather than a broken
surface, and clicking the hint copies the command.

For the cockpit, install the desktop application from
the `desktop/` directory of the anubis repository (`./install.sh`). Without it the dropdown still
reads correctly; only the route out of it stops leading anywhere.

The widget is registered in `~/.config/omarchy/shell.json` under
`bar.layout.right` as `{"id": "khephri.anubis"}`.

## The bar face

- A shield glyph whose shape carries the vault state, and the identity count
  beside it.
- A state dot: accent when ready, urgent when the last operation failed or the
  status could not be read, dim when no engine is installed.
- A tooltip on hover: engine version, identity and recipient counts, the last
  failure's reason, and the cipher suite.
- **Left-click** opens the dropdown. **Right-click** re-probes for the engine.

The dot does not pulse. It used to claim to pulse "only while the engine is
actually moving bytes", but no bar surface has ever launched an operation, so
the flag it watched was permanently false and the animation was unreachable.
Now that every operation belongs to the application, it can never become true —
so the claim is gone rather than carried forward.

## The dropdown

Nothing the tooltip already shows is repeated here. Every section carries
either a fact a tooltip structurally cannot hold, or an interaction a tooltip
cannot host — a tooltip has no mouse area, so nothing in one can ever be
copied.

| Section | Why it earns its place |
| --- | --- |
| **Hero** — version, and how long ago the readout was taken | The version is in the tooltip; the **age** is not. Nothing else distinguishes "polled 8 seconds ago" from "the poll wedged an hour ago", and every other number here is only as true as that timestamp. |
| **Status error** | Without it an empty readout is indistinguishable from an empty vault. |
| **Identity** — the effective identity, with both fingerprints | A fingerprint's whole purpose is out-of-band comparison and pasting. Click a plate to copy the fingerprint; click `⧉ key` to copy the full ~2573-character recipient. |
| **Recent** — the last five operations | The tooltip names a failure only when the *newest* operation failed; it is a state, not a history. Each row is a route into the app. |
| **Open ANUBIS Vault** | Pinned outside the scroll area. It is the whole contract of this surface. |
| **The boundary line** | Pinned too — it is the line that must never be scrolled away. |

Deliberately absent: the ledger counts (a permanently red cumulative
`280 failed` is alarm fatigue, not information), the activity strip (a sparkline
that needs a paragraph to read is a cockpit object), the address book, and the
container inspector. The application owns all four.

| Key | Action |
| --- | --- |
| `Esc` | close |
| `o` | open the application |
| `r` | poll the engine now |
| `Return` / `Space` | open the application |
| `Tab` | rotate to the neighbouring bar dropdown |

## IPC

The historic target name is kept, so existing scripts still work:

```
qs ipc call anubis toggle
qs ipc call anubis vaultState        # -> ready | failed | error | unknown | absent
qs ipc call anubis poll
qs ipc call anubis inspect /path/to/file.anubis   # opens it in the application
```

`inspect` now opens the container in the application rather than drawing an
inspector the dropdown no longer has.

## One poller

The engine driver is declared as a `service` kind in the manifest, so the shell
creates exactly **one** instance per session and the bar surface reads it
through `serviceFor("khephri.anubis")`. An inline `Service {}` in the widget
would be instantiated once per monitor, because the bar builds one surface per
screen.

Before v3.0.0 there were two inside the shell — the bar widget built its own
and the overlay built another — plus a third if the application was running.

## Settings

Inline on the bar layout entry in `shell.json`. The service reads its own entry
and watches the file, so a change lands without a shell restart.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `pollIntervalSec` | integer 5-600 | `30` | how often `anubis status --json` is re-read |
| `defaultIdentity` | string | `""` | which identity the dropdown shows; empty means the first the engine reports |

`confirmOverwrite` and `motionEnabled` are gone. The first was a write policy on
a surface that cannot write; the second existed for the overlay's fades and the
dot's pulse, both of which are gone.

## Fingerprints are the handle

An ANUBIS recipient is roughly **2573 bech32 characters** — past the length at
which bech32's checksum still guarantees error detection. So every identity
carries an 80-bit fingerprint (SHA-256, five groups of four uppercase hex), and
that is what this panel puts in front of you. The full key is reachable only
through an explicit copy action.

There are **two fingerprint namespaces** and they are not interchangeable:

| Kind | Hashes | Answers |
| --- | --- | --- |
| `recipient` | the KEM recipient payload | who can decrypt this |
| `signer` | the ML-DSA-87 verifying key | who wrote this |

Comparing one against the other produces a falsehood, so no fingerprint is ever
drawn without its kind beside it, and each gets its own full-width line so it
can never be truncated. Where a theme makes the string too wide for one line it
breaks on a group boundary with both lines starting on a hex digit — a
mid-group split is the same silent half-truth as an elide.

## What the colours mean

- **Urgent** marks a failed or refused result — an operation that died, a check
  that did not pass, or an unreadable status response.
- **Accent** is general emphasis for interaction, operational readiness, and
  successful engine results. Colour alone is never an assurance claim; the
  accompanying text names the state.
- **Neutral** covers *unknown* and *not applicable*, including a container from
  an older, unsupported wire format. An old file is not a tampered file, so it
  reads as `unsupported` in a neutral tone, never as a failure.

## Honesty rules this surface keeps

- A field the engine did not state renders as *not stated*, never as a pass.
- A failed poll clears the status rather than leaving the last good one on
  screen — a dead binary must not go on asserting that everything is fine.
- A poll is accepted only when the child exits successfully and emits exactly
  one complete, duplicate-free, schema-valid status record. Probe candidates
  and poll children have TERM-to-KILL deadlines, and status output is capped
  before it reaches the long-lived readout.
- The readout's age is always on screen, because every other number depends on
  it.
- The boundary line is pinned outside the scroll area.
- The compact panel shows the accepted engine suite but intentionally carries
  no NIST/FIPS badge. The desktop cockpit is the surface that renders the full
  reviewed profile and explicit `NOT FIPS 140-3 VALIDATED` state. Neither
  surface infers module validation from an algorithm publication number.
- The assurance fields use a versioned status schema. A pre-assurance engine
  remains usable during a non-atomic upgrade, while partial or unknown
  assurance schemas are rejected. The current schema is a closed profile: any
  changed algorithm, standard, category, profile, approved-mode, validation,
  or certificate field is rejected before it can make the bar `ready`.
- Poll stdout and stderr are captured only to the cap plus one byte, measured
  with `wc -c`, and released only after that raw-byte check succeeds.
  Successful records must leave stderr completely empty, including no
  whitespace, and the deadline escalates from TERM to KILL. A failed boundary
  check clears the prior readout.
- Nothing here claims a behaviour it cannot perform.

Operations are appended by the engine to `~/.local/state/anubis/audit.jsonl`
where any log tailer (SIA, on machines that run it) can consume it. The
engine writes no `status.json`,
so nothing here watches for one.

## Licence

MIT OR Apache-2.0

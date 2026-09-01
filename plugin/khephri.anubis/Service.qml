import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

// Reads the `anubis` engine and holds everything the bar surfaces render.
//
// Four rules shape this file.
//
//   The engine is the only authority. This service spawns `anubis status
//   --json`, reads its JSON, and stores it. It never derives a cryptographic
//   conclusion, never fills in a field the engine omitted, and never keeps a
//   previous success alive across a failed run -- a dead binary must not go on
//   asserting that the last operation was fine.
//
//   It is READ-ONLY. The only subprocesses it ever spawns are `anubis status
//   --json` and a one-shot engine probe. Encrypt, decrypt, keygen and the
//   address book left with the cockpit and now belong to the ANUBIS Vault
//   desktop application, which owns its own engine driver. A surface that
//   cannot write cannot corrupt a vault by mistake.
//
//   Nothing blocks. Every invocation is an asynchronous Process, so the bar
//   keeps painting.
//
//   The binary may be absent. That is an ordinary state, not an error: the
//   engine is installed separately, so a fresh machine simply has no engine
//   yet. `engineMissing` drives an install hint instead of a broken surface.
//
// There is exactly ONE of these per session. It is instantiated by the shell
// from the manifest's `service` kind rather than inline in the bar widget,
// because the bar builds one surface per monitor and an inline driver would
// poll once per screen.
Item {
  id: root

  // Injected by the host when it creates a `service` plugin. Present so the
  // shape is documented even though nothing here uses them yet.
  property var shell: null
  property var manifest: ({})

  // The host does NOT inject bar-layout settings into a service, so this reads
  // its own entry out of shell.json rather than waiting for a widget to assign
  // one. Forget this and the poll interval silently reverts to the default.
  property var settings: ({})
  readonly property var opts: Model.resolveSettings(settings)

  readonly property string home: Quickshell.env("HOME") || ""
  readonly property string configDir: home + "/.config/anubis"
  readonly property string stateDir: home + "/.local/state/anubis"

  // ---- engine presence -----------------------------------------------------
  //
  // Resolved once at load and re-resolved on demand. `enginePath` empty means
  // no executable was found in any of the places `cargo install` and the
  // distribution packages put one.
  property string enginePath: ""
  property bool engineProbed: false
  readonly property bool engineMissing: engineProbed && enginePath === ""
  readonly property string installHint: Model.installHint()

  // Both child streams are captured through `head` one byte past this limit.
  // The shell then uses `wc -c` on those bounded files before releasing any
  // bytes to the long-lived shell process, so the boundary remains a raw-byte
  // boundary even for multibyte UTF-8.
  readonly property int maxStatusOutputBytes: 4194304

  // ---- status --------------------------------------------------------------
  property var status: null
  property string statusError: ""
  property double statusAtMs: 0
  property double nowMs: Date.now()
  readonly property bool statusBusy: statusProc.running

  readonly property var identities: Model.identities(status)
  readonly property var recipients: Model.recipients(status)
  readonly property var recentOps: Model.recentOps(status)
  readonly property var suite: Model.suiteOf(status)
  readonly property string version: Model.engineVersion(status)

  // ---- transient feedback --------------------------------------------------
  property string actionStatus: ""

  // ==========================================================================
  // lifecycle
  // ==========================================================================

  Component.onCompleted: {
    nowMs = Date.now()
    probeEngine()
  }

  // Locate the executable. `cargo install` lands in ~/.cargo/bin, which is on
  // an interactive PATH but not necessarily on the compositor's, so the known
  // locations are checked explicitly before falling back to a PATH lookup.
  function probeEngine() {
    if (probeProc.running) return
    probeProc.outText = ""
    probeProc.running = true
  }

  function refresh() {
    if (enginePath === "") { probeEngine(); return }
    if (statusProc.running) return
    statusProc.outText = ""
    statusProc.errText = ""
    statusProc.command = [
      "/usr/bin/bash", "-c",
      "set -u; limit=4194304; "
        + "work=$(/usr/bin/mktemp -d /tmp/anubis-status.XXXXXX) || exit 126; "
        + "cleanup() { /usr/bin/unlink \"$work/out\" 2>/dev/null || :; "
        + "/usr/bin/unlink \"$work/err\" 2>/dev/null || :; "
        + "/usr/bin/rmdir -- \"$work\" 2>/dev/null || :; }; "
        + "trap cleanup EXIT; set +e; "
        + "/usr/bin/timeout --signal=TERM --kill-after=2s 15s "
        + "\"$1\" status --json "
        + "> >(/usr/bin/head -c 4194305 > \"$work/out\") "
        + "2> >(/usr/bin/head -c 4194305 > \"$work/err\"); "
        + "rc=$?; wait; "
        + "out_bytes=$(/usr/bin/wc -c < \"$work/out\"); "
        + "err_bytes=$(/usr/bin/wc -c < \"$work/err\"); "
        + "if [ \"$out_bytes\" -gt \"$limit\" ] "
        + "|| [ \"$err_bytes\" -gt \"$limit\" ]; then exit 125; fi; "
        + "/usr/bin/cat -- \"$work/out\"; "
        + "/usr/bin/cat -- \"$work/err\" >&2; exit \"$rc\"",
      "anubis-status", enginePath
    ]
    statusProc.running = true
  }

  function applyStatus(raw, stderrText, exitCode) {
    var rawStderr = String(stderrText || "")
    var displayStderr = rawStderr.replace(/^\s+|\s+$/g, "")
    var parsed = null
    var parsedCount = 0
    var protocolValid = true
    if (exitCode === 125
        || String(raw || "").length > maxStatusOutputBytes
        || rawStderr.length > maxStatusOutputBytes) {
      status = null
      statusError = "status output exceeded the safe readout limit"
      statusAtMs = Date.now()
      nowMs = statusAtMs
      return
    }
    var trimmed = String(raw || "").replace(/^\s+|\s+$/g, "")
    if (trimmed !== "") {
      var lines = trimmed.split("\n")
      for (var i = 0; i < lines.length; i++) {
        var o = Model.parseLine(lines[i])
        if (Model.validStatusRecord(o)) {
          parsed = o
          parsedCount += 1
        } else protocolValid = false
      }
    }
    if (!Model.statusResponseAccepted(parsed, exitCode, rawStderr,
                                       protocolValid, parsedCount)) {
      status = null
      statusError = rawStderr !== ""
        ? (displayStderr !== "" ? displayStderr
                                : "anubis status wrote to stderr")
        : (exitCode === 127 ? "anubis could not execute"
            : (exitCode === 124 ? "anubis status timed out"
              : (exitCode !== 0 ? "anubis status exited " + exitCode
                                : "status produced no complete payload")))
    } else {
      status = parsed
      statusError = ""
    }
    statusAtMs = Date.now()
    nowMs = statusAtMs
  }

  // ==========================================================================
  // clipboard
  // ==========================================================================
  //
  // A full recipient is thousands of characters; the clipboard is the only
  // sane way to move one. Everything that leaves this panel goes through here
  // so there is one place that decides what can be copied.
  function copyText(text, description) {
    var value = String(text || "")
    if (value === "") return
    copyProc.running = false
    copyProc.command = ["/usr/bin/wl-copy", "--", value]
    copyProc.running = true
    actionStatus = "Copied " + description
    statusClear.restart()
  }

  // ==========================================================================
  // processes
  // ==========================================================================

  Process {
    id: probeProc
    property string outText: ""
    // Each candidate is identity-checked before it is accepted. There is more
    // than one program called `anubis` -- a language toolchain of the same name
    // has been known to hold this very path -- and accepting one on its
    // filename alone means the bar would silently drive the wrong tool and
    // report a dead vault with no cause. `--help` parses arguments and nothing
    // else: it reads no key and writes no file.
    command: ["/usr/bin/timeout", "--signal=TERM", "--kill-after=2s", "15s",
      "/usr/bin/env", "sh", "-c",
      "is_engine() { /usr/bin/timeout --signal=TERM --kill-after=2s 15s "
      + "\"$1\" --help 2>/dev/null | "
      + "grep -qi 'post-quantum file encryption'; }; "
      + "for p in \"$HOME/.cargo/bin/anubis\" \"$HOME/.local/bin/anubis\" "
      + "/usr/local/bin/anubis /usr/bin/anubis; do "
      + "[ -x \"$p\" ] && is_engine \"$p\" && { printf %s \"$p\"; exit 0; }; done; "
      + "p=$(command -v anubis 2>/dev/null) || exit 0; "
      + "[ -n \"$p\" ] && is_engine \"$p\" && printf %s \"$p\""]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: probeProc.outText = String(text || "")
    }
    onExited: function (code) {
      var candidate = probeProc.outText.replace(/^\s+|\s+$/g, "")
      root.enginePath = code === 0
        && candidate.length <= root.maxStatusOutputBytes ? candidate : ""
      root.engineProbed = true
      if (root.enginePath !== "") root.refresh()
      else {
        root.status = null
        root.statusError = ""
      }
    }
  }

  Process {
    id: statusProc
    property string outText: ""
    property string errText: ""
    property int exitCode: 0
    property bool exited: false
    property bool outDone: false
    property bool errDone: false

    function settle() {
      if (!exited || !outDone || !errDone) return
      root.applyStatus(outText, errText, exitCode)
    }

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        statusProc.outText = String(text || "")
        statusProc.outDone = true
        statusProc.settle()
      }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        statusProc.errText = String(text || "")
        statusProc.errDone = true
        statusProc.settle()
      }
    }
    onRunningChanged: if (running) {
      exited = false; outDone = false; errDone = false; exitCode = 0
    }
    onExited: function (code) {
      statusProc.exitCode = code
      statusProc.exited = true
      statusProc.settle()
    }
  }

  Process { id: copyProc; command: ["/usr/bin/true"] }

  // ==========================================================================
  // timers and watches
  // ==========================================================================

  Timer {
    id: statusClear
    interval: 2500
    repeat: false
    onTriggered: root.actionStatus = ""
  }

  Timer {
    interval: Math.max(5, root.opts.pollIntervalSec) * 1000
    running: root.enginePath !== ""
    repeat: true
    onTriggered: root.refresh()
  }

  // Drives the relative timestamps -- "3m ago" on the hero and on every
  // operation row. Fifteen seconds is finer than the resolution those strings
  // actually change at, and nothing else wakes for it.
  Timer {
    interval: 15000
    running: true
    repeat: true
    onTriggered: root.nowMs = Date.now()
  }

  // This plugin's own bar entry in shell.json, watched so a settings change
  // lands without a shell restart. The engine's state directory is NOT
  // watched: the engine writes only audit.jsonl there, and the status.json a
  // previous version of this file watched has never existed -- a FileView on a
  // path nothing writes is a permanent silent error path, not a fallback.
  FileView {
    id: shellSettings
    path: root.home + "/.config/omarchy/shell.json"
    watchChanges: true
    printErrors: false
    onLoaded: root.settings =
      Model.settingsFromShellJson(text(), "khephri.anubis")
    onFileChanged: settingsSettle.restart()
  }

  Timer {
    id: settingsSettle
    interval: 200
    repeat: false
    onTriggered: {
      shellSettings.reload()
      root.settings =
        Model.settingsFromShellJson(shellSettings.text(), "khephri.anubis")
    }
  }
}

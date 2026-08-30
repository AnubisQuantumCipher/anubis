import QtQuick
import Anubis
import "Model.js" as Model

// Drives the `anubis` engine and holds everything the vault surfaces render.
//
// Three rules shape this file.
//
//   The engine is the only authority. This service spawns processes, reads
//   their JSON, and stores it. It never derives a cryptographic conclusion,
//   never fills in a field the engine omitted, and never keeps a previous
//   success alive across a failed run -- a dead binary must not go on
//   asserting that the last operation was fine.
//
//   Nothing blocks. Every invocation is an asynchronous Process. Long
//   operations stream `{"kind":"progress"}` lines through a SplitParser so
//   the bar keeps painting while a gigabyte moves.
//
//   The binary may be absent. That is an ordinary state, not an error: the
//   engine is installed with `cargo install`, so a fresh machine simply has
//   no engine yet. `engineMissing` drives an install hint instead of a
//   broken surface, and every action refuses cleanly while it holds.
//
// Three things this file used to spawn a subprocess for -- locating the
// engine, testing whether an output already exists, and putting a recipient on
// the clipboard -- are now direct calls into the application. None of them
// needed a shell, and a standalone program should not require `sh`, `test`,
// and `wl-copy` to be installed in order to refuse an operation politely.
Item {
  id: root

  // Settings, assigned by the window from the application's own settings
  // file. Unset keys fall back to the documented defaults in Model.js.
  property var settings: ({})
  readonly property var opts: Model.resolveSettings(settings)

  readonly property string home: App.env("HOME") || ""
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

  // ---- status --------------------------------------------------------------
  property var status: null
  property string statusError: ""
  property double statusAtMs: 0
  property double nowMs: Date.now()
  readonly property bool statusBusy: statusProc.running

  readonly property var identities: Model.identities(status)
  readonly property var recipients: Model.recipients(status)
  readonly property var recentOps: Model.recentOps(status)
  readonly property var counts: Model.counts(status)
  readonly property var suite: Model.suiteOf(status)
  readonly property string version: Model.engineVersion(status)
  readonly property bool canSign: Model.canSign(status)

  // ---- streaming operation -------------------------------------------------
  property string opKind: ""            // "encrypt" | "decrypt" | ""
  property string opInput: ""
  property string opOutput: ""
  property double opStartMs: 0
  property double opDone: 0
  property double opTotal: 0
  property var opResult: null           // last {"kind":"result"} object
  property string opError: ""
  readonly property bool opBusy: opProc.running
  readonly property real opPct: Model.pctOf(opDone, opTotal)
  readonly property double opElapsedMs: opStartMs > 0
    ? Math.max(0, nowMs - opStartMs) : 0
  // The engine throttles progress records to roughly one per 4 MiB, so a
  // small file streams none at all and no total is ever announced. That is a
  // known-unknown, not a stalled operation, and the UI is told which it is.
  readonly property bool opIndeterminate: opBusy && opTotal <= 0

  // Containers whose header MAC a decrypt in this session actually verified,
  // keyed by path, valued by when. Never persisted and never inferred: it is
  // the record of a check that happened, not a belief about a file.
  property var macAttested: ({})

  function macAttestedAt(path) {
    var p = String(path || "")
    return p !== "" && macAttested[p] ? String(macAttested[p]) : ""
  }

  // Signatures whose validity a `verify` in this session actually established,
  // keyed by path. Same discipline as macAttested: the record of a check that
  // ran, never persisted and never inferred. `inspect` reads the header only,
  // so it can say a container is signed and can never say the signature is
  // good; only this map may promote the chip.
  property var sigAttested: ({})
  readonly property bool verifyBusy: verifyProc.running

  function sigAttestedFor(path) {
    var p = String(path || "")
    return p !== "" && sigAttested[p] ? sigAttested[p] : null
  }

  // Check a signature without a key. The signature covers a digest of the
  // header and the payload ciphertext, and the verifying key travels in the
  // header, so this decrypts nothing and needs no identity -- it works on a
  // container addressed to somebody else.
  function verifySignature(path) {
    var p = Model.normalizePath(path, home)
    if (p === "") return
    if (engineMissing || enginePath === "") {
      actionError = "The anubis engine is not installed."
      return
    }
    if (verifyProc.running) return
    actionError = ""
    actionStatus = "Verifying signature..."
    verifyProc.target = p
    verifyProc.outText = ""
    verifyProc.errText = ""
    verifyProc.command = [enginePath, "verify", "--json", p]
    verifyProc.running = true
  }

  function applyVerify(raw, stderrText, exitCode) {
    var target = String(verifyProc.target || "")
    var record = null
    var lines = String(raw || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      var o = Model.parseLine(lines[i])
      if (o && o.kind === "verify") record = o
    }
    actionStatus = ""

    if (target === "") return

    if (record === null) {
      // No verdict is not a verdict. Say the check could not be made rather
      // than leaving a chip that implies one was.
      actionError = stderrText !== "" ? stderrText
        : "anubis exited " + exitCode + " without a verify record"
      return
    }

    // Order matters. A verdict about the signature -- either way -- is what
    // this map exists to hold, so it is read first. Only when the engine
    // reached no verdict at all does the unsigned case apply; an unsigned
    // container is not a failed signature and must not be recorded as one.
    if (record.signature_ok !== true && record.signature_ok !== false) {
      actionError = record.signed === true
        ? String(record.error || "the signature could not be checked")
        : "This container carries no signature."
      return
    }

    var next = {}
    for (var k in sigAttested) next[k] = sigAttested[k]
    next[target] = {
      ok: record.signature_ok === true,
      at: new Date().toISOString(),
      fingerprint: String(record.signer_fingerprint || ""),
      error: String(record.error || "")
    }
    sigAttested = next
    actionError = record.signature_ok === true ? ""
      : String(record.error || "signature verification failed")
  }

  // A request held back because the output already exists and the operator
  // asked to be warned. Null when nothing is pending.
  property var pendingOverwrite: null

  // ---- inspector -----------------------------------------------------------
  property string inspectPath: ""
  property var inspectResult: null
  property string inspectError: ""
  readonly property bool inspectBusy: inspectProc.running

  // ---- key and address-book actions ---------------------------------------
  property string actionStatus: ""
  property string actionError: ""
  readonly property bool actionBusy: keygenProc.running || bookProc.running

  readonly property bool anyBusy: statusBusy || opBusy || inspectBusy || actionBusy
    || verifyBusy

  signal operationFinished(string kind, bool ok)
  signal identityCreated(string name)

  // ==========================================================================
  // lifecycle
  // ==========================================================================

  Component.onCompleted: {
    nowMs = Date.now()
    probeEngine()
  }

  // Locate the executable. `cargo install` lands in ~/.cargo/bin, which is on
  // an interactive PATH but not necessarily on the PATH a desktop launcher
  // hands a graphical application, so the known locations are checked
  // explicitly before falling back to a PATH lookup.
  //
  // The answer is four stat() calls, so it is taken synchronously. Nothing is
  // executed to find out where the engine is -- a probe that ran the binary
  // would be running an unverified executable to decide whether to run it.
  function probeEngine() {
    enginePath = App.locateEngine()
    engineProbed = true
    if (enginePath !== "") refresh()
    else {
      status = null
      statusError = ""
    }
  }

  function refresh() {
    if (enginePath === "") { probeEngine(); return }
    if (statusProc.running) return
    statusProc.outText = ""
    statusProc.errText = ""
    statusProc.command = [enginePath, "status", "--json"]
    statusProc.running = true
  }

  function applyStatus(raw, stderrText, exitCode) {
    var parsed = null
    var trimmed = String(raw || "").replace(/^\s+|\s+$/g, "")
    if (trimmed !== "") {
      // `status` emits exactly one object, but a stray leading line from a
      // future version must not take the whole read down.
      var lines = trimmed.split("\n")
      for (var i = lines.length - 1; i >= 0 && parsed === null; i--) {
        var o = Model.parseLine(lines[i])
        if (o && o.kind === "status") parsed = o
      }
    }
    if (parsed === null) {
      status = null
      statusError = stderrText !== "" ? stderrText
        : (exitCode === 127 ? "anubis could not execute"
                            : "status produced no parsable payload")
    } else {
      status = parsed
      statusError = ""
    }
    statusAtMs = Date.now()
    nowMs = statusAtMs
  }

  // ==========================================================================
  // encrypt / decrypt
  // ==========================================================================

  // Build the request without running it, so the overwrite gate and the UI
  // both see exactly what would be executed.
  function buildRequest(kind, inputPath, recipientKeys, sign, identityName,
                        outputPath) {
    var input = Model.normalizePath(inputPath, home)
    var out = String(outputPath || "")
    if (out === "") out = Model.outputFor(kind, input)
    return {
      kind: kind,
      input: input,
      output: out,
      recipients: recipientKeys || [],
      sign: sign === true,
      identity: String(identityName || "")
    }
  }

  function requestRefusal(req) {
    if (engineMissing) return "The anubis engine is not installed."
    if (enginePath === "") return "Locating the anubis engine."
    if (opProc.running) return "An operation is already running."
    if (req.input === "") return "Name a file first."
    if (req.kind === "encrypt" && req.recipients.length === 0)
      return "Select at least one recipient."
    if (req.kind === "encrypt" && req.sign && !canSign)
      return "No identity with signing material; generate one first."
    if (req.output === req.input)
      return "Refusing to write the output over its own input."
    return ""
  }

  // Entry point for both operations. When `confirmOverwrite` is on, the
  // existence of the output is checked first and the request is parked until
  // the operator confirms; the confirmation is what adds `--force`, so an
  // overwrite is never something the panel decided on its own.
  function submit(req) {
    opError = ""
    actionError = ""
    var refusal = requestRefusal(req)
    if (refusal !== "") { opError = refusal; return }
    pendingOverwrite = null
    if (!opts.confirmOverwrite) { launch(req, false); return }
    // Existence only. Nothing is read, nothing is written, and the answer
    // never becomes an overwrite on its own -- confirming is what adds
    // `--force`, and confirming is the operator's click.
    if (App.fileExists(req.output)) pendingOverwrite = req
    else launch(req, false)
  }

  function confirmPending() {
    if (!pendingOverwrite) return
    var req = pendingOverwrite
    pendingOverwrite = null
    launch(req, true)
  }

  function cancelPending() {
    pendingOverwrite = null
    opError = ""
  }

  function launch(req, force) {
    var cmd = [enginePath, req.kind, "--json"]
    if (req.kind === "encrypt") {
      for (var i = 0; i < req.recipients.length; i++)
        cmd.push("-r", String(req.recipients[i]))
      if (req.sign) cmd.push("--sign")
    }
    if (req.identity !== "") cmd.push("--identity", req.identity)
    cmd.push("-o", req.output)
    if (force) cmd.push("--force")
    cmd.push(req.input)

    opKind = req.kind
    opInput = req.input
    opOutput = req.output
    opDone = 0
    opTotal = 0
    opResult = null
    opError = ""
    opStartMs = Date.now()
    nowMs = opStartMs
    opProc.errText = ""
    opProc.command = cmd
    opProc.running = true
  }

  function abortOperation() {
    if (!opProc.running) return
    opProc.signal(15)
    opError = "Operation terminated by the operator."
  }

  // One streamed line. Progress records only move the counters; the result
  // record is stored whole and never summarised into a boolean here.
  function consumeLine(line) {
    var o = Model.parseLine(line)
    if (!o) return
    if (o.kind === "progress") {
      opDone = Number(o.done || 0)
      opTotal = Number(o.total || 0)
      nowMs = Date.now()
    } else if (o.kind === "result") {
      opResult = o
      if (o.ok === false) opError = String(o.error || "operation failed")
      else {
        opDone = Number(o.bytes || opDone)
        if (opTotal <= 0) opTotal = opDone
      }
      // A successful decrypt is only reachable after the header MAC has
      // already been checked, so `header_mac_ok: true` here is a fact about
      // this container, not an inference. `inspect` can never state it --
      // it holds no key -- so the one place the answer exists is recorded
      // against the file it was established for, and nowhere else.
      if (o.ok === true && o.header_mac_ok === true) {
        var target = String(o.path || opInput)
        if (target !== "") {
          var next = {}
          for (var k in macAttested) next[k] = macAttested[k]
          next[target] = new Date().toISOString()
          macAttested = next
        }
      }
      // A signed container cannot decrypt successfully unless its signature
      // verified first, so a successful decrypt attests the signature on the
      // same footing as the header MAC. Recording it here means the operator
      // is not asked to re-verify by hand something the engine just checked.
      if (o.ok === true && o.signature_ok === true) {
        var sigTarget = String(o.path || opInput)
        if (sigTarget !== "") {
          var sigNext = {}
          for (var sk in sigAttested) sigNext[sk] = sigAttested[sk]
          sigNext[sigTarget] = {
            ok: true,
            at: new Date().toISOString(),
            fingerprint: String(o.signer_fingerprint || ""),
            error: ""
          }
          sigAttested = sigNext
        }
      }
    }
  }

  function settleOperation(exitCode) {
    var kind = opKind
    var ok = opResult ? opResult.ok === true : exitCode === 0
    if (!opResult && exitCode !== 0 && opError === "")
      opError = opProc.errText !== "" ? opProc.errText
        : "anubis exited " + exitCode + " without a result record"
    opKind = ""
    opStartMs = 0
    refresh()
    if (ok && kind === "encrypt" && opOutput !== "") runInspect(opOutput)
    if (ok && kind === "decrypt" && Model.isVaultFile(opInput))
      runInspect(opInput)
    operationFinished(kind, ok)
  }

  // ==========================================================================
  // inspect
  // ==========================================================================

  function runInspect(path) {
    var p = Model.normalizePath(path, home)
    if (p === "") return
    inspectPath = p
    if (engineMissing || enginePath === "") {
      inspectResult = null
      inspectError = "The anubis engine is not installed."
      return
    }
    if (inspectProc.running) inspectProc.running = false
    inspectResult = null
    inspectError = ""
    inspectProc.outText = ""
    inspectProc.errText = ""
    inspectProc.command = [enginePath, "inspect", "--json", p]
    inspectProc.running = true
  }

  function clearInspect() {
    inspectPath = ""
    inspectResult = null
    inspectError = ""
  }

  function applyInspect(raw, stderrText, exitCode) {
    var parsed = null
    var lines = String(raw || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      var o = Model.parseLine(lines[i])
      if (o && o.kind === "inspect") parsed = o
      else if (o && o.kind === "result" && o.ok === false)
        inspectError = String(o.error || "inspect failed")
    }
    if (parsed) {
      inspectResult = parsed
      if (inspectError === "" && exitCode !== 0)
        inspectError = "anubis exited " + exitCode
    } else {
      inspectResult = null
      if (inspectError === "")
        inspectError = stderrText !== "" ? stderrText
          : "not an ANUBIS container, or the header could not be read"
    }
  }

  // ==========================================================================
  // identities and the address book
  // ==========================================================================

  // Every ANUBIS identity is capability-complete -- X25519, ML-KEM-1024 and
  // ML-DSA-87 material in one file -- so keygen takes a name and nothing
  // else. Whether a given file is signed is decided per operation, at
  // encrypt time.
  function generateIdentity(name) {
    actionError = ""
    if (engineMissing || enginePath === "") {
      actionError = "The anubis engine is not installed."
      return
    }
    if (keygenProc.running) return
    if (!Model.validIdentityName(name)) {
      actionError = "Identity name refused: letters, digits, dot, dash, "
        + "underscore; 64 max."
      return
    }
    if (Model.identityByName(status, name)) {
      actionError = "An identity named \"" + name + "\" already exists."
      return
    }
    keygenProc.wanted = String(name)
    keygenProc.outText = ""
    keygenProc.errText = ""
    keygenProc.command = [enginePath, "keygen", "--json", "--name", String(name)]
    actionStatus = "Generating " + name + "..."
    keygenProc.running = true
  }

  function addRecipient(label, key) {
    actionError = ""
    if (engineMissing || enginePath === "") {
      actionError = "The anubis engine is not installed."
      return
    }
    if (bookProc.running) return
    var refusal = Model.recipientRefusal(label, key, recipients)
    if (refusal !== "") { actionError = refusal; return }
    bookProc.outText = ""
    bookProc.errText = ""
    bookProc.command = [enginePath, "recipient", "add", "--json",
                        "--label", String(label), String(key)]
    actionStatus = "Adding " + label + "..."
    bookProc.running = true
  }

  function removeRecipient(label) {
    actionError = ""
    if (engineMissing || enginePath === "") {
      actionError = "The anubis engine is not installed."
      return
    }
    if (bookProc.running) return
    if (!Model.validLabel(label)) { actionError = "Unknown label."; return }
    bookProc.outText = ""
    bookProc.errText = ""
    bookProc.command = [enginePath, "recipient", "remove", "--json",
                        "--label", String(label)]
    actionStatus = "Removing " + label + "..."
    bookProc.running = true
  }

  function applyBookResult(raw, stderrText, exitCode) {
    var ok = false
    var err = ""
    var lines = String(raw || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      var o = Model.parseLine(lines[i])
      if (!o || o.kind !== "result") continue
      ok = o.ok === true
      if (!ok) err = String(o.error || "the engine refused the change")
    }
    actionStatus = ""
    if (!ok && err === "")
      err = stderrText !== "" ? stderrText
        : "anubis exited " + exitCode + " without a result record"
    actionError = ok ? "" : err
    refresh()
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
    App.copyToClipboard(value)
    actionStatus = "Copied " + description
    actionError = ""
    statusClear.restart()
  }

  // ==========================================================================
  // processes
  // ==========================================================================


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
      root.applyStatus(outText, errText.replace(/^\s+|\s+$/g, ""), exitCode)
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


  Process {
    id: opProc
    property string errText: ""
    command: ["/usr/bin/true"]
    stdout: SplitParser {
      splitMarker: "\n"
      onRead: function (data) { root.consumeLine(data) }
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: opProc.errText = String(text || "").replace(/\s+$/, "")
    }
    onExited: function (code) { root.settleOperation(code) }
  }

  Process {
    id: inspectProc
    property string outText: ""
    property string errText: ""
    command: ["/usr/bin/true"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: inspectProc.outText = String(text || "")
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: inspectProc.errText = String(text || "")
    }
    onExited: function (code) {
      root.applyInspect(inspectProc.outText,
                        inspectProc.errText.replace(/^\s+|\s+$/g, ""), code)
    }
  }

  Process {
    id: verifyProc
    property string target: ""
    property string outText: ""
    property string errText: ""
    command: ["/usr/bin/true"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: verifyProc.outText = String(text || "")
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: verifyProc.errText = String(text || "")
    }
    onExited: function (code) {
      root.applyVerify(verifyProc.outText,
                       verifyProc.errText.replace(/^\s+|\s+$/g, ""), code)
    }
  }

  Process {
    id: keygenProc
    property string wanted: ""
    property string outText: ""
    property string errText: ""
    command: ["/usr/bin/true"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: keygenProc.outText = String(text || "")
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: keygenProc.errText = String(text || "")
    }
    onExited: function (code) {
      var made = null
      var lines = keygenProc.outText.split("\n")
      for (var i = 0; i < lines.length; i++) {
        var o = Model.parseLine(lines[i])
        if (o && o.kind === "keygen") made = o
        else if (o && o.kind === "result" && o.ok === false)
          root.actionError = String(o.error || "keygen failed")
      }
      root.actionStatus = ""
      if (made) {
        root.actionError = ""
        root.identityCreated(String(made.name || keygenProc.wanted))
      } else if (root.actionError === "") {
        var err = keygenProc.errText.replace(/^\s+|\s+$/g, "")
        root.actionError = err !== "" ? err
          : "anubis exited " + code + " without a keygen record"
      }
      root.refresh()
    }
  }

  Process {
    id: bookProc
    property string outText: ""
    property string errText: ""
    command: ["/usr/bin/true"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: bookProc.outText = String(text || "")
    }
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: bookProc.errText = String(text || "")
    }
    onExited: function (code) {
      root.applyBookResult(bookProc.outText,
                           bookProc.errText.replace(/^\s+|\s+$/g, ""), code)
    }
  }

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

  // Drives elapsed time and throughput while an operation streams. Idle
  // outside an operation so nothing wakes the compositor for no reason.
  Timer {
    interval: 250
    running: root.opBusy
    repeat: true
    onTriggered: root.nowMs = Date.now()
  }

  Timer {
    interval: 15000
    running: true
    repeat: true
    onTriggered: root.nowMs = Date.now()
  }

  // The engine rewrites status.json after every operation, including ones run
  // from a terminal. Watching it keeps the panel current without shortening
  // the poll interval.
  FileView {
    id: stateWatch
    path: root.stateDir + "/status.json"
    watchChanges: true
    printErrors: false
    onFileChanged: stateSettle.restart()
  }

  Timer {
    id: stateSettle
    interval: 250
    repeat: false
    onTriggered: root.refresh()
  }
}

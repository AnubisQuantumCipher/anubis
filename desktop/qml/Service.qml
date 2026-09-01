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

  // A status record is small, fixed-shape control data. Bound the native
  // child before its bytes reach the long-lived QML collectors; encrypt and
  // decrypt streams do not inherit either limit.
  readonly property int maxStatusOutputBytes: 4194304
  readonly property int statusTimeoutMs: 15000

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
  property int opResultCount: 0
  property bool opProtocolValid: true
  property string opError: ""
  readonly property bool opBusy: opProc.running
  readonly property real opPct: Model.pctOf(opDone, opTotal)
  readonly property double opElapsedMs: opStartMs > 0
    ? Math.max(0, nowMs - opStartMs) : 0
  // The engine throttles progress records to roughly one per 4 MiB, so a
  // small file streams none at all and no total is ever announced. That is a
  // known-unknown, not a stalled operation, and the UI is told which it is.
  readonly property bool opIndeterminate: opBusy && opTotal <= 0

  // Containers whose header MAC a decrypt in this session actually verified.
  // Keys are SHA-512 content IDs over the complete decoded container, never
  // mutable paths. Values retain the path only so a later inspection of that
  // path can evict an obsolete entry after the bytes change.
  property var macAttested: ({})

  function macAttestationFor(inspect) {
    var id = Model.contentId(inspect)
    if (id === "" || !macAttested[id]) return null
    var attested = macAttested[id]
    return attested.content_id === id ? attested : null
  }

  // Signatures whose validity a `verify` in this session actually established,
  // keyed by the same immutable content ID. The cached signer must also equal
  // the current header's signer or the entry is unusable. `inspect` reads the
  // header only, so only this map may promote the chip.
  property var sigAttested: ({})
  readonly property bool verifyBusy: verifyProc.running
  property int verifyGeneration: 0

  function sigAttestedFor(inspect) {
    var id = Model.contentId(inspect)
    if (id === "" || !sigAttested[id]) return null
    var attested = sigAttested[id]
    if (attested.content_id !== id) return null
    var current = Model.signerFingerprint(inspect)
    var checked = Model.formatFingerprint(attested.fingerprint)
    return current !== "" && Model.validFingerprint(current)
      && checked === current ? attested : null
  }

  function reconcileAttestations(path, inspect) {
    var target = String(path || "")
    var currentId = Model.contentId(inspect)
    var currentSigner = Model.signerFingerprint(inspect)
    var nextMac = {}
    for (var mk in macAttested) {
      var mac = macAttested[mk]
      if (String(mac.path || "") !== target || mk === currentId)
        nextMac[mk] = mac
    }
    macAttested = nextMac

    var nextSig = {}
    for (var sk in sigAttested) {
      var sig = sigAttested[sk]
      var samePath = String(sig.path || "") === target
      var sameContent = sk === currentId
      var sameSigner = Model.formatFingerprint(sig.fingerprint) === currentSigner
      if (!samePath || (sameContent && sameSigner)) nextSig[sk] = sig
    }
    sigAttested = nextSig
  }

  function decryptPolicyForPath(path, requireSignature, signerPin) {
    return Model.decryptPolicy(
      path, inspectPath, inspectResult, sigAttestedFor(inspectResult),
      requireSignature, signerPin)
  }

  function retainDecryptAttestations(result) {
    var contentId = Model.contentId(result)
    var target = Model.exactPath(result && result.path !== undefined
                                 ? result.path : opInput)
    if (contentId === "") {
      opError = "Decryption completed, but the engine returned no valid "
        + "content_id; no authentication attestation was retained."
      return
    }
    var now = new Date().toISOString()
    if (result.header_mac_ok === true) {
      var nextMac = {}
      for (var mk in macAttested) nextMac[mk] = macAttested[mk]
      nextMac[contentId] = {
        at: now,
        content_id: contentId,
        path: target
      }
      macAttested = nextMac
    }
    if (result.signature_ok === true) {
      var signer = Model.formatFingerprint(result.signer_fingerprint)
      if (!Model.validFingerprint(signer)) {
        opError = "Decryption completed, but the engine returned no valid "
          + "signer fingerprint; no signature attestation was retained."
        return
      }
      var nextSig = {}
      for (var sk in sigAttested) nextSig[sk] = sigAttested[sk]
      nextSig[contentId] = {
        ok: true,
        at: now,
        content_id: contentId,
        path: target,
        fingerprint: signer,
        error: ""
      }
      sigAttested = nextSig
    }
  }

  // Check a signature without a key. The signature covers a digest of the
  // header and the payload ciphertext, and the verifying key travels in the
  // header, so this decrypts nothing and needs no identity -- it works on a
  // container addressed to somebody else.
  function verifySignature(path) {
    var p = Model.exactPath(path)
    if (p === "") return
    if (engineMissing || enginePath === "") {
      actionError = "The anubis engine is not installed."
      return
    }
    if (verifyProc.running) return
    if (p !== inspectPath || !inspectResult) {
      actionError = "Inspect this container before verifying it."
      return
    }
    var contentId = Model.contentId(inspectResult)
    var signer = Model.signerFingerprint(inspectResult)
    if (contentId === "") {
      actionError = "This engine did not provide a valid content_id; "
        + "verification cannot be bound to immutable bytes."
      return
    }
    if (!Model.validFingerprint(signer)) {
      actionError = "The inspected container did not provide a valid signer "
        + "fingerprint."
      return
    }
    actionError = ""
    actionStatus = "Verifying signature..."
    verifyGeneration += 1
    verifyProc.target = p
    verifyProc.generation = verifyGeneration
    verifyProc.expectedContentId = contentId
    verifyProc.expectedSigner = signer
    verifyProc.outText = ""
    verifyProc.errText = ""
    verifyProc.command = [enginePath, "verify", "--json", p]
    verifyProc.running = true
  }

  function applyVerify(raw, stderrText, exitCode, target, generation,
                       expectedContentId, expectedSigner) {
    // A cancelled run is allowed to exit later; it is never allowed to write
    // into the state for the inspection that replaced it.
    if (!Model.runIsCurrent(generation, target, verifyGeneration, inspectPath)
        || expectedContentId !== Model.contentId(inspectResult)) return

    var record = null
    var recordCount = 0
    var protocolValid = true
    var lines = String(raw || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      if (String(lines[i]).replace(/^\s+|\s+$/g, "") === "") continue
      var o = Model.parseLine(lines[i])
      if (o && o.kind === "verify") {
        record = o
        recordCount += 1
      } else protocolValid = false
    }
    actionStatus = ""

    var decision = Model.verifyRecordDecision(
      record, exitCode, protocolValid, recordCount,
      expectedContentId, expectedSigner)
    if (decision === "record-invalid") {
      // No verdict is not a verdict. Say the check could not be made rather
      // than leaving a chip that implies one was.
      actionError = stderrText !== "" ? stderrText
        : "anubis exited " + exitCode + " without a verify record"
      return
    }

    var actualContentId = Model.contentId(record)
    var actualSigner = Model.formatFingerprint(record.signer_fingerprint)
    if (decision === "content-mismatch") {
      actionError = "The container changed while its signature was being "
        + "verified; no verdict was retained."
      return
    }
    if (decision === "signer-mismatch") {
      actionError = "The signer changed while the signature was being "
        + "verified; no verdict was retained."
      return
    }

    // Order matters. A verdict about the signature -- either way -- is what
    // this map exists to hold, so it is read first. Only when the engine
    // reached no verdict at all does the unsigned case apply; an unsigned
    // container is not a failed signature and must not be recorded as one.
    if (decision === "verdict-missing") {
      actionError = record.signed === true
        ? String(record.error || "the signature could not be checked")
        : "This container carries no signature."
      return
    }

    if (decision === "exit-failed") {
      actionError = stderrText !== "" ? stderrText
        : "anubis reported a valid signature but exited " + exitCode
      return
    }

    var next = {}
    for (var k in sigAttested) next[k] = sigAttested[k]
    next[actualContentId] = {
      ok: record.signature_ok === true,
      at: new Date().toISOString(),
      content_id: actualContentId,
      path: target,
      fingerprint: actualSigner,
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
  property int inspectGeneration: 0
  property var queuedInspect: null
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

  function applyStatus(raw, stderrText, exitCode, timedOut,
                       outputLimitExceeded) {
    var rawStderr = String(stderrText || "")
    var displayStderr = rawStderr.replace(/^\s+|\s+$/g, "")
    var parsed = null
    var parsedCount = 0
    var protocolValid = true
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
    if (timedOut === true) {
      status = null
      statusError = "anubis status timed out"
    } else if (outputLimitExceeded === true) {
      status = null
      statusError = "status output exceeded the safe readout limit"
    } else if (!Model.statusResponseAccepted(parsed, exitCode, rawStderr,
                                              protocolValid, parsedCount)) {
      status = null
      statusError = rawStderr !== ""
        ? (displayStderr !== "" ? displayStderr
                                : "anubis status wrote to stderr")
        : (exitCode === 127 ? "anubis could not execute"
            : (exitCode !== 0 ? "anubis status exited " + exitCode
                              : "status produced no complete payload"))
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
                        outputPath, requireSignature, signerPin) {
    var input = Model.exactPath(inputPath)
    var out = Model.exactPath(outputPath)
    if (out === "") out = Model.outputFor(kind, input)
    return {
      kind: kind,
      input: input,
      output: out,
      recipients: recipientKeys || [],
      sign: sign === true,
      identity: String(identityName || ""),
      require_signature: requireSignature === true,
      signer: String(signerPin || "")
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
    if (req.kind === "decrypt") {
      var policy = decryptPolicyForPath(
        req.input, req.require_signature, req.signer)
      if (!policy.ok) return policy.error
      var expectedId = String(req.expected_content_id || "")
      if (expectedId !== ""
          && !Model.decryptPolicyStillCurrent(policy, expectedId))
        return "The container changed after decrypt was requested; review "
          + "the new inspection and try again."
    }
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
    if (req.kind === "decrypt") {
      var policy = decryptPolicyForPath(
        req.input, req.require_signature, req.signer)
      // Park the effective policy, not only the visible controls. In
      // particular, a signer inherited from a successful verification must
      // neither disappear nor be replaced while overwrite confirmation is up.
      req.expected_content_id = policy.content_id
      req.bound_require_signature = policy.require_signature
      req.bound_signer = policy.signer
    }
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
    // Confirmation can leave a request parked while the selected file changes.
    // Re-evaluate every boundary immediately before spawning the engine.
    var refusal = requestRefusal(req)
    if (refusal !== "") { opError = refusal; return }
    if (req.kind === "decrypt"
        && String(req.expected_content_id || "") === "") {
      var livePolicy = decryptPolicyForPath(
        req.input, req.require_signature, req.signer)
      req.expected_content_id = livePolicy.content_id
      req.bound_require_signature = livePolicy.require_signature
      req.bound_signer = livePolicy.signer
    }

    var cmd = [enginePath, req.kind, "--json"]
    if (req.kind === "encrypt") {
      for (var i = 0; i < req.recipients.length; i++)
        cmd.push("-r", String(req.recipients[i]))
      if (req.sign) cmd.push("--sign")
    }
    if (req.kind === "decrypt") {
      // Every decrypt is pinned to the exact bytes inspected. Signature
      // requirements are separate: the operator may demand any signature or
      // a particular signer, and a prior successful verify retains the old
      // automatic signer pin.
      var policy = {
        ok: true,
        content_id: String(req.expected_content_id || ""),
        require_signature: req.bound_require_signature === true,
        signer: String(req.bound_signer || "")
      }
      var policyArgs = Model.decryptPolicyArguments(policy)
      for (var p = 0; p < policyArgs.length; p++) cmd.push(policyArgs[p])
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
    opResultCount = 0
    opProtocolValid = true
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
    if (!o) {
      opProtocolValid = false
      opError = "anubis emitted a malformed JSON record"
      return
    }
    if (o.kind === "progress") {
      opDone = Number(o.done || 0)
      opTotal = Number(o.total || 0)
      nowMs = Date.now()
    } else if (o.kind === "result") {
      opResultCount += 1
      opResult = o
      if (opResultCount !== 1) {
        opError = "anubis emitted more than one result record"
        return
      }
      if (o.ok === false) opError = String(o.error || "operation failed")
      else {
        opDone = Number(o.bytes || opDone)
        if (opTotal <= 0) opTotal = opDone
      }
    } else {
      opProtocolValid = false
      opError = "anubis emitted an unexpected " + String(o.kind)
        + " record"
    }
  }

  function settleOperation(exitCode) {
    var kind = opKind
    var completeResult = opProtocolValid && opResult !== null
      && opResultCount === 1
      && (opResult.ok === true || opResult.ok === false)
    if (completeResult && opResult.ok === true && kind === "decrypt") {
      completeResult = Model.decryptResultAccepted(
        opResult, exitCode, opProtocolValid, opResultCount, opInput, opOutput)
    } else if (completeResult && opResult.ok === true) {
      completeResult = String(opResult.op || "") === kind
        && String(opResult.path || "") === opInput
        && String(opResult.out || "") === opOutput
        && typeof opResult.bytes === "number" && isFinite(opResult.bytes)
        && opResult.bytes >= 0
    }
    var ok = exitCode === 0 && completeResult && opResult.ok === true
    if (!completeResult && opError === "")
      opError = "anubis exited " + exitCode
        + " without exactly one complete result record"
    else if (exitCode !== 0 && opError === "")
      opError = opProc.errText !== "" ? opProc.errText
        : "anubis exited " + exitCode

    // Attest only after both the structured result and process exit agree on
    // success. A result line followed by a crash is not a completed check.
    if (ok && kind === "decrypt") retainDecryptAttestations(opResult)
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
    var p = Model.exactPath(path)
    if (p === "") return
    inspectGeneration += 1
    inspectPath = p
    inspectResult = null
    inspectError = ""
    queuedInspect = { path: p, generation: inspectGeneration }

    // A verifier launched for a previous inspection is stale by definition.
    verifyGeneration += 1
    if (verifyProc.running) verifyProc.running = false
    actionStatus = ""

    if (engineMissing || enginePath === "") {
      queuedInspect = null
      inspectError = "The anubis engine is not installed."
      return
    }

    // Process termination is asynchronous. Park the newest request and start
    // it only after the old child's exit is observed; changing the visible
    // path while the old output is still in flight can otherwise bind that
    // output to the new file.
    if (inspectProc.running) {
      inspectProc.running = false
      return
    }
    launchQueuedInspect()
  }

  function launchQueuedInspect() {
    if (inspectProc.running || !queuedInspect) return
    var request = queuedInspect
    queuedInspect = null
    inspectProc.target = String(request.path || "")
    inspectProc.generation = Number(request.generation || 0)
    inspectProc.outText = ""
    inspectProc.errText = ""
    inspectProc.command = [enginePath, "inspect", "--json", inspectProc.target]
    inspectProc.running = true
  }

  function clearInspect() {
    inspectGeneration += 1
    queuedInspect = null
    if (inspectProc.running) inspectProc.running = false
    verifyGeneration += 1
    if (verifyProc.running) verifyProc.running = false
    inspectPath = ""
    inspectResult = null
    inspectError = ""
    actionStatus = ""
  }

  function invalidateInspectedFile() {
    var target = inspectPath
    if (target === "") return
    inspectGeneration += 1
    queuedInspect = null
    if (inspectProc.running) inspectProc.running = false
    verifyGeneration += 1
    if (verifyProc.running) verifyProc.running = false
    inspectResult = null
    reconcileAttestations(target, null)
    inspectError = "Container changed; inspecting the current bytes again."
    actionStatus = ""
    inspectChangeSettle.restart()
  }

  function applyInspect(raw, stderrText, exitCode, target, generation) {
    if (!Model.runIsCurrent(generation, target,
                            inspectGeneration, inspectPath)) return

    var parsed = null
    var parsedCount = 0
    var reportedError = ""
    var protocolValid = true
    var lines = String(raw || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      if (String(lines[i]).replace(/^\s+|\s+$/g, "") === "") continue
      var o = Model.parseLine(lines[i])
      if (o && o.kind === "inspect") {
        parsed = o
        parsedCount += 1
      }
      else if (o && o.kind === "result" && o.ok === false)
        reportedError = String(o.error || "inspect failed")
      else protocolValid = false
    }

    if (Model.inspectRecordAccepted(parsed, exitCode, protocolValid,
                                    parsedCount, reportedError, target)) {
      inspectResult = parsed
      reconcileAttestations(target, parsed)
      if (Model.contentId(parsed) === "")
        inspectError = "content identity unavailable: this engine did not "
          + "return a valid content_id, so cached verification and MAC "
          + "attestations are disabled until it is upgraded"
      else inspectError = ""
    } else {
      inspectResult = null
      reconcileAttestations(target, null)
      inspectError = reportedError !== "" ? reportedError
        : (stderrText !== "" ? stderrText
          : (exitCode !== 0 ? "anubis inspect exited " + exitCode
          : "not an ANUBIS container, or the header could not be read"
          ))
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
    var resultCount = 0
    var protocolValid = true
    var lines = String(raw || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      if (String(lines[i]).replace(/^\s+|\s+$/g, "") === "") continue
      var o = Model.parseLine(lines[i])
      if (!o || o.kind !== "result"
          || (o.ok !== true && o.ok !== false)) {
        protocolValid = false
        continue
      }
      resultCount += 1
      ok = o.ok === true
      if (!ok) err = String(o.error || "the engine refused the change")
    }
    ok = exitCode === 0 && protocolValid && resultCount === 1 && ok
    actionStatus = ""
    if (!ok && err === "")
      err = stderrText !== "" ? stderrText
        : "anubis exited " + exitCode
          + " without exactly one complete result record"
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
    timeoutMs: root.statusTimeoutMs
    maximumOutputBytes: root.maxStatusOutputBytes
    property string outText: ""
    property string errText: ""
    property int exitCode: 0
    property bool exited: false
    property bool outDone: false
    property bool errDone: false

    function settle() {
      if (!exited || !outDone || !errDone) return
      root.applyStatus(outText, errText, exitCode,
                       statusProc.timedOut, statusProc.outputLimitExceeded)
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
    property string target: ""
    property int generation: 0
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
                        inspectProc.errText.replace(/^\s+|\s+$/g, ""), code,
                        inspectProc.target, inspectProc.generation)
      root.launchQueuedInspect()
    }
  }

  Process {
    id: verifyProc
    property string target: ""
    property int generation: 0
    property string expectedContentId: ""
    property string expectedSigner: ""
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
                       verifyProc.errText.replace(/^\s+|\s+$/g, ""), code,
                       verifyProc.target, verifyProc.generation,
                       verifyProc.expectedContentId,
                       verifyProc.expectedSigner)
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
      var madeCount = 0
      var recordCount = 0
      var protocolValid = true
      var lines = keygenProc.outText.split("\n")
      for (var i = 0; i < lines.length; i++) {
        if (String(lines[i]).replace(/^\s+|\s+$/g, "") === "") continue
        recordCount += 1
        var o = Model.parseLine(lines[i])
        if (o && o.kind === "keygen") {
          made = o
          madeCount += 1
        }
        else if (o && o.kind === "result" && o.ok === false)
          root.actionError = String(o.error || "keygen failed")
        else protocolValid = false
      }
      root.actionStatus = ""
      if (code === 0 && protocolValid && recordCount === 1
          && made && madeCount === 1) {
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

  // The selected container is watched independently. A change invalidates
  // inspection and verification immediately; the follow-up read is debounced
  // for atomic replacement. Contents are not loaded by FileView because the
  // engine's inspect is the only reader needed here.
  FileView {
    id: inspectedFileWatch
    readContents: false
    path: root.inspectPath
    watchChanges: true
    printErrors: false
    onFileChanged: root.invalidateInspectedFile()
  }

  Timer {
    id: inspectChangeSettle
    interval: 250
    repeat: false
    onTriggered: {
      var target = root.inspectPath
      if (target !== "") root.runInspect(target)
    }
  }
}

// ANUBIS Model -- pure helpers for the vault surfaces.
//
// Nothing in this file performs cryptography, reads a key, or decides whether
// something verified. It formats, parses, and lays out what the `anubis`
// engine already said. Every value that carries an assurance meaning
// (header MAC state, signature state, ok/failed) is passed through verbatim
// and only mapped to a tone name; it is never inferred, defaulted to a pass,
// or repaired when the engine declined to state it.
//
// One design rule runs through the whole file: the FINGERPRINT is the human
// handle. An ANUBIS recipient is roughly 2573 bech32 characters -- past the
// length at which the bech32 checksum still guarantees error detection -- so
// the engine emits an 80-bit fingerprint alongside every identity and
// recipient. That is what a person compares out of band, and that is what
// these helpers put in front of the operator. The full key is available only
// through an explicit copy action.
.pragma library

// ------------------------------------------------------------------ glyphs
//
// Nerd Font (Material Design Icons range) codepoints, all verified present in
// the installed CaskaydiaMono Nerd Font. Written as codepoints so this file
// stays plain ASCII.

var GLYPH = {
  lock:        String.fromCodePoint(0xF033E),
  lockOpen:    String.fromCodePoint(0xF0341),
  lockOutline: String.fromCodePoint(0xF0335),
  key:         String.fromCodePoint(0xF0306),
  keyChain:    String.fromCodePoint(0xF0BE9),
  accountKey:  String.fromCodePoint(0xF05E1),
  shield:      String.fromCodePoint(0xF0499),
  shieldCheck: String.fromCodePoint(0xF0565),
  shieldAlert: String.fromCodePoint(0xF0ECC),
  shieldKey:   String.fromCodePoint(0xF0BC2),
  check:       String.fromCodePoint(0xF012C),
  alert:       String.fromCodePoint(0xF0026),
  close:       String.fromCodePoint(0xF0156),
  copy:        String.fromCodePoint(0xF018F),
  refresh:     String.fromCodePoint(0xF0450),
  plus:        String.fromCodePoint(0xF0415),
  trash:       String.fromCodePoint(0xF01B4),
  file:        String.fromCodePoint(0xF0224),
  fileLock:    String.fromCodePoint(0xF0770),
  fileKey:     String.fromCodePoint(0xF0AB5),
  eye:         String.fromCodePoint(0xF0214),
  signature:   String.fromCodePoint(0xF0D96),
  history:     String.fromCodePoint(0xF0954),
  timer:       String.fromCodePoint(0xF04DB),
  seal:        String.fromCodePoint(0xF0F0F),
  atom:        String.fromCodePoint(0xF0099),
  pulse:       String.fromCodePoint(0xF0794),
  info:        String.fromCodePoint(0xF02DC),
  fingerprint: String.fromCodePoint(0xF0234),
  upload:      String.fromCodePoint(0xF0511),
  download:    String.fromCodePoint(0xF01DA),
  folder:      String.fromCodePoint(0xF024B),
  cog:         String.fromCodePoint(0xF0493)
}

function opGlyph(op) {
  if (op === "encrypt") return GLYPH.lock
  if (op === "decrypt") return GLYPH.lockOpen
  if (op === "keygen")  return GLYPH.key
  if (op === "inspect") return GLYPH.eye
  if (op === "recipient.add") return GLYPH.plus
  if (op === "recipient.remove") return GLYPH.trash
  return GLYPH.file
}

// ------------------------------------------------------------- the suite
//
// The engine reports its own suite in `status.suite`. There is NO fallback.
//
// There used to be one -- a hardcoded X25519 + ML-KEM-1024 / ML-DSA-87 with
// FIPS 203 and 204 chips -- returned whenever `status` was null, which is the
// state after every failed poll and before the first one. So a surface whose
// stated rule is "a field the engine did not state is rendered as NOT STATED,
// never as a pass" was painting a full cryptographic claim over a binary that
// had said nothing at all, including one that had just failed to execute.
//
// Guessing a cipher suite is the one guess an encryption tool must never make.
// These helpers now return null or empty, and every caller renders the absence.

function suiteOf(status) {
  return (status && status.suite) ? status.suite : null
}

function suiteBadge(suite) {
  if (!suite) return ""
  var kem = String(suite.kem || "").split("+").join(" + ")
  var sig = String(suite.sig || "")
  return sig === "" ? kem : kem + " / " + sig
}

function suiteDetail(suite) {
  if (!suite) return ""
  var parts = []
  if (suite.aead) parts.push("AEAD " + suite.aead)
  if (suite.kdf) parts.push("KDF " + suite.kdf)
  if (suite.pure_rust !== undefined)
    parts.push(suite.pure_rust === true ? "pure Rust" : "native dependencies")
  return parts.join("  |  ")
}

// The wire format string, verbatim from whatever the engine reported. It
// versions on its own schedule and is deliberately not reconstructed here.
function wireFormat(suite) {
  var s = suite || {}
  return s.format ? String(s.format) : ""
}

function fipsChips(suite) {
  var list = suite && Array.isArray(suite.fips) ? suite.fips : []
  var out = []
  for (var i = 0; i < list.length; i++) out.push("FIPS " + String(list[i]))
  return out
}

function engineVersion(status) {
  return status && status.version ? String(status.version) : ""
}

// ------------------------------------------------------------- formatting

function formatBytes(n) {
  var v = Number(n)
  if (!isFinite(v) || v < 0) return "--"
  if (v < 1024) return v + " B"
  var units = ["KiB", "MiB", "GiB", "TiB"]
  var i = -1
  do { v = v / 1024; i++ } while (v >= 1024 && i < units.length - 1)
  return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + " " + units[i]
}

function formatMillis(ms) {
  var v = Number(ms)
  if (!isFinite(v) || v < 0) return "--"
  if (v < 1000) return Math.round(v) + " ms"
  if (v < 60000) return (v / 1000).toFixed(v < 10000 ? 2 : 1) + " s"
  var m = Math.floor(v / 60000)
  var s = Math.round((v - m * 60000) / 1000)
  return m + "m " + (s < 10 ? "0" : "") + s + "s"
}

function formatRate(bytes, ms) {
  var b = Number(bytes)
  var t = Number(ms)
  if (!isFinite(b) || !isFinite(t) || t <= 0 || b <= 0) return ""
  return formatBytes(b * 1000 / t) + "/s"
}

function formatPct(pct) {
  var v = Number(pct)
  if (!isFinite(v)) return "--"
  if (v < 0) v = 0
  if (v > 100) v = 100
  return (v >= 99.95 ? "100" : v.toFixed(1)) + "%"
}

function pctOf(done, total) {
  var d = Number(done)
  var t = Number(total)
  if (!isFinite(d) || !isFinite(t) || t <= 0) return 0
  var p = d * 100 / t
  return p < 0 ? 0 : (p > 100 ? 100 : p)
}

function two(n) { return (n < 10 ? "0" : "") + n }

function stampLocal(iso) {
  var t = Date.parse(iso)
  if (!(t > 0)) return ""
  var d = new Date(t)
  return d.getFullYear() + "-" + two(d.getMonth() + 1) + "-" + two(d.getDate())
    + " " + two(d.getHours()) + ":" + two(d.getMinutes())
}

function stampDay(iso) {
  var t = Date.parse(iso)
  if (!(t > 0)) return ""
  var d = new Date(t)
  return d.getFullYear() + "-" + two(d.getMonth() + 1) + "-" + two(d.getDate())
}

function stampClock(iso) {
  var t = Date.parse(iso)
  if (!(t > 0)) return ""
  var d = new Date(t)
  return two(d.getHours()) + ":" + two(d.getMinutes()) + ":" + two(d.getSeconds())
}

function timeAgo(iso, nowMs) {
  var t = Date.parse(iso)
  if (!(t > 0)) return ""
  var s = Math.max(0, Math.floor((nowMs - t) / 1000))
  if (s < 90) return s + "s ago"
  if (s < 5400) return Math.round(s / 60) + "m ago"
  if (s < 129600) return Math.round(s / 3600) + "h ago"
  return Math.round(s / 86400) + "d ago"
}

function elideMiddle(text, head, tail) {
  var s = String(text === undefined || text === null ? "" : text)
  if (s.length <= head + tail + 3) return s
  return s.substring(0, head) + "..." + s.substring(s.length - tail)
}

// -------------------------------------------------------------- fingerprint
//
// 80 bits of SHA-256 over the recipient payload, rendered uppercase hex in
// five groups of four. The engine emits it already grouped; this normalises
// whatever arrives so a differently-punctuated value still lines up in the
// column, and refuses to invent one when the field is absent.

function formatFingerprint(fp) {
  var raw = String(fp === undefined || fp === null ? "" : fp)
    .replace(/[^0-9A-Fa-f]/g, "").toUpperCase()
  if (raw.length === 0) return ""
  var groups = []
  for (var i = 0; i < raw.length; i += 4) groups.push(raw.substring(i, i + 4))
  return groups.join("-")
}

// The same value as formatFingerprint, with the four separators marked up in a
// caller-supplied colour so the panel can paint them dimmer than the digits.
// Grouping is the only thing that makes comparing two of these by eye
// survivable, so it is worth painting properly rather than leaving to a flat
// dashed string.
//
// This produces Text.StyledText, and doing that safely is the reason the value
// is rebuilt here from formatFingerprint rather than passed through: that
// function has already reduced its input to [0-9A-F] and dashes, so there is
// no `<` or `&` left that could turn a fingerprint into markup. `sepColor` is
// a theme colour stringified by the caller, never a literal.
//
// The panel renders the result in ONE wrapping Text rather than a row of
// per-group items. A positioner would either clip or overflow the rail at a
// large theme font size, and a clipped fingerprint is the same silent
// half-truth as an elided one; a wrapping Text is always complete.
//
// `breakAfter` is the group index after which to force a line break, or 0 for
// none. Twenty-four characters at the shipped theme's 18px body does not fit a
// 360px rail, so the panel measures the string and asks for a break at group
// three rather than letting the wrap fall wherever it lands. A fingerprint
// split 14/9 on group boundaries can still be read aloud and compared; one
// split mid-group as `...D1F2-0C1 / B-7CAB` cannot.
function fingerprintMarkup(fp, sepColor, breakAfter) {
  var groups = formatFingerprint(fp).split("-")
  if (groups.length === 0 || groups[0] === "") return ""
  var sep = '<font color="' + String(sepColor) + '">-</font>'
  var at = parseInt(String(breakAfter), 10)
  if (!isFinite(at) || at < 1 || at >= groups.length) at = 0
  var out = groups[0]
  for (var i = 1; i < groups.length; i++)
    out += (i === at ? "<br/>" : sep) + groups[i]
  return out
}

function validFingerprint(fp) {
  return /^[0-9A-F]{4}(-[0-9A-F]{4}){4}$/.test(formatFingerprint(fp))
}

// The handle shown wherever a key would otherwise be. Never falls back to the
// raw key: a 2573-character string in a label slot is not a handle, and a
// truncated one invites exactly the mistaken-identity error the fingerprint
// exists to prevent.
function handleOf(entry) {
  if (!entry) return "no fingerprint"
  var fp = formatFingerprint(entry.fingerprint)
  return fp === "" ? "no fingerprint" : fp
}

function keyLengthNote(key) {
  var n = String(key || "").length
  return n === 0 ? "" : n + " bech32 chars"
}

// Cross-reference an arbitrary key (an inspector's verifying key, say) against
// what the engine currently lists. Returns null when nothing matches -- an
// unrecognised signer is a real answer and must stay visible as one.
function knownKey(status, extraRecipients, key) {
  var k = String(key || "")
  if (k === "") return null
  var i
  var ids = identities(status)
  for (i = 0; i < ids.length; i++)
    if (String(ids[i].recipient) === k)
      return { kind: "identity", label: String(ids[i].name),
               fingerprint: formatFingerprint(ids[i].fingerprint) }
  var book = recipients(status)
  for (i = 0; i < book.length; i++)
    if (String(book[i].key) === k)
      return { kind: "recipient", label: String(book[i].label),
               fingerprint: formatFingerprint(book[i].fingerprint) }
  var extra = extraRecipients || []
  for (i = 0; i < extra.length; i++)
    if (String(extra[i].key) === k)
      return { kind: "recipient", label: String(extra[i].label),
               fingerprint: formatFingerprint(extra[i].fingerprint) }
  return null
}

// The same cross-reference, keyed by RECIPIENT fingerprint. Signer
// fingerprints live in a different namespace and must never be looked up
// here; `signedByIdentity` is the only correct route for those. An entry this
// vault does not know stays visibly unknown.
function knownFingerprint(status, fingerprint) {
  var fp = formatFingerprint(fingerprint)
  if (fp === "") return null
  var i
  var ids = identities(status)
  for (i = 0; i < ids.length; i++)
    if (formatFingerprint(ids[i].fingerprint) === fp)
      return { kind: "identity", label: String(ids[i].name), fingerprint: fp }
  var book = recipients(status)
  for (i = 0; i < book.length; i++)
    if (formatFingerprint(book[i].fingerprint) === fp)
      return { kind: "recipient", label: String(book[i].label),
               fingerprint: fp }
  return null
}

// ------------------------------------------------------------------ paths

function basename(path) {
  var p = String(path || "")
  var i = p.lastIndexOf("/")
  return i < 0 ? p : p.substring(i + 1)
}

function parentDir(path) {
  var p = String(path || "")
  var i = p.lastIndexOf("/")
  return i <= 0 ? "/" : p.substring(0, i)
}

// Accepts what a drop, a paste, or a hand-typed field can produce: a bare
// path, a quoted path, a `file://` URL, or a `~`-relative path. Anything the
// user did not actually name comes back empty rather than guessed.
function normalizePath(raw, home) {
  var s = String(raw === undefined || raw === null ? "" : raw)
  s = s.replace(/^\s+|\s+$/g, "")
  if (s === "") return ""
  s = s.split("\n")[0].replace(/\s+$/, "")
  if ((s.charAt(0) === '"' && s.charAt(s.length - 1) === '"')
      || (s.charAt(0) === "'" && s.charAt(s.length - 1) === "'"))
    s = s.substring(1, s.length - 1)
  if (s.indexOf("file://") === 0) {
    s = s.substring(7)
    try { s = decodeURIComponent(s) } catch (e) { /* keep the raw form */ }
  }
  if (s === "~") return String(home || "")
  if (s.indexOf("~/") === 0) s = String(home || "") + s.substring(1)
  return s
}

function isVaultFile(path) { return /\.anubis$/.test(String(path || "")) }

function encryptOutput(path) {
  var p = String(path || "")
  return p === "" ? "" : p + ".anubis"
}

function decryptOutput(path) {
  var p = String(path || "")
  if (p === "") return ""
  return isVaultFile(p) ? p.substring(0, p.length - 7) : p + ".decrypted"
}

function outputFor(op, path) {
  return op === "decrypt" ? decryptOutput(path) : encryptOutput(path)
}

// ---------------------------------------------------------------- settings

var SETTINGS_DEFAULTS = {
  pollIntervalSec: 30,
  confirmOverwrite: true,
  defaultIdentity: "",
  motionEnabled: true
}

function clampInt(value, min, max, fallback) {
  var n = parseInt(String(value), 10)
  if (!isFinite(n)) return fallback
  if (n < min) return min
  if (n > max) return max
  return n
}

function asBool(value, fallback) {
  if (value === undefined || value === null) return fallback
  if (value === true || value === false) return value
  var s = String(value).toLowerCase()
  if (s === "true" || s === "1" || s === "yes" || s === "on") return true
  if (s === "false" || s === "0" || s === "no" || s === "off") return false
  return fallback
}

function resolveSettings(raw) {
  var r = raw || {}
  return {
    pollIntervalSec: clampInt(r.pollIntervalSec, 5, 600,
                              SETTINGS_DEFAULTS.pollIntervalSec),
    confirmOverwrite: asBool(r.confirmOverwrite,
                             SETTINGS_DEFAULTS.confirmOverwrite),
    motionEnabled: asBool(r.motionEnabled, SETTINGS_DEFAULTS.motionEnabled),
    defaultIdentity: String(r.defaultIdentity === undefined
                            || r.defaultIdentity === null
                            ? "" : r.defaultIdentity)
  }
}

// The overlay is not handed the bar entry's inline settings, so it reads the
// same shell.json the bar host reads. A malformed or absent file yields the
// declared defaults rather than a broken surface.
function settingsFromShellJson(text, pluginId) {
  var doc = null
  try { doc = JSON.parse(String(text || "")) } catch (e) { return {} }
  if (!doc) return {}
  var id = String(pluginId)
  var sections = ["left", "center", "right"]
  var layout = doc.bar && doc.bar.layout ? doc.bar.layout : {}
  for (var s = 0; s < sections.length; s++) {
    var list = layout[sections[s]]
    if (!Array.isArray(list)) continue
    for (var i = 0; i < list.length; i++)
      if (list[i] && list[i].id === id) return list[i]
  }
  if (Array.isArray(doc.plugins))
    for (var p = 0; p < doc.plugins.length; p++)
      if (doc.plugins[p] && doc.plugins[p].id === id) return doc.plugins[p]
  return {}
}

// ------------------------------------------------------------ status rows

function identities(status) {
  return status && Array.isArray(status.identities) ? status.identities : []
}

// Just the names, for the settings sheet's hint about which identity a blank
// "default identity" field would otherwise leave to the engine.
function identityNames(status) {
  var out = []
  var rows = identities(status)
  for (var i = 0; i < rows.length; i++) {
    var name = String(rows[i] && rows[i].name ? rows[i].name : "")
    if (name !== "") out.push(name)
  }
  return out
}

function recipients(status) {
  return status && Array.isArray(status.recipients) ? status.recipients : []
}

// Newest first. The engine already emits recent operations in that order, but
// the timeline sorts defensively so a reordered file cannot silently present
// an old failure as the latest state.
function recentOps(status) {
  var rows = status && Array.isArray(status.recent) ? status.recent.slice() : []
  rows.sort(function (a, b) {
    return (Date.parse(b && b.ts) || 0) - (Date.parse(a && a.ts) || 0)
  })
  return rows
}

function counts(status) {
  var c = status && status.counts ? status.counts : {}
  return {
    encrypt: Number(c.encrypt || 0),
    decrypt: Number(c.decrypt || 0),
    failed: Number(c.failed || 0)
  }
}

function lastOp(status) {
  var rows = recentOps(status)
  return rows.length > 0 ? rows[0] : null
}

function lastOpFailed(status) {
  var op = lastOp(status)
  return !!(op && op.ok === false)
}

function identityByName(status, name) {
  var list = identities(status)
  for (var i = 0; i < list.length; i++)
    if (String(list[i].name) === String(name)) return list[i]
  return null
}

// The identity actually used when the operator has not picked one: the
// configured default if it exists, otherwise the first identity the engine
// listed. Returns "" when there is nothing to choose.
function effectiveIdentity(status, configuredDefault, chosen) {
  var pick = String(chosen || "")
  if (pick !== "" && identityByName(status, pick)) return pick
  var cfg = String(configuredDefault || "")
  if (cfg !== "" && identityByName(status, cfg)) return cfg
  var list = identities(status)
  return list.length > 0 ? String(list[0].name) : ""
}

// A signature needs a private key, so signing is only offerable when the
// engine has listed at least one identity that declares signing material.
function canSign(status) {
  var list = identities(status)
  for (var i = 0; i < list.length; i++) if (list[i].signing === true) return true
  return false
}

// ------------------------------------------------------------- bar summary

function panelState(engineMissing, status, statusError) {
  if (engineMissing) return "absent"
  if (statusError && String(statusError) !== "") return "error"
  if (!status) return "unknown"
  if (lastOpFailed(status)) return "failed"
  return "ready"
}

function panelGlyph(state) {
  if (state === "absent") return GLYPH.lockOutline
  if (state === "failed" || state === "error") return GLYPH.shieldAlert
  if (state === "unknown") return GLYPH.shield
  return GLYPH.shieldKey
}

function panelTooltip(state, status, engineMissing) {
  if (engineMissing)
    return "ANUBIS -- engine not installed\n" + installHint()
  var idc = identities(status).length
  var rec = recipients(status).length
  var head = "ANUBIS " + engineVersion(status)
  var body = idc + (idc === 1 ? " identity" : " identities")
    + "  |  " + rec + (rec === 1 ? " recipient" : " recipients")
  if (state === "failed") {
    var op = lastOp(status)
    body += "\nlast operation FAILED"
      + (op && op.error ? ": " + String(op.error) : "")
  } else if (state === "error") {
    body += "\nstatus could not be read"
  } else if (state === "unknown") {
    body += "\nno status yet"
  }
  return head + "\n" + body + "\n" + suiteBadge(suiteOf(status))
    + "\nclick for the vault"
}

// ------------------------------------------------------------ progress

function progressLabel(op, done, total, elapsedMs) {
  if (op === "") return ""
  var parts = [op]
  if (Number(total) > 0) {
    parts.push(formatPct(pctOf(done, total)))
    parts.push(formatBytes(done) + " / " + formatBytes(total))
  } else if (Number(done) > 0) {
    parts.push(formatBytes(done))
  }
  var rate = formatRate(done, elapsedMs)
  if (rate !== "") parts.push(rate)
  return parts.join("  |  ")
}

// Parse one line of the engine's streaming JSON. A line that is not a
// complete JSON object is dropped rather than partially interpreted: a
// half-written progress record must never become a result.
function parseLine(line) {
  var s = String(line || "").replace(/^\s+|\s+$/g, "")
  if (s === "" || s.charAt(0) !== "{") return null
  try {
    var o = JSON.parse(s)
    return (o && typeof o === "object" && o.kind) ? o : null
  } catch (e) { return null }
}

// Machine-readable status is a protocol, not a bag of optional UI hints.
// Requiring the complete top-level shape prevents a truncated or unrelated
// `{"kind":"status"}` line from turning the vault health indicator green.
function validStatusRecord(o) {
  if (!o || o.kind !== "status") return false
  if (typeof o.version !== "string" || o.version === "") return false
  if (typeof o.generated !== "string" || o.generated === "") return false
  if (!Array.isArray(o.identities) || !Array.isArray(o.recipients)
      || !Array.isArray(o.recent)) return false
  var s = o.suite
  if (!s || typeof s !== "object") return false
  if (typeof s.kem !== "string" || s.kem === "") return false
  if (typeof s.sig !== "string" || s.sig === "") return false
  if (typeof s.aead !== "string" || s.aead === "") return false
  if (typeof s.kdf !== "string" || s.kdf === "") return false
  if (typeof s.format !== "string" || s.format === "") return false
  if (typeof s.pure_rust !== "boolean" || !Array.isArray(s.fips)) return false
  var c = o.counts
  if (!c || typeof c !== "object") return false
  var names = ["encrypt", "decrypt", "failed"]
  for (var i = 0; i < names.length; i++) {
    var value = c[names[i]]
    if (typeof value !== "number" || !isFinite(value) || value < 0)
      return false
  }
  return true
}

// SHA-512 over the exact decoded binary container, including any signature
// trailer. The engine emits lowercase hex with no prefix. No fallback is
// allowed: path, size and header fields do not identify immutable bytes.
function contentId(record) {
  var value = record ? String(record.content_id || "") : ""
  return /^[0-9a-f]{128}$/.test(value) ? value : ""
}

// A child may finish after its caller cancelled it and selected another file.
// Generation and target must both match before any of that child's output can
// mutate visible state. Kept pure so the asynchronous boundary is executable
// in the QML protocol tests rather than source-reviewed only.
function runIsCurrent(runGeneration, runTarget, currentGeneration,
                      currentTarget) {
  var target = String(runTarget || "")
  return target !== "" && runGeneration === currentGeneration
    && target === String(currentTarget || "")
}

// Decide whether one parsed inspect response is eligible to become current
// state. Content identity is deliberately not required here: an older engine
// may still expose neutral header metadata, while the attestation helpers
// below independently fail closed when contentId() is empty.
function inspectRecordAccepted(record, exitCode, protocolValid, recordCount,
                               reportedError, expectedPath) {
  if (exitCode !== 0 || protocolValid !== true
      || String(reportedError || "") !== ""
      || !record || record.kind !== "inspect" || recordCount !== 1
      || String(record.path || "") !== String(expectedPath || "")) return false

  // `inspect` reports presence only. It cannot verify either keyed state, so
  // accepting a boolean verdict here would let malformed engine output paint
  // VERIFIED without doing the corresponding cryptographic operation.
  if (record.signed !== true && record.signed !== false) return false
  if (record.header_mac_ok !== null && record.header_mac_ok !== undefined)
    return false
  if (record.signature_ok !== null && record.signature_ok !== undefined)
    return false

  var signer = formatFingerprint(record.signer_fingerprint)
  if (record.signed === true && !validFingerprint(signer)) return false
  if (record.signed === false
      && record.signer_fingerprint !== null
      && record.signer_fingerprint !== undefined
      && String(record.signer_fingerprint) !== "") return false

  return typeof record.format === "string" && record.format !== ""
    && typeof record.recipients === "number" && isFinite(record.recipients)
    && record.recipients >= 0
    && typeof record.header_bytes === "number" && isFinite(record.header_bytes)
    && record.header_bytes >= 0
    && typeof record.payload_bytes === "number" && isFinite(record.payload_bytes)
    && record.payload_bytes >= 0
    && typeof record.chunks === "number" && isFinite(record.chunks)
    && record.chunks >= 0
}

// A successful decrypt result is eligible to become an authentication
// attestation only when its entire security envelope is coherent. This is
// intentionally stricter than the generic operation record: `signed:false`
// cannot carry a positive signature verdict, and a signed success must name
// the exact signer whose signature was checked.
function decryptResultAccepted(record, exitCode, protocolValid, recordCount,
                               expectedPath, expectedOutput) {
  if (exitCode !== 0 || protocolValid !== true || !record
      || record.kind !== "result" || recordCount !== 1
      || record.ok !== true || record.op !== "decrypt"
      || String(record.path || "") !== String(expectedPath || "")
      || String(record.out || "") !== String(expectedOutput || "")
      || typeof record.bytes !== "number" || !isFinite(record.bytes)
      || record.bytes < 0 || record.header_mac_ok !== true
      || contentId(record) === ""
      || (record.signed !== true && record.signed !== false)) return false

  if (record.signed === true) {
    return record.signature_ok === true
      && validFingerprint(record.signer_fingerprint)
  }
  return (record.signature_ok === null || record.signature_ok === undefined)
    && (record.signer_fingerprint === null
        || record.signer_fingerprint === undefined
        || String(record.signer_fingerprint) === "")
}

// Classify a verify response without mutating UI state. Only `verified` may
// promote a signature. `rejected` is a valid negative cryptographic verdict;
// every other value means no verdict may be retained.
function verifyRecordDecision(record, exitCode, protocolValid, recordCount,
                              expectedContentId, expectedSigner) {
  if (protocolValid !== true || !record || record.kind !== "verify"
      || recordCount !== 1) return "record-invalid"

  // A cryptographic verdict is meaningful only when the record's envelope
  // agrees with it. Do not let a truncated or contradictory object such as
  // `signature_ok:true, signed:false` promote the UI merely because the two
  // identity fields happen to match.
  if (typeof record.ok !== "boolean"
      || (record.signed !== true && record.signed !== false))
    return "record-invalid"

  var actualContentId = contentId(record)
  if (actualContentId === "" || actualContentId !== expectedContentId)
    return "content-mismatch"

  // This tuple is the only coherent unsigned response. The current desktop
  // never launches verify for an unsigned inspection, but retaining the
  // protocol state keeps this pure classifier complete and prevents a future
  // caller from turning absence into a failed-signature attestation.
  if (record.signed === false) {
    var noSigner = record.signer_fingerprint === null
      || record.signer_fingerprint === undefined
      || String(record.signer_fingerprint) === ""
    var noVerdict = record.signature_ok === null
      || record.signature_ok === undefined
    if (String(expectedSigner || "") !== "" || !noSigner || !noVerdict
        || record.ok !== false || exitCode === 0) return "record-invalid"
    return "verdict-missing"
  }

  var actualSigner = formatFingerprint(record.signer_fingerprint)
  if (!validFingerprint(actualSigner) || !validFingerprint(expectedSigner)
      || actualSigner !== expectedSigner)
    return "signer-mismatch"

  if (record.signature_ok !== true && record.signature_ok !== false)
    return "verdict-missing"
  if (record.ok !== (record.signature_ok === true)) return "record-invalid"
  if (record.signature_ok === true && exitCode !== 0) return "exit-failed"
  if (record.signature_ok === false && exitCode === 0) return "record-invalid"
  return record.signature_ok === true ? "verified" : "rejected"
}

function attestationMatches(inspect, attested) {
  var id = contentId(inspect)
  return id !== "" && !!attested && attested.content_id === id
}

function signatureAttestationMatches(inspect, attested) {
  if (!attestationMatches(inspect, attested)) return false
  var current = signerFingerprint(inspect)
  var checked = formatFingerprint(attested.fingerprint)
  return current !== "" && validFingerprint(current) && checked === current
}

// ------------------------------------------------------------- inspector

function stanzaRows(inspect) {
  return inspect && Array.isArray(inspect.stanzas) ? inspect.stanzas : []
}

// Tone names, not colours: the QML layer owns the palette.
//
// `header_mac_ok` is ALWAYS null from `inspect`, and that is by design, not
// sloppiness: the header MAC key is derived from the file key, so only a
// recipient can check it and inspect never decrypts. Null is therefore an
// honest "not determinable from here" and MUST NOT be painted as a failure.
// Urgent is reserved for a decrypt or a signature that actually failed.
function macTone(inspect) {
  if (!inspect || inspect.header_mac_ok === undefined
      || inspect.header_mac_ok === null) return "unknown"
  return inspect.header_mac_ok === true ? "good" : "bad"
}

function macLabel(inspect) {
  var tone = macTone(inspect)
  if (tone === "good") return "HEADER MAC VERIFIED"
  if (tone === "bad") return "HEADER MAC FAILED"
  return "HEADER MAC NOT DETERMINABLE HERE"
}

function macExplanation(inspect) {
  var tone = macTone(inspect)
  if (tone === "bad")
    return "HMAC-SHA512 over the header did not match. The header was "
      + "altered after it was written."
  if (tone === "good")
    return "HMAC-SHA512 over the header matched. Integrity of the stanzas, "
      + "not the identity of the sender."
  return "The header MAC key is derived from the file key, so only a "
    + "recipient can verify it and inspect never decrypts. Run a decrypt to "
    + "check it. Unknown here is not a failure."
}

// `inspect` can never state the header MAC, but a successful DECRYPT can:
// reaching one is only possible after the MAC has been checked, so the engine
// reports `header_mac_ok: true` on the decrypt result. These variants are used
// only when such a decrypt actually happened for this exact container, and
// they say so -- the claim is about a check that ran, not about the file's
// general trustworthiness.
function macToneAttested(inspect, attested) {
  var tone = macTone(inspect)
  if (tone !== "unknown") return tone
  return attestationMatches(inspect, attested) ? "good" : "unknown"
}

function macLabelAttested(inspect, attested) {
  if (macTone(inspect) !== "unknown") return macLabel(inspect)
  return attestationMatches(inspect, attested)
    ? "HEADER MAC VERIFIED BY DECRYPT" : macLabel(inspect)
}

function macExplanationAttested(inspect, attested) {
  if (macTone(inspect) !== "unknown") return macExplanation(inspect)
  if (!attestationMatches(inspect, attested)) return macExplanation(inspect)
  var at = String(attested.at || "")
  return "A decrypt of this container at " + stampClock(at)
    + " checked the header MAC and it matched. inspect cannot re-check it "
    + "on its own, because it holds no key."
}

// The engine reports the signer as `signer_fingerprint` -- already a
// fingerprint in the same 5x4 uppercase hex form, never a raw key. There is
// nothing to truncate and nothing to reconstruct.
//
// This is a DIFFERENT namespace from a recipient fingerprint: it hashes the
// ML-DSA-87 verifying key, not the KEM recipient payload. The two must never
// be compared, and the only identity field it may be checked against is
// `signing_fingerprint`.
function signerFingerprint(inspect) {
  return inspect ? formatFingerprint(inspect.signer_fingerprint) : ""
}

// Real attribution: does a signer fingerprint belong to an identity in this
// vault? Compared only against `signing_fingerprint`, so a hit is a true
// statement and a miss is an equally true "not this vault", not the always-on
// false alarm that comparing across namespaces would produce.
function signedByIdentity(status, inspect) {
  var fp = signerFingerprint(inspect)
  if (fp === "") return null
  var list = identities(status)
  for (var i = 0; i < list.length; i++)
    if (formatFingerprint(list[i].signing_fingerprint) === fp)
      return { name: String(list[i].name), fingerprint: fp }
  return null
}

function signingFingerprint(identity) {
  return identity ? formatFingerprint(identity.signing_fingerprint) : ""
}

// A signature's PRESENCE and its VALIDITY are different claims, and this
// surface must never merge them. `inspect` reads the header alone; checking a
// signature means hashing every byte of payload, which inspect does not do. So
// a container can be known to be signed and not known to be validly signed.
//
// Until v2.0.0 this function returned "good" -- the accent tone, which on this
// surface means VERIFIED -- for any container whose header carried a signer.
// That was an unearned pass: nothing had verified anything. The engine now has
// a keyless `verify`, so the honest states are distinguishable and this returns
// "notice" (a readable neutral) for present-but-unchecked.
function signatureTone(inspect) {
  if (!inspect) return "unknown"
  if (inspect.signed !== true) return "none"
  if (inspect.signature_ok === true) return "good"
  if (inspect.signature_ok === false) return "bad"
  return "notice"
}

function signatureLabel(inspect) {
  var tone = signatureTone(inspect)
  if (tone === "good") return "SIGNATURE VERIFIED -- ML-DSA-87"
  if (tone === "bad") return "SIGNATURE FAILED"
  if (tone === "notice") return "SIGNED -- NOT VERIFIED HERE"
  if (tone === "none") return "UNSIGNED"
  return "SIGNATURE NOT STATED"
}

function signatureExplanation(inspect) {
  var tone = signatureTone(inspect)
  if (tone === "bad")
    return "The ML-DSA-87 signature does not match these bytes. The file "
      + "changed after it was signed, or it was not signed by that key."
  if (tone === "good")
    return "The ML-DSA-87 signature matched over this exact file."
  if (tone === "none")
    return "No signature. That is not the same as the sender not signing: "
      + "any recipient holds the file key and can strip a signature, so "
      + "absence carries no information. Require one up front instead."
  if (tone === "notice")
    return "The header names a signer, and nothing here has checked its "
      + "signature -- that means hashing the whole payload, which inspect "
      + "does not do. Verify needs no key and decrypts nothing."
  return "The engine did not state whether this container is signed."
}

// A `verify` that actually ran over these exact bytes is allowed to promote
// the chip, exactly as a decrypt promotes the header MAC. The claim is about a
// check that happened, at a stated time, and is never persisted.
function signatureToneAttested(inspect, attested) {
  var tone = signatureTone(inspect)
  if (tone !== "notice") return tone
  if (!signatureAttestationMatches(inspect, attested)) return tone
  return attested.ok === true ? "good" : "bad"
}

function signatureLabelAttested(inspect, attested) {
  var tone = signatureTone(inspect)
  if (tone !== "notice" || !signatureAttestationMatches(inspect, attested))
    return signatureLabel(inspect)
  return attested.ok === true ? "SIGNATURE VERIFIED -- ML-DSA-87"
                              : "SIGNATURE FAILED"
}

function signatureExplanationAttested(inspect, attested) {
  var tone = signatureTone(inspect)
  if (tone !== "notice" || !signatureAttestationMatches(inspect, attested))
    return signatureExplanation(inspect)
  if (attested.ok !== true)
    return "A verify of this container at " + stampClock(attested.at)
      + " checked the ML-DSA-87 signature and it did NOT match. "
      + String(attested.error || "")
  return "A check of this container at " + stampClock(attested.at)
    + " verified the ML-DSA-87 signature over these exact bytes. It proves "
    + "the holder of that key produced this file; it does not say who that "
    + "holder is."
}

// -------------------------------------------------- legacy-format notices
//
// A container written by anubis-rage 1.x is not a tampered container. The
// engine says so explicitly by pointing at MIGRATION.md, and that distinction
// has to survive into the pixels: urgent styling is reserved for
// authentication and signature failures, which mean somebody changed bytes.
// An old file means somebody upgraded.

function isMigrationNotice(text) {
  return /see MIGRATION\.md/.test(String(text || ""))
}

function isContentIdNotice(text) {
  return /^content identity unavailable:/.test(String(text || ""))
}

// "notice" is a third tone alongside good/bad/neutral, and the only one an
// error string can map to without implying tampering.
function noticeTone(text) {
  if (String(text || "") === "") return "neutral"
  return isMigrationNotice(text) || isContentIdNotice(text) ? "notice" : "bad"
}

function noticeGlyph(text) {
  return isMigrationNotice(text) || isContentIdNotice(text)
    ? GLYPH.info : GLYPH.alert
}

function noticeHeading(text) {
  if (String(text || "") === "") return ""
  if (isContentIdNotice(text))
    return "ENGINE UPGRADE REQUIRED FOR BYTE-BOUND ATTESTATIONS"
  return isMigrationNotice(text)
    ? "LEGACY CONTAINER -- UPGRADE PATH, NOT A FAILURE"
    : "HEADER COULD NOT BE READ"
}

// The engine names the legacy generation in its own message; this only adds
// what to do about it, and never restates the version itself.
function noticeAdvice(text) {
  if (isContentIdNotice(text))
    return "Header fields remain visible, but this session will not reuse "
      + "a MAC or signature verdict without an immutable SHA-512 content ID."
  return isMigrationNotice(text)
    ? "This container predates the ANUBIS/v3 wire format and is not "
      + "interoperable with it. Its integrity is not in question here -- "
      + "this engine simply does not read that generation. Decrypt it with "
      + "the tool that wrote it, then re-encrypt with ANUBIS."
    : ""
}

// The engine reports a top-level recipient count and also one per stanza.
// The top-level number is authoritative; the stanza sum is only a fallback
// for a payload that did not carry one.
function inspectRecipients(inspect) {
  if (!inspect) return 0
  if (inspect.recipients !== undefined && inspect.recipients !== null)
    return Number(inspect.recipients)
  return totalStanzaRecipients(inspect)
}

function totalStanzaRecipients(inspect) {
  var rows = stanzaRows(inspect)
  var n = 0
  for (var i = 0; i < rows.length; i++) n += Number(rows[i].recipients || 0)
  return n
}

function inspectFacts(inspect) {
  if (!inspect) return []
  var rows = [
    // Verbatim. The wire format versions on the engine's schedule and is
    // never reconstructed from a constant in this panel.
    { label: "wire format", value: String(inspect.format || "--"),
      tone: "neutral" },
    { label: "payload",     value: formatBytes(inspect.payload_bytes),
      tone: "neutral" },
    { label: "chunks",      value: String(inspect.chunks === undefined
                                          ? "--" : inspect.chunks),
      tone: "neutral" },
    { label: "recipients",  value: String(inspectRecipients(inspect)),
      tone: "neutral" }
  ]
  if (inspect.header_bytes !== undefined && inspect.header_bytes !== null)
    rows.splice(1, 0, { label: "header", value: formatBytes(inspect.header_bytes),
                        tone: "neutral" })
  return rows
}

// The chunk arithmetic the engine reports is restated, not recomputed: this
// only says what a 64 KiB STREAM chunking implies for the payload it named,
// so a mismatch stays visible instead of being smoothed over.
var CHUNK_BYTES = 65536

function impliedChunks(payloadBytes) {
  var b = Number(payloadBytes)
  if (!isFinite(b) || b < 0) return -1
  if (b === 0) return 0
  return Math.ceil(b / CHUNK_BYTES)
}

function chunkNote(inspect) {
  if (!inspect) return ""
  var implied = impliedChunks(inspect.payload_bytes)
  var stated = Number(inspect.chunks)
  if (implied < 0 || !isFinite(stated)) return ""
  if (implied === stated) return "consistent with 64 KiB STREAM chunking"
  return "engine states " + stated + " chunks; 64 KiB chunking implies "
    + implied
}

// ------------------------------------------------------------- activity

// Newest-last series for the audit strip. Each entry carries the byte count
// (bar height) and the ok flag (bar tone). Failures with no byte count still
// get a visible minimum so a failure is never an invisible gap.
function activitySeries(status, limit) {
  var rows = recentOps(status)
  var n = Math.min(rows.length, limit)
  var out = []
  for (var i = n - 1; i >= 0; i--) {
    var r = rows[i]
    out.push({
      bytes: Number(r.bytes || 0),
      ok: r.ok !== false,
      op: String(r.op || "")
    })
  }
  return out
}

function activityMax(series) {
  var m = 1
  for (var i = 0; i < series.length; i++)
    if (series[i].bytes > m) m = series[i].bytes
  return m
}

function activitySummary(status, limit) {
  var series = activitySeries(status, limit)
  if (series.length === 0) return "no operations recorded"
  var bytes = 0
  var failed = 0
  for (var i = 0; i < series.length; i++) {
    bytes += series[i].bytes
    if (!series[i].ok) failed++
  }
  // One fact per line rather than one pipe-separated run. In a 360px rail the
  // run wrapped wherever it liked, which split "5.0 GiB" across two lines and
  // read as two different numbers.
  return "last " + series.length + " operations\n" + formatBytes(bytes)
    + " processed\n" + failed + " failed"
}

function opSummary(row) {
  if (!row) return ""
  var parts = []
  if (row.bytes !== undefined && row.bytes !== null)
    parts.push(formatBytes(row.bytes))
  if (row.ms !== undefined && row.ms !== null) parts.push(formatMillis(row.ms))
  var rate = formatRate(row.bytes, row.ms)
  if (rate !== "") parts.push(rate)
  if (row.recipients) parts.push(row.recipients
    + (Number(row.recipients) === 1 ? " recipient" : " recipients"))
  if (row.signed === true) parts.push("signed")
  return parts.join("  |  ")
}

// -------------------------------------------------------- recipient book
//
// The address book lives in ~/.config/anubis/recipients.toml but is only ever
// read and written through the engine, so there is one parser and no write
// race between this panel and a concurrent CLI invocation. These helpers only
// pre-validate, so an obviously malformed entry is refused before a
// subprocess is spawned; the engine remains the authority.

var BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

function validRecipient(key) {
  var s = String(key || "")
  if (s.indexOf("anubis1") !== 0) return false
  if (s.length < 64) return false
  for (var i = 7; i < s.length; i++)
    if (BECH32_CHARSET.indexOf(s.charAt(i)) < 0) return false
  return true
}

function recipientRefusal(label, key, existing) {
  if (!validLabel(label))
    return "Label refused: letters, digits, dot, dash, underscore; 64 max."
  if (labelTaken(existing, label))
    return "Label refused: \"" + label + "\" is already in the address book."
  if (!validRecipient(key))
    return "Key refused before any subprocess: an ANUBIS recipient starts "
      + "with anubis1 and is bech32 throughout."
  return ""
}

function validLabel(label) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(String(label || ""))
}

function validIdentityName(name) {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(String(name || ""))
}

function labelTaken(list, label) {
  for (var i = 0; i < list.length; i++)
    if (String(list[i].label) === String(label)) return true
  return false
}

// ---------------------------------------------------------- selection sets

function toggleMember(list, value) {
  var out = []
  var found = false
  for (var i = 0; i < list.length; i++) {
    if (list[i] === value) found = true
    else out.push(list[i])
  }
  if (!found) out.push(value)
  return out
}

function isMember(list, value) {
  for (var i = 0; i < list.length; i++) if (list[i] === value) return true
  return false
}

// Selected recipient keys, filtered against what the engine currently lists so
// a key removed from the address book cannot linger in a pending command.
function selectedKeys(status, selection) {
  var known = {}
  var i
  var book = recipients(status)
  for (i = 0; i < book.length; i++) known[String(book[i].key)] = true
  var ids = identities(status)
  for (i = 0; i < ids.length; i++) known[String(ids[i].recipient)] = true
  var out = []
  for (i = 0; i < selection.length; i++)
    if (known[String(selection[i])]) out.push(String(selection[i]))
  return out
}

// Fingerprints of the current selection, for the confirmation line above the
// Encrypt button. The operator confirms fingerprints, never truncated keys.
function selectionHandles(status, selection) {
  var keys = selectedKeys(status, selection)
  var out = []
  for (var i = 0; i < keys.length; i++) {
    var hit = knownKey(status, [], keys[i])
    out.push(hit ? hit.label + " " + hit.fingerprint : "unknown key")
  }
  return out
}

// ------------------------------------------------------------ layout math

// Column widths for the cockpit body. The centre console takes what the two
// fixed rails leave, with a floor so the operation form never collapses into
// an unusable sliver on a narrow display.
function columnWidths(totalWidth, gap) {
  var rail = Math.round(Math.max(240, Math.min(360, totalWidth * 0.22)))
  var centre = totalWidth - (rail * 2) - (gap * 2)
  if (centre < 420) {
    rail = Math.max(200, Math.floor((totalWidth - 420 - gap * 2) / 2))
    centre = totalWidth - (rail * 2) - (gap * 2)
  }
  return { left: rail, centre: Math.max(280, centre), right: rail }
}

function metricColumn(width) {
  return Math.round(Math.min(width * 0.45, 210))
}

function installHint() {
  return "cargo install --git https://github.com/AnubisQuantumCipher/anubis anubis-cli"
}

// The honest boundary line. It states the standardisation facts, the hybrid
// argument, and -- deliberately -- what this panel is not.
function assuranceLine() {
  return "ML-KEM-1024 (FIPS 203) and ML-DSA-87 (FIPS 204) are NIST-standardized; "
    + "hybrid mode requires breaking BOTH X25519 and ML-KEM-1024. "
    + "This panel renders engine output; it performs no cryptography itself. "
    + "A verified header MAC says the header is intact, not who sent it -- "
    + "only a signature whose fingerprint you checked out of band says that."
}

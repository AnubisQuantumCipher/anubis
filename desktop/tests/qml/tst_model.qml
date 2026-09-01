import QtQuick
import QtTest
import "../../qml/Model.js" as Model

TestCase {
  name: "ModelProtocol"

  function repeated(character, count) {
    var result = ""
    for (var i = 0; i < count; i++) result += character
    return result
  }

  function completeStatus() {
    return {
      kind: "status",
      version: "test",
      generated: "now",
      identities: [],
      recipients: [],
      recent: [],
      counts: { encrypt: 0, decrypt: 0, failed: 0 },
      suite: {
        kem: "kem",
        sig: "sig",
        aead: "aead",
        kdf: "kdf",
        format: "format",
        pure_rust: true,
        fips: []
      }
    }
  }

  function test_statusRequiresCompleteSchema() {
    verify(!Model.validStatusRecord({ kind: "status" }))
    verify(Model.validStatusRecord(completeStatus()))

    var partial = completeStatus()
    delete partial.counts.failed
    verify(!Model.validStatusRecord(partial))
  }

  function test_contentIdIsExactLowercaseSha512Hex() {
    var valid = repeated("a", 128)
    compare(Model.contentId({ content_id: valid }), valid)
    compare(Model.contentId({ content_id: valid.toUpperCase() }), "")
    compare(Model.contentId({ content_id: repeated("a", 127) }), "")
    compare(Model.contentId({}), "")
  }

  function test_attestationsRequireContentAndSignerMatch() {
    var content = repeated("b", 128)
    var inspect = {
      content_id: content,
      signed: true,
      signer_fingerprint: "AAAA-BBBB-CCCC-DDDD-EEEE"
    }
    var attested = {
      content_id: content,
      fingerprint: "AAAA-BBBB-CCCC-DDDD-EEEE",
      ok: true,
      at: "now"
    }

    compare(Model.macToneAttested(inspect, attested), "good")
    compare(Model.signatureToneAttested(inspect, attested), "good")

    var otherContent = {
      content_id: repeated("c", 128),
      fingerprint: attested.fingerprint,
      ok: true
    }
    compare(Model.macToneAttested(inspect, otherContent), "unknown")
    compare(Model.signatureToneAttested(inspect, otherContent), "notice")

    var otherSigner = {
      content_id: content,
      fingerprint: "1111-2222-3333-4444-5555",
      ok: true
    }
    compare(Model.signatureToneAttested(inspect, otherSigner), "notice")
  }

  function verifyRecord(content, signer) {
    return {
      kind: "verify",
      content_id: content,
      signer_fingerprint: signer,
      signed: true,
      ok: true,
      signature_ok: true
    }
  }

  function decryptRecord(content, signer) {
    return {
      kind: "result",
      op: "decrypt",
      ok: true,
      path: "/tmp/sealed.anubis",
      out: "/tmp/opened.txt",
      bytes: 12,
      signed: true,
      signer_fingerprint: signer,
      content_id: content,
      header_mac_ok: true,
      signature_ok: true
    }
  }

  function inspectRecord(path, signed) {
    return {
      kind: "inspect",
      path: path,
      format: "anubis-encryption.org/v3",
      recipients: 1,
      signed: signed,
      signer_fingerprint: signed
        ? "AAAA-BBBB-CCCC-DDDD-EEEE" : null,
      content_id: repeated("a", 128),
      header_bytes: 12,
      payload_bytes: 34,
      chunks: 1,
      header_mac_ok: null,
      signature_ok: null
    }
  }

  function test_verifyAcceptanceFailsClosed() {
    var expectedContent = repeated("d", 128)
    var otherContent = repeated("e", 128)
    var expectedSigner = "AAAA-BBBB-CCCC-DDDD-EEEE"
    var otherSigner = "1111-2222-3333-4444-5555"
    var valid = verifyRecord(expectedContent, expectedSigner)

    compare(Model.verifyRecordDecision(
              valid, 0, true, 1, expectedContent, expectedSigner),
            "verified")
    compare(Model.verifyRecordDecision(
              verifyRecord(otherContent, expectedSigner),
              0, true, 1, expectedContent, expectedSigner),
            "content-mismatch")
    compare(Model.verifyRecordDecision(
              verifyRecord(expectedContent, otherSigner),
              0, true, 1, expectedContent, expectedSigner),
            "signer-mismatch")
    compare(Model.verifyRecordDecision(
              valid, 1, true, 1, expectedContent, expectedSigner),
            "exit-failed")
    compare(Model.verifyRecordDecision(
              valid, 0, true, 2, expectedContent, expectedSigner),
            "record-invalid")
    compare(Model.verifyRecordDecision(
              valid, 0, false, 1, expectedContent, expectedSigner),
            "record-invalid")

    var unsigned = verifyRecord(expectedContent, expectedSigner)
    unsigned.signed = false
    compare(Model.verifyRecordDecision(
              unsigned, 0, true, 1, expectedContent, expectedSigner),
            "record-invalid")

    var missingSigned = verifyRecord(expectedContent, expectedSigner)
    delete missingSigned.signed
    compare(Model.verifyRecordDecision(
              missingSigned, 0, true, 1, expectedContent, expectedSigner),
            "record-invalid")

    var falseSuccess = verifyRecord(expectedContent, expectedSigner)
    falseSuccess.ok = false
    compare(Model.verifyRecordDecision(
              falseSuccess, 0, true, 1, expectedContent, expectedSigner),
            "record-invalid")

    var missingOk = verifyRecord(expectedContent, expectedSigner)
    delete missingOk.ok
    compare(Model.verifyRecordDecision(
              missingOk, 0, true, 1, expectedContent, expectedSigner),
            "record-invalid")
  }

  function test_negativeVerifyVerdictRemainsNegative() {
    var content = repeated("f", 128)
    var signer = "AAAA-BBBB-CCCC-DDDD-EEEE"
    var rejected = verifyRecord(content, signer)
    rejected.signature_ok = false
    rejected.ok = false
    compare(Model.verifyRecordDecision(
              rejected, 1, true, 1, content, signer),
            "rejected")

    rejected.ok = true
    compare(Model.verifyRecordDecision(
              rejected, 1, true, 1, content, signer),
            "record-invalid")

    rejected.ok = false
    compare(Model.verifyRecordDecision(
              rejected, 0, true, 1, content, signer),
            "record-invalid")
  }

  function test_unsignedVerifyRecordStaysNonAttesting() {
    var content = repeated("0", 128)
    var unsigned = {
      kind: "verify",
      content_id: content,
      signer_fingerprint: null,
      signed: false,
      ok: false,
      signature_ok: null
    }
    compare(Model.verifyRecordDecision(
              unsigned, 1, true, 1, content, ""),
            "verdict-missing")

    unsigned.signature_ok = true
    compare(Model.verifyRecordDecision(
              unsigned, 1, true, 1, content, ""),
            "record-invalid")
  }

  function test_decryptResultRequiresCoherentAuthenticationEnvelope() {
    var content = repeated("1", 128)
    var signer = "AAAA-BBBB-CCCC-DDDD-EEEE"
    var valid = decryptRecord(content, signer)
    verify(Model.decryptResultAccepted(
             valid, 0, true, 1, valid.path, valid.out))
    verify(!Model.decryptResultAccepted(
             valid, 1, true, 1, valid.path, valid.out))
    verify(!Model.decryptResultAccepted(
             valid, 0, false, 1, valid.path, valid.out))
    verify(!Model.decryptResultAccepted(
             valid, 0, true, 2, valid.path, valid.out))
    verify(!Model.decryptResultAccepted(
             valid, 0, true, 1, "/tmp/other.anubis", valid.out))

    var noMac = decryptRecord(content, signer)
    noMac.header_mac_ok = false
    verify(!Model.decryptResultAccepted(
             noMac, 0, true, 1, noMac.path, noMac.out))

    var contradiction = decryptRecord(content, signer)
    contradiction.signed = false
    verify(!Model.decryptResultAccepted(
             contradiction, 0, true, 1,
             contradiction.path, contradiction.out))

    var badSignature = decryptRecord(content, signer)
    badSignature.signature_ok = false
    verify(!Model.decryptResultAccepted(
             badSignature, 0, true, 1,
             badSignature.path, badSignature.out))

    var missingSigner = decryptRecord(content, signer)
    missingSigner.signer_fingerprint = null
    verify(!Model.decryptResultAccepted(
             missingSigner, 0, true, 1,
             missingSigner.path, missingSigner.out))

    var unsigned = decryptRecord(content, signer)
    unsigned.signed = false
    unsigned.signer_fingerprint = null
    unsigned.signature_ok = null
    verify(Model.decryptResultAccepted(
             unsigned, 0, true, 1, unsigned.path, unsigned.out))
  }

  function test_inspectGenerationAndAcceptanceGuards() {
    var path = "/tmp/current.anubis"
    verify(Model.runIsCurrent(8, path, 8, path))
    verify(!Model.runIsCurrent(7, path, 8, path))
    verify(!Model.runIsCurrent(8, "/tmp/stale.anubis", 8, path))

    var record = inspectRecord(path, true)
    verify(Model.inspectRecordAccepted(record, 0, true, 1, "", path))
    verify(!Model.inspectRecordAccepted(record, 1, true, 1, "", path))
    verify(!Model.inspectRecordAccepted(record, 0, true, 2, "", path))
    verify(!Model.inspectRecordAccepted(record, 0, false, 1, "", path))
    verify(!Model.inspectRecordAccepted(record, 0, true, 1,
                                        "inspect failed", path))
    verify(!Model.inspectRecordAccepted(record, 0, true, 1, "",
                                        "/tmp/other.anubis"))

    var missingSigned = inspectRecord(path, true)
    delete missingSigned.signed
    verify(!Model.inspectRecordAccepted(
             missingSigned, 0, true, 1, "", path))

    var forgedMac = inspectRecord(path, true)
    forgedMac.header_mac_ok = true
    verify(!Model.inspectRecordAccepted(
             forgedMac, 0, true, 1, "", path))

    var forgedSignature = inspectRecord(path, true)
    forgedSignature.signature_ok = true
    verify(!Model.inspectRecordAccepted(
             forgedSignature, 0, true, 1, "", path))

    var unsignedWithSigner = inspectRecord(path, false)
    unsignedWithSigner.signer_fingerprint = "AAAA-BBBB-CCCC-DDDD-EEEE"
    verify(!Model.inspectRecordAccepted(
             unsignedWithSigner, 0, true, 1, "", path))
  }
}

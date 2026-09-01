import QtQuick
import QtTest
import "../../../plugin/khephri.anubis/Model.js" as PluginModel

TestCase {
  name: "PluginModelProtocol"

  function completeStatus() {
    return {
      kind: "status",
      status_schema: "anubis-status/assurance-v1",
      version: "2.1.0",
      generated: "now",
      identities: [],
      recipients: [],
      recent: [],
      counts: { encrypt: 0, decrypt: 0, failed: 0 },
      suite: {
        kem: "X25519+ML-KEM-1024",
        sig: "ML-DSA-87",
        aead: "ChaCha20-Poly1305",
        kdf: "HKDF-SHA512",
        format: "anubis-encryption.org/v3",
        pure_rust: true,
        fips: ["203", "204"],
        nist_standards: ["FIPS 203", "FIPS 204"],
        pq_security_category: 5,
        algorithm_profile: "portable-v3",
        approved_only_mode: false,
        fips_140_3_validated: false,
        fips_140_3_certificate: null
      }
    }
  }

  function test_partialStatusCannotBecomeReady() {
    verify(!PluginModel.validStatusRecord({ kind: "status" }))

    var status = completeStatus()
    verify(PluginModel.validStatusRecord(status))
    compare(PluginModel.panelState(false, status, ""), "ready")

    delete status.suite.kdf
    verify(!PluginModel.validStatusRecord(status))

    var approved = completeStatus()
    approved.suite.approved_only_mode = true
    verify(!PluginModel.validStatusRecord(approved))

    var validated = completeStatus()
    validated.suite.fips_140_3_validated = true
    validated.suite.fips_140_3_certificate = "unverified"
    verify(!PluginModel.validStatusRecord(validated))

    var falseStandard = completeStatus()
    falseStandard.suite.nist_standards = ["FIPS 999"]
    verify(!PluginModel.validStatusRecord(falseStandard))

    var reorderedStandards = completeStatus()
    reorderedStandards.suite.nist_standards = ["FIPS 204", "FIPS 203"]
    verify(!PluginModel.validStatusRecord(reorderedStandards))

    var wrongCategory = completeStatus()
    wrongCategory.suite.pq_security_category = 6
    verify(!PluginModel.validStatusRecord(wrongCategory))

    var wrongAlgorithm = completeStatus()
    wrongAlgorithm.suite.kem = "replacement-kem"
    verify(!PluginModel.validStatusRecord(wrongAlgorithm))

    var extraClaim = completeStatus()
    extraClaim.suite.unexpected_claim = true
    verify(!PluginModel.validStatusRecord(extraClaim))
    compare(PluginModel.fipsChips(extraClaim.suite).join("|"),
            "FIPS 140-3 STATUS REFUSED")

    var claimVersion = completeStatus()
    claimVersion.version = "not-a-semver"
    verify(!PluginModel.validStatusRecord(claimVersion))

    var claimTokenVersion = completeStatus()
    claimTokenVersion.version = "2.1.0-"
      + ["FIPS", "140-3", "VALIDATED"].join("-")
    verify(!PluginModel.validStatusRecord(claimTokenVersion))

    var extraRootClaim = completeStatus()
    extraRootClaim.unexpected_claim = true
    verify(!PluginModel.validStatusRecord(extraRootClaim))
  }

  function test_statusParserRejectsDuplicateDecodedMemberNames() {
    var raw = JSON.stringify(completeStatus())
    var claimName = ["fips", "140", "3", "validated"].join("_")
    var expected = "\"" + claimName + "\":" + String(false)
    var ambiguous = "\"" + claimName + "\":" + String(true)
      + "," + expected
    verify(PluginModel.parseLine(raw.replace(expected, ambiguous)) === null)

    var top = "\"kind\":\"status\""
    var escapedDuplicate = "\"k\\u0069nd\":\"other\"," + top
    verify(PluginModel.parseLine(raw.replace(top, escapedDuplicate)) === null)
    verify(PluginModel.validStatusRecord(PluginModel.parseLine(raw)))
  }

  function test_statusTransportRequiresCompletelyEmptyStderr() {
    var status = completeStatus()
    verify(PluginModel.statusResponseAccepted(status, 0, "", true, 1))
    verify(!PluginModel.statusResponseAccepted(status, 0, "\n", true, 1))
    verify(!PluginModel.statusResponseAccepted(status, 0, " ", true, 1))
  }

  function test_currentStatusRendersExplicitNonValidation() {
    var status = completeStatus()
    compare(PluginModel.fipsChips(status.suite).join("|"),
            "NIST FIPS 203|NIST FIPS 204|PQ CATEGORY 5|NOT FIPS 140-3 VALIDATED")
  }

  function test_unexpectedPositiveStatusIsRefused() {
    var status = completeStatus()
    status.suite.fips_140_3_validated = true
    status.suite.fips_140_3_certificate = "unverified"
    compare(PluginModel.fipsChips(status.suite).join("|"),
            "FIPS 140-3 STATUS REFUSED")
  }

  function test_legacyStatusIsReadyWithUnstatedAssurance() {
    var status = completeStatus()
    delete status.status_schema
    delete status.suite.nist_standards
    delete status.suite.pq_security_category
    delete status.suite.algorithm_profile
    delete status.suite.approved_only_mode
    delete status.suite.fips_140_3_validated
    delete status.suite.fips_140_3_certificate

    verify(PluginModel.validStatusRecord(status))
    compare(PluginModel.panelState(false, status, ""), "ready")
    compare(PluginModel.fipsChips(status.suite).join("|"),
            "FIPS 140-3 STATUS NOT STATED")

    status.suite.approved_only_mode = false
    verify(!PluginModel.validStatusRecord(status))
  }
}

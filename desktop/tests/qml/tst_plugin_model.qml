import QtQuick
import QtTest
import "../../../plugin/khephri.anubis/Model.js" as PluginModel

TestCase {
  name: "PluginModelProtocol"

  function completeStatus() {
    return {
      kind: "status",
      status_schema: "anubis-status/assurance-v1",
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

import QtQuick
import QtTest
import "../../../plugin/khephri.anubis/Model.js" as PluginModel

TestCase {
  name: "PluginModelProtocol"

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

  function test_partialStatusCannotBecomeReady() {
    verify(!PluginModel.validStatusRecord({ kind: "status" }))

    var status = completeStatus()
    verify(PluginModel.validStatusRecord(status))
    compare(PluginModel.panelState(false, status, ""), "ready")

    delete status.suite.kdf
    verify(!PluginModel.validStatusRecord(status))
  }
}

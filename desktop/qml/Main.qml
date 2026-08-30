import QtQuick
import QtQuick.Controls
import Anubis
import "Model.js" as Model

// The window. Everything of substance is in Vault; this file decides how big
// it opens, what it is called, and what happens when someone closes it.
ApplicationWindow {
  id: window

  // Sized to the cockpit's three rails at a comfortable reading width, then
  // whatever the operator last left it at. The minimum is the point below
  // which the rails stop being three columns and start being a queue.
  //
  // Applied once, at startup, and never bound to the settings. A binding here
  // means every later settings change re-asserts a size the operator has since
  // moved on from -- including while the window is maximised or fullscreen,
  // where the result is a surface that shrinks away from its own frame.
  width: 1560
  height: 980
  minimumWidth: 1100
  minimumHeight: 720

  function restoreGeometry() {
    var saved = App.settings.window
    if (!saved) return
    var w = Number(saved.width)
    var h = Number(saved.height)
    if (isFinite(w) && w >= window.minimumWidth) window.width = w
    if (isFinite(h) && h >= window.minimumHeight) window.height = h
    if (saved.maximized === true) window.showMaximized()
  }

  visible: true
  color: Color.background

  // The window is named after what is loaded, because a taskbar entry that
  // says only "ANUBIS Vault" is useless the moment there are two of them.
  title: vault.targetPath === ""
    ? "ANUBIS Vault"
    : Model.basename(vault.targetPath) + " — ANUBIS Vault"

  Vault {
    id: vault
    anchors.fill: parent
  }

  Component.onCompleted: {
    restoreGeometry()
    vault.openPath(App.pendingOpenPath)
    App.clearPendingOpenPath()
  }

  // A second launch of this program forwards its argument to this instance
  // rather than opening a window of its own, so this is what brings the
  // existing window forward.
  Connections {
    target: App
    function onRaiseRequested() {
      if (window.visibility === Window.Minimized) window.showNormal()
      window.raise()
      window.requestActivate()
    }
  }

  // Closing the window ends the program, so it goes through the same gate the
  // quit button does: a running operation is asked about, not killed.
  onClosing: function (event) {
    if (vault.engine.opBusy) {
      event.accepted = false
      vault.requestQuit()
    }
  }

  // Geometry is saved here rather than in onClosing, because onClosing only
  // fires when the window manager closes the window. Ctrl+Q and the quit
  // button call Qt.quit() directly and never reach it, and a size that is
  // remembered only when you close one particular way is a size that mostly
  // is not remembered.
  Connections {
    target: Qt.application
    function onAboutToQuit() {
      App.rememberGeometry(window.width, window.height,
                           window.visibility === Window.Maximized)
    }
  }
}

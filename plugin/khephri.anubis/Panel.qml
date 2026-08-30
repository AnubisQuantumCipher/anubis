// ANUBIS -- the bar face and its dropdown.
//
// This surface is a READOUT. It renders what `anubis status --json` said and
// performs no cryptography, holds no key material, and runs no vault
// operation of any kind. Everything that changes state -- encrypt, decrypt,
// keygen, the address book -- lives in the ANUBIS Vault desktop application,
// one click away.
//
// That split is the whole design. A dropdown is a surface any stray click
// dismisses, which makes it the wrong place for a multi-step operation and a
// worse place for a confirmation gate. So this panel answers the questions you
// would otherwise open the app for, and hands you the app for everything else.
//
// What earns a place here is narrow on purpose. The bar tooltip already gives
// engine version, identity and recipient counts, and the suite badge at zero
// clicks, so none of that is repeated below. Every section carries either a
// fact a tooltip structurally cannot hold, or an interaction a tooltip cannot
// host -- a tooltip has no MouseArea, so nothing in one can ever be copied.

import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "khephri.anubis"

  // The IPC target keeps its historic name so `qs ipc call anubis ...` and
  // every script written against it still works. Ui/Panel would register
  // open/close/show/hide/toggle for us, but only those five; the readout verbs
  // below are the reason this plugin was scriptable in the first place, so the
  // handler is ours.
  ipcTarget: "anubis"
  manageIpc: false

  // Ui/Panel is a bare Item with no implicit size, and the bar sizes the slot
  // from these. Omit them and the widget is a zero-width slot: invisible, yet
  // still found by summon -- so the hotkey "works" while nothing is on screen.
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // Ui/Panel has no `vertical` of its own -- that lives on Ui/BarWidget --
  // and an undefined read here would silently mean false on a vertical bar.
  readonly property bool vertical: bar ? bar.vertical : false

  readonly property color fg: bar ? bar.barForeground : Color.foreground
  readonly property color accent: Color.accent
  readonly property color urgent: Color.urgent
  readonly property string fontFamily: Style.font.family

  // ---- one type and spacing scale ------------------------------------------
  readonly property int typeMeta: Style.font.caption
  readonly property int typeBody: Style.font.bodySmall
  readonly property int padTight: Style.spacing.xxs
  readonly property int padLine: Style.spacing.sm
  readonly property int padGroup: Style.spacing.lg
  readonly property int padCard: Style.spacing.xxl

  // ---- the engine driver ---------------------------------------------------
  //
  // ONE instance, created by the host from the manifest's `service` kind and
  // shared by every bar surface. An inline Service here would be instantiated
  // once per monitor, because the bar builds one surface per screen -- so the
  // manifest kind is what actually guarantees a single poller.
  //
  // It is null until the component finishes loading, so this is bound rather
  // than cached and every read below is guarded.
  readonly property var anubis:
    bar && bar.shell && typeof bar.shell.serviceFor === "function"
      ? bar.shell.serviceFor("khephri.anubis") : null

  readonly property var status: anubis ? anubis.status : null
  readonly property string statusError: anubis ? anubis.statusError : ""
  readonly property bool engineMissing: anubis ? anubis.engineMissing : false
  readonly property var identityList: anubis ? anubis.identities : []
  readonly property var recent: anubis ? anubis.recentOps : []
  readonly property double nowMs: anubis ? anubis.nowMs : 0
  readonly property string version: anubis ? anubis.version : ""

  readonly property string vaultState:
    Model.panelState(engineMissing, status, statusError)
  readonly property int identityCount: identityList.length

  // The identity the engine would actually use. The dropdown shows this one
  // and no other: the app owns the list.
  readonly property var effectiveId:
    Model.identityByName(status,
      Model.effectiveIdentity(status,
        anubis ? anubis.opts.defaultIdentity : "", ""))

  function stateColor() {
    if (vaultState === "absent") return Qt.alpha(fg, 0.35)
    if (vaultState === "failed" || vaultState === "error") return urgent
    if (vaultState === "unknown") return Qt.alpha(fg, 0.6)
    return accent
  }

  function toneColor(tone) {
    if (tone === "good") return root.accent
    if (tone === "bad") return root.urgent
    if (tone === "notice") return Qt.alpha(root.fg, 0.85)
    if (tone === "unknown") return Qt.alpha(root.fg, 0.5)
    return root.fg
  }

  function copy(text, description) {
    if (anubis) anubis.copyText(text, description)
  }

  // ==========================================================================
  // the route into the app
  // ==========================================================================
  //
  // execDetached takes an argv list and does not go through a shell, so a path
  // containing spaces needs no quoting -- each element is one argument. The
  // app is single-instance: a second launch hands its argument to the running
  // window and exits, so this is both "open" and "raise" with one call.
  function openApp(path) {
    var p = String(path || "")
    var argv = ["uwsm-app", "--", "anubis-desktop"]
    if (p !== "") argv.push(p)
    Quickshell.execDetached(argv)
    root.close()
  }

  // Re-read on open so the panel is never showing a poll that went stale while
  // it was closed, and rewind the scroll so it always opens at the top.
  onOpenedChanged: if (opened) {
    if (anubis) anubis.refresh()
    panelFlick.contentY = 0
    Qt.callLater(function () { keyCatcher.forceActiveFocus() })
  }

  IpcHandler {
    target: root.ipcTarget

    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function poll(): string {
      if (root.anubis) root.anubis.refresh()
      return "polling"
    }
    function vaultState(): string { return root.vaultState }

    // The cockpit moved out, so this opens the application on that container
    // rather than drawing an inspector the dropdown no longer has.
    function inspect(path: string): string {
      root.openApp(String(path || ""))
      return "opening"
    }
  }

  // ==========================================================================
  // text vocabulary
  // ==========================================================================

  component Mono: Text {
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    font.family: root.fontFamily
    font.pixelSize: root.typeBody
    color: Qt.alpha(root.fg, 0.72)
  }

  component Meta: Mono {
    font.pixelSize: root.typeMeta
    color: Qt.alpha(root.fg, 0.42)
  }

  component Legend: Mono {
    font.pixelSize: root.typeMeta
    font.bold: true
    font.letterSpacing: 1.1
    color: Qt.alpha(root.fg, 0.5)
  }

  // A fingerprint rendered as the handle it is: five groups of four, short
  // enough to read aloud, which is the whole point of it.
  //
  // The KIND is always shown. There are two fingerprint namespaces -- one over
  // the KEM recipient payload, one over the ML-DSA-87 verifying key -- and
  // they are not interchangeable. A bare fingerprint invites someone to
  // compare a recipient against a signer and conclude something false.
  //
  // The fingerprint gets its own line. Twenty-four characters plus a label
  // plus an action does not fit a dropdown at every font size the theme
  // allows, and the failure mode of trying is an ELIDED fingerprint -- worse
  // than none, because it silently invites exactly the mistaken-identity error
  // the fingerprint exists to prevent.
  component FingerprintRow: Item {
    id: fpRow
    property string kind: "recipient"
    property string fingerprint: ""
    property string fullKey: ""
    readonly property bool known: fpRow.fingerprint !== ""
    implicitHeight: fpHead.height + fpPlate.implicitHeight + root.padTight

    Item {
      id: fpHead
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      height: fpKind.implicitHeight

      Mono {
        id: fpGlyph
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
        text: Model.GLYPH.fingerprint
        font.pixelSize: root.typeMeta
        color: Qt.alpha(root.fg, 0.38)
      }
      Legend {
        id: fpKind
        anchors.left: fpGlyph.right
        anchors.leftMargin: root.padLine + root.padTight
        anchors.right: keyArea.left
        anchors.rightMargin: root.padGroup
        anchors.verticalCenter: parent.verticalCenter
        elide: Text.ElideRight
        text: fpRow.kind
      }

      MouseArea {
        id: keyArea
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: copyKey.visible ? copyKey.implicitWidth : 0
        hoverEnabled: true
        enabled: copyKey.visible
        cursorShape: Qt.PointingHandCursor
        onClicked: root.copy(fpRow.fullKey, "full " + fpRow.kind + " key")
        Meta {
          id: copyKey
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          visible: fpRow.fullKey !== ""
          text: Model.GLYPH.copy + " key"
          color: keyArea.containsMouse ? root.accent : Qt.alpha(root.fg, 0.38)
          Behavior on color { ColorAnimation { duration: 60 } }
        }
      }
    }

    // The digits are ONE Text, not a row of per-group items: a Row overflows
    // the rail and a Flow will not fill an anchor-derived width, and both
    // failure modes end in a fingerprint the reader cannot fully see.
    //
    // Where the string does not fit one line, fpMetrics measures it and asks
    // Model for a break on the group-three boundary -- 14 characters over 9,
    // both lines starting on a digit -- rather than letting the wrap fall
    // mid-group. WrapAnywhere stays on underneath as the guarantee that
    // nothing is ever lost, whatever a theme does.
    TextMetrics {
      id: fpMetrics
      font: fpDigits.font
      text: fpRow.fingerprint
    }
    Rectangle {
      id: fpPlate
      anchors.left: parent.left
      anchors.leftMargin: fpGlyph.implicitWidth + root.padLine + root.padTight
      anchors.right: parent.right
      anchors.top: fpHead.bottom
      anchors.topMargin: root.padTight
      implicitHeight: fpDigits.implicitHeight + (root.padLine * 2)
      radius: Style.cornerRadius
      color: fpArea.containsMouse ? Qt.alpha(root.accent, 0.10)
        : Qt.alpha(root.fg, fpRow.known ? 0.05 : 0.02)
      border.color: fpArea.containsMouse ? Qt.alpha(root.accent, 0.45)
        : Qt.alpha(root.fg, fpRow.known ? 0.10 : 0.06)
      border.width: 1

      Behavior on color { ColorAnimation { duration: 60 } }
      Behavior on border.color { ColorAnimation { duration: 60 } }

      Mono {
        id: fpDigits
        anchors.left: parent.left
        anchors.leftMargin: root.padGroup - root.padTight
        anchors.right: parent.right
        anchors.rightMargin: root.padGroup - root.padTight
        anchors.verticalCenter: parent.verticalCenter
        textFormat: fpRow.known ? Text.StyledText : Text.PlainText
        wrapMode: Text.WrapAnywhere
        // The engine did not state one. Said plainly, in the dim weight that
        // means absent, never dressed up as a value.
        text: fpRow.known
          ? Model.fingerprintMarkup(fpRow.fingerprint,
                                    Qt.alpha(root.fg, 0.3).toString(),
                                    fpMetrics.width > fpDigits.width ? 3 : 0)
          : "not reported"
        font.bold: fpRow.known
        font.pixelSize: fpRow.known ? root.typeBody : root.typeMeta
        font.letterSpacing: fpRow.known ? 0.5 : 0
        color: fpRow.known
          ? (fpArea.containsMouse ? root.accent : Qt.alpha(root.fg, 0.92))
          : Qt.alpha(root.fg, 0.42)
        Behavior on color { ColorAnimation { duration: 60 } }
      }

      Meta {
        anchors.right: parent.right
        anchors.rightMargin: root.padLine
        anchors.bottom: parent.bottom
        anchors.bottomMargin: root.padTight
        visible: opacity > 0
        opacity: fpArea.containsMouse && fpRow.known ? 1.0 : 0.0
        text: Model.GLYPH.copy
        color: root.accent
        Behavior on opacity { NumberAnimation { duration: 60 } }
      }
    }

    MouseArea {
      id: fpArea
      anchors.fill: fpPlate
      hoverEnabled: true
      enabled: fpRow.known
      cursorShape: Qt.PointingHandCursor
      onClicked: root.copy(fpRow.fingerprint, fpRow.kind + " fingerprint")
    }
  }

  // ==========================================================================
  // the bar face
  // ==========================================================================

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: Model.panelGlyph(root.vaultState)
      + (root.vaultState === "absent" || root.identityCount === 0
         ? "" : " " + root.identityCount)
    slotSize: Style.bar.statusSlot
    // The stock slot is one glyph wide; grow with the painted count so the
    // neighbouring widget cannot paint over the number.
    fixedWidth: vertical ? -1
      : Math.max(slotSize, glyphPaintedWidth + Style.spaceReal(8))
    fontSize: Style.font.caption
    foreground: root.vaultState === "absent" ? Qt.alpha(root.fg, 0.4) : root.fg
    tooltipText: Model.panelTooltip(root.vaultState, root.status,
                                    root.engineMissing)

    onPressed: function (buttonCode) {
      if (buttonCode === Qt.RightButton) {
        if (root.anubis) root.anubis.probeEngine()
        return
      }
      root.toggle()
    }

    // State dot. Kept off the glyph baseline so it reads as an indicator
    // rather than part of the icon.
    //
    // It does not pulse. It used to claim to pulse "only while the engine is
    // actually moving bytes", but no bar surface has ever launched an
    // operation, so the flag it watched was permanently false and the
    // animation was unreachable. Now that every operation belongs to the
    // desktop app, it can never become true -- so the claim is gone rather
    // than carried forward.
    Rectangle {
      width: Style.spaceReal(5)
      height: width
      radius: width / 2
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.rightMargin: Style.spaceReal(2)
      anchors.topMargin: Style.spaceReal(3)
      color: root.stateColor()
      visible: !root.vertical
    }
  }

  // ==========================================================================
  // the dropdown
  // ==========================================================================

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher

    // Width is a constant cap and only the height tracks content: binding the
    // width to the content's implicit width while the content's width binds
    // back to the panel is a loop.
    contentWidth: panel.fittedContentWidth(Style.space(252))
    // The footer is pinned outside the Flickable, so its height is NOT part of
    // column.implicitHeight. Leave it out of this sum and the card is sized for
    // the scrolling content alone -- the footer then eats into the Flickable
    // from below and clips the top of the hero, which is exactly what happens
    // when the engine is missing and the scrolling half is nearly empty.
    contentHeight: panel.fittedContentHeight(
      column.implicitHeight + footer.implicitHeight + root.padGroup,
      Style.space(520))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function (direction) { root.switchPanel(direction) }
      onActivateRequested: root.openApp("")
      onTextKey: function (t) {
        if (t === "r" || t === "R") { if (root.anubis) root.anubis.refresh() }
        else if (t === "o" || t === "O") root.openApp("")
      }

      Flickable {
        id: panelFlick
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.bottom: footer.top
        anchors.bottomMargin: root.padGroup
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: panelFlick.width
          spacing: root.padCard

          // ---------------------------------------------------------- hero
          //
          // The version is in the tooltip already; the AGE is not, and nothing
          // else on this surface distinguishes "polled eight seconds ago" from
          // "the poll wedged an hour ago". Every other number here is only as
          // true as that timestamp, so it is the line that licenses the rest.
          PanelHero {
            width: column.width
            foreground: root.fg
            fontFamily: root.fontFamily
            title: "ANUBIS"
            meta: root.version !== "" ? "v" + root.version
              : (root.engineMissing ? "engine absent" : "version unknown")
            detail: root.anubis && root.anubis.statusAtMs > 0
              ? Model.timeAgo(new Date(root.anubis.statusAtMs).toISOString(),
                              root.nowMs)
              : ""
          }

          // ------------------------------------------------ engine absent
          //
          // An ordinary state, not an error: the engine is installed
          // separately, so a fresh machine simply has no engine yet.
          Item {
            width: column.width
            visible: root.engineMissing
            implicitHeight: hintPlate.implicitHeight

            Rectangle {
              id: hintPlate
              width: parent.width
              implicitHeight: hintText.implicitHeight + (root.padGroup * 2)
              radius: Style.cornerRadius
              color: hintArea.containsMouse ? Qt.alpha(root.accent, 0.10)
                                            : Qt.alpha(root.fg, 0.05)
              border.color: hintArea.containsMouse
                ? Qt.alpha(root.accent, 0.45) : Qt.alpha(root.fg, 0.12)
              border.width: 1
              Behavior on color { ColorAnimation { duration: 60 } }

              Mono {
                id: hintText
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.margins: root.padGroup
                anchors.verticalCenter: parent.verticalCenter
                wrapMode: Text.WrapAnywhere
                text: Model.installHint()
                font.pixelSize: root.typeMeta
                color: hintArea.containsMouse ? root.accent
                                              : Qt.alpha(root.fg, 0.75)
              }
              MouseArea {
                id: hintArea
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.copy(Model.installHint(), "install command")
              }
            }
          }

          // ------------------------------------------------- status error
          //
          // Not a feature -- an honesty requirement. Without it an empty
          // readout is indistinguishable from an empty vault, and a failed
          // poll clears the status rather than leaving the last good one on
          // screen.
          Mono {
            width: column.width
            visible: root.statusError !== ""
            wrapMode: Text.WordWrap
            text: Model.GLYPH.alert + "  " + root.statusError
            color: root.urgent
            font.pixelSize: root.typeMeta
          }

          // ----------------------------------------------------- identity
          PanelSeparator {
            width: column.width
            foreground: root.fg
            visible: !root.engineMissing
          }
          PanelSectionHeader {
            width: column.width
            foreground: root.fg
            fontFamily: root.fontFamily
            visible: !root.engineMissing
            text: "IDENTITY"
          }

          Mono {
            width: column.width
            visible: !root.engineMissing && root.identityCount === 0
            wrapMode: Text.WordWrap
            text: "No identity yet. Open ANUBIS to generate one."
            font.pixelSize: root.typeMeta
            color: Qt.alpha(root.fg, 0.55)
          }

          Column {
            width: column.width
            spacing: root.padGroup
            visible: !root.engineMissing && root.effectiveId !== null
              && root.effectiveId !== undefined

            Mono {
              width: parent.width
              elide: Text.ElideRight
              text: Model.GLYPH.key + "  "
                + (root.effectiveId ? String(root.effectiveId.name) : "")
              color: root.fg
              font.bold: true
            }
            // Both namespaces or neither. Showing one unlabelled is what
            // invites comparing a recipient against a signer.
            FingerprintRow {
              width: parent.width
              kind: "recipient"
              fingerprint: root.effectiveId
                ? Model.formatFingerprint(root.effectiveId.fingerprint) : ""
              fullKey: root.effectiveId
                ? String(root.effectiveId.recipient || "") : ""
            }
            FingerprintRow {
              width: parent.width
              kind: "signer"
              visible: fingerprint !== ""
              fingerprint: Model.signingFingerprint(root.effectiveId)
              fullKey: ""
            }
          }

          // ------------------------------------------------------- recent
          //
          // The tooltip names a failure only when the NEWEST operation
          // failed; it is structurally a state, not a history. These rows are
          // the history, and each one is a route into the app.
          PanelSeparator {
            width: column.width
            foreground: root.fg
            visible: recentRepeater.count > 0
          }
          PanelSectionHeader {
            width: column.width
            foreground: root.fg
            fontFamily: root.fontFamily
            visible: recentRepeater.count > 0
            text: "RECENT"
          }

          Column {
            width: column.width
            spacing: root.padLine

            Repeater {
              id: recentRepeater
              model: root.recent.slice(0, 5)

              delegate: CursorSurface {
                id: opRow
                required property var modelData
                readonly property bool ok: modelData.ok === true
                readonly property string errText: String(modelData.error || "")
                readonly property string errTone: Model.noticeTone(errText)

                width: column.width
                implicitHeight: opCol.implicitHeight + (root.padGroup * 2)
                foreground: root.fg
                accent: root.accent
                hasCursor: opArea.containsMouse

                Column {
                  id: opCol
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.top: parent.top
                  anchors.margins: root.padGroup
                  spacing: root.padTight

                  Item {
                    width: parent.width
                    height: opName.implicitHeight
                    Mono {
                      id: opGlyph
                      anchors.left: parent.left
                      anchors.verticalCenter: parent.verticalCenter
                      text: Model.opGlyph(String(opRow.modelData.op))
                      font.pixelSize: root.typeMeta
                      color: opRow.ok ? root.accent
                                      : root.toneColor(opRow.errTone)
                    }
                    Mono {
                      id: opName
                      anchors.left: opGlyph.right
                      anchors.leftMargin: root.padGroup
                      anchors.right: opVerdict.left
                      anchors.rightMargin: root.padGroup
                      anchors.verticalCenter: parent.verticalCenter
                      elide: Text.ElideMiddle
                      text: Model.basename(String(opRow.modelData.path || ""))
                      color: root.fg
                    }
                    Meta {
                      id: opVerdict
                      anchors.right: parent.right
                      anchors.baseline: opName.baseline
                      // An old container is not a tampered container, so an
                      // unsupported wire format reads as an upgrade path and
                      // never borrows the urgent colour.
                      text: opRow.ok ? "ok"
                        : (opRow.errTone === "notice" ? "unsupported" : "FAILED")
                      color: opRow.ok ? Qt.alpha(root.accent, 0.8)
                                      : root.toneColor(opRow.errTone)
                      font.bold: !opRow.ok && opRow.errTone !== "notice"
                    }
                  }

                  // One wrapping line, not two elided halves. Splitting this
                  // into a left summary and a right timestamp is what cut the
                  // throughput to "524..." -- and a rate the reader cannot
                  // finish reading is worse than no rate at all. At a
                  // dropdown's width there is no arrangement where both facts
                  // fit on one line at every theme, so neither gets a column
                  // and the pair simply wraps.
                  Meta {
                    width: parent.width
                    visible: text !== ""
                    wrapMode: Text.WordWrap
                    text: {
                      var sum = Model.opSummary(opRow.modelData)
                      var age = Model.timeAgo(opRow.modelData.ts, root.nowMs)
                      if (sum === "") return age
                      if (age === "") return sum
                      return sum + "  |  " + age
                    }
                  }

                  // Wraps rather than elides. A refusal cut to "no matching..."
                  // is a reason the reader cannot use; a second line is.
                  Mono {
                    width: parent.width
                    wrapMode: Text.WordWrap
                    visible: !opRow.ok && opRow.errText !== ""
                    text: Model.noticeGlyph(opRow.errText) + " " + opRow.errText
                    font.pixelSize: root.typeMeta
                    color: opRow.errTone === "notice"
                      ? Qt.alpha(root.fg, 0.6) : Qt.alpha(root.urgent, 0.9)
                  }
                }

                MouseArea {
                  id: opArea
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    var target = String(opRow.modelData.out || "")
                    if (target === "" || !Model.isVaultFile(target))
                      target = String(opRow.modelData.path || "")
                    root.openApp(target)
                  }
                }
              }
            }
          }

        }
      }

      // Pinned to the card, OUTSIDE the Flickable.
      //
      // The action first: it is the whole contract of this surface -- every
      // state-changing operation lives behind it -- so it must never be a
      // scroll away. Then the boundary line, which is the line that must never
      // be scrolled away at all. The dropdown makes it more load-bearing
      // rather than less: this is the surface people glance at daily, it shows
      // key fingerprints and FAILED verdicts, and a reader concluding the
      // shell verified something is precisely the error the line prevents.
      Column {
        id: footer
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        spacing: root.padGroup

        PanelSeparator {
          width: parent.width
          foreground: root.fg
        }

        CursorSurface {
          width: parent.width
          implicitHeight: openLabel.implicitHeight + (root.padGroup * 2)
          foreground: root.fg
          accent: root.accent
          hasCursor: openArea.containsMouse

          Mono {
            id: openLabel
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.margins: root.padGroup
            anchors.verticalCenter: parent.verticalCenter
            text: Model.GLYPH.shieldKey + "  Open ANUBIS Vault"
            color: openArea.containsMouse ? root.accent : root.fg
            font.bold: true
            Behavior on color { ColorAnimation { duration: 60 } }
          }
          MouseArea {
            id: openArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.openApp("")
          }
        }

        Meta {
          width: parent.width
          wrapMode: Text.WordWrap
          text: Model.boundaryLine()
          color: Qt.alpha(root.fg, 0.4)
        }
      }
    }
  }
}

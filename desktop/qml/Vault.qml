// ANUBIS VAULT -- mission control for post-quantum file encryption.
//
// The application's one surface. Everything painted here is the `anubis`
// engine's own JSON. This surface holds no key material, computes no
// ciphertext, and decides no verification outcome; when the engine declines to
// state something, the panel says so rather than filling in a pass.
//
// Layout is a three-rail cockpit:
//
//   LEFT    the vault itself -- identities and the recipient address book,
//           both keyed by FINGERPRINT, because an ANUBIS recipient is roughly
//           2573 bech32 characters and no human compares that.
//   CENTRE  the console -- what is about to happen and what is happening,
//           then the inspector for whatever container is selected.
//   RIGHT   the record -- counts, an activity strip, and the audit timeline.
//
// One colour rule runs through the whole surface. The urgent colour means
// AUTHENTICATION FAILED: a header MAC that did not verify, a signature that
// did not check out, an operation that died. It is never spent on anything
// else. A container from an older, unsupported wire format is not tampering,
// so it is drawn as a plain notice with an upgrade path.
//
// The assurance line is pinned outside every scroll area, because it is the
// line that must never be scrolled away.

import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import Anubis
import "Model.js" as Model

Item {
  id: root

  // False only for the arrival fade on the first frame. Nothing hides this
  // surface afterwards: it is the application, not an overlay over one.
  property bool opened: false

  // Sheets. At most one is up at a time, and neither blocks the engine --
  // an operation launched before a sheet opened keeps streaming behind it.
  property bool showPreferences: false
  property bool showAbout: false
  readonly property bool sheetOpen: showPreferences || showAbout

  // The application's settings file, watched and re-read by the App
  // singleton, so an edit on disk lands here without a restart.
  readonly property var prefs: App.settings

  readonly property string home: App.env("HOME") || ""
  readonly property string fontFamily: Style.font.family
  readonly property color fg: Color.foreground
  readonly property color accent: Color.accent
  readonly property color urgent: Color.urgent

  // ---- one spacing scale ---------------------------------------------------
  //
  // Every gap on this surface is one of five roles, and each role is a theme
  // spacing token rather than a number picked by eye. Nothing below calls
  // Style.space() with an ad-hoc argument, so a user who scales spacing in
  // their theme scales this whole cockpit coherently instead of unevenly.
  readonly property int padTight: Style.spacing.xxs    //  2  baseline nudge
  readonly property int padLine: Style.spacing.sm      //  4  lines of one thought
  readonly property int padGroup: Style.spacing.lg     //  8  groups inside a card
  readonly property int padCard: Style.spacing.xxl     // 12  card interior, card to card
  readonly property int padRail: Style.spacing.huge    // 18  rail gutter, body margin

  // ---- one type scale ------------------------------------------------------
  //
  // Four steps, each with one job. Before this the whole surface sat inside a
  // 10-11px band, which is why nothing read as a heading: hierarchy needs a
  // scale, not just a bolder weight.
  readonly property int typeMeta: Style.font.caption      // 10  provenance, units
  readonly property int typeBody: Style.font.bodySmall    // 11  values, body copy
  readonly property int typeLead: Style.font.body         // 12  card titles, names
  readonly property int typeBrand: Style.font.title       // 14  the brand only

  // ---- motion --------------------------------------------------------------
  //
  // The same `motionEnabled` switch the sibling plugins expose. Every
  // transition here is a fade or a colour ramp under 180ms and none of them
  // gate input: with motion off the surface simply snaps.
  readonly property bool motion: opts.motionEnabled
  readonly property int motionFast: motion ? 110 : 0
  readonly property int motionBase: motion ? 160 : 0

  // ---- console state -------------------------------------------------------
  property string targetPath: ""
  property var selection: []          // recipient keys chosen for encryption
  property bool signRequested: false
  property string chosenIdentity: ""
  property string newIdentityName: ""
  property string newRecipientLabel: ""
  property string newRecipientKey: ""
  property string focusRequest: ""    // which action the last shortcut wanted
  property double nowMs: Date.now()

  readonly property var opts: Model.resolveSettings(prefs)
  readonly property string effectiveIdentity:
    Model.effectiveIdentity(anubis.status, opts.defaultIdentity, chosenIdentity)
  readonly property var selectedKeys:
    Model.selectedKeys(anubis.status, selection)
  readonly property bool targetIsVault: Model.isVaultFile(targetPath)

  readonly property string vaultState:
    Model.panelState(anubis.engineMissing, anubis.status, anubis.statusError)

  // The engine driver, exposed so the bar widget, the IPC surface, and any
  // harness can read the same state the cockpit renders instead of starting
  // a second poller against the same binary.
  readonly property alias engine: anubis

  // ==========================================================================
  // lifecycle
  // ==========================================================================

  // Load a container into the console. Called at startup, and again whenever a
  // second launch of this program hands its path to the instance already
  // running -- a file manager's "Open with" must never end up with two vaults
  // polling the same engine.
  function openPath(path) {
    opened = true
    showPreferences = false
    showAbout = false
    anubis.actionError = ""
    anubis.opError = ""
    anubis.cancelPending()

    var target = App.pathFromUrl(String(path || ""))
    if (target !== "") selectPath(target)
    if (anubis.enginePath === "") anubis.probeEngine()
    else anubis.refresh()

    Qt.callLater(function () {
      keyCatcher.forceActiveFocus()
      activityStrip.requestPaint()
    })
  }

  // Quitting. There is no host to route this back through and nothing to
  // hide behind: closing the window ends the program. A running operation is
  // the one thing that makes this a question rather than a reflex, so it is
  // asked about rather than assumed.
  function requestQuit() {
    if (anubis.opBusy) {
      quitConfirm.open()
      return
    }
    Qt.quit()
  }

  // Esc. It cancels whatever is pending, in the order a person would expect,
  // and it never quits: an application that exits on Esc loses work.
  function escapeAction() {
    if (quitConfirm.asking) {
      quitConfirm.asking = false
    } else if (showPreferences || showAbout) {
      showPreferences = false
      showAbout = false
    } else if (anubis.pendingOverwrite) {
      anubis.cancelPending()
    } else if (anubis.opBusy) {
      anubis.abortOperation()
    } else {
      keyCatcher.forceActiveFocus()
    }
  }

  function browseForTarget() {
    targetDialog.currentFolder =
      App.urlFromPath(App.parentDirectory(targetPath !== "" ? targetPath : home))
    targetDialog.open()
  }

  // ==========================================================================
  // console actions
  // ==========================================================================

  function selectPath(raw) {
    var p = Model.normalizePath(raw, home)
    pathField.text = p
    targetPath = p
  }

  onTargetPathChanged: {
    if (targetPath !== "" && Model.isVaultFile(targetPath))
      anubis.runInspect(targetPath)
    else anubis.clearInspect()
  }

  function toggleRecipient(key) {
    selection = Model.toggleMember(selection, String(key))
  }

  function runEncrypt() {
    focusRequest = "encrypt"
    anubis.submit(anubis.buildRequest("encrypt", targetPath, selectedKeys,
                                      signRequested, effectiveIdentity, ""))
  }

  function runDecrypt() {
    focusRequest = "decrypt"
    anubis.submit(anubis.buildRequest("decrypt", targetPath, [], false,
                                      effectiveIdentity, ""))
  }

  // Tone names come from Model; the palette lives here. "notice" is
  // deliberately a readable neutral -- not accent, which would read as
  // verified, and not urgent, which would read as tampering.
  function toneColor(tone) {
    if (tone === "good") return root.accent
    if (tone === "bad") return root.urgent
    if (tone === "notice") return Qt.alpha(root.fg, 0.85)
    if (tone === "unknown") return Qt.alpha(root.fg, 0.5)
    return root.fg
  }

  // ==========================================================================
  // wiring
  // ==========================================================================

  Service {
    id: anubis
    settings: root.prefs

    onOperationFinished: function (kind, ok) {
      activityStrip.requestPaint()
      if (ok && kind === "encrypt") root.selectPath(anubis.opOutput)
    }
    onIdentityCreated: function (name) {
      root.newIdentityName = ""
      root.chosenIdentity = name
    }
    onStatusChanged: activityStrip.requestPaint()
  }

  Timer {
    id: pathSettle
    interval: 350
    repeat: false
    onTriggered: root.targetPath = Model.normalizePath(pathField.text, root.home)
  }

  Timer {
    interval: 1000
    running: root.opened
    repeat: true
    onTriggered: root.nowMs = Date.now()
  }

  // A second launch of this program forwards its argument here rather than
  // opening a window of its own.
  Connections {
    target: App
    function onOpenPathRequested(path) { root.openPath(path) }
  }

  FileDialog {
    id: targetDialog
    title: "Choose a file"
    fileMode: FileDialog.OpenFile
    nameFilters: ["ANUBIS containers (*.anubis)", "All files (*)"]
    onAccepted: root.selectPath(App.pathFromUrl(String(selectedFile)))
  }

  // ==========================================================================
  // inline building blocks
  // ==========================================================================

  // Body copy. One step up from the old caption default, because a surface
  // where every string is the same size has no headings, only bold ones.
  component Mono: Text {
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    font.family: root.fontFamily
    font.pixelSize: root.typeBody
    color: Qt.alpha(root.fg, 0.72)
  }

  // Metadata: timestamps, paths, units, provenance. Anything the eye should
  // be able to skip on the way to the value it came for.
  component Meta: Mono {
    font.pixelSize: root.typeMeta
    color: Qt.alpha(root.fg, 0.42)
  }

  // The one treatment for every sub-heading inside a card -- GENERATE
  // IDENTITY, RECIPIENTS, STANZAS, ACTIVITY. They used to be four
  // independently invented styles that happened to look similar; now they are
  // one, a clear step below a card title.
  component Legend: Mono {
    font.pixelSize: root.typeMeta
    font.bold: true
    font.letterSpacing: 1.1
    color: Qt.alpha(root.fg, 0.44)
  }

  component SectionCard: Rectangle {
    id: card
    property string title: ""
    property string note: ""
    // The centre console sets this. An emphasised card carries an accent
    // hairline along its top edge and a fractionally brighter field, which is
    // how the primary workspace says so without growing or shouting.
    property bool emphasis: false
    // The rails set this. The record and the vault are reference material, not
    // the workspace, so they sit on a fainter field with a fainter edge and a
    // quieter title. Three cards of identical weight either side of the
    // console is what made the rails compete with it.
    property bool recessed: false
    property color tint: Qt.alpha(root.fg, card.recessed ? 0.02 : 0.035)
    property color edge: Qt.alpha(root.fg, card.recessed ? 0.06 : 0.09)
    // A floor for the whole card, so one that is deliberately waiting for
    // input reads as a well rather than as a collapsed strip.
    property int minHeight: 0
    default property alias content: cardBody.data

    radius: Style.cornerRadius
    color: card.tint
    border.color: card.emphasis ? Qt.alpha(root.accent, 0.22) : card.edge
    border.width: 1
    implicitHeight: Math.max(card.minHeight,
                             cardOuter.implicitHeight + (root.padCard * 2))

    Behavior on color {
      enabled: root.motion
      ColorAnimation { duration: root.motionBase; easing.type: Easing.OutQuart }
    }
    Behavior on border.color {
      enabled: root.motion
      ColorAnimation { duration: root.motionBase; easing.type: Easing.OutQuart }
    }

    Rectangle {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.margins: 1
      height: 2
      visible: card.emphasis
      color: Qt.alpha(root.accent, 0.55)
    }

    Column {
      id: cardOuter
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.margins: root.padCard
      spacing: root.padGroup

      // Header band. The rule under the title is what makes a card title read
      // as a title at a glance instead of as the first line of its contents.
      Column {
        width: cardOuter.width
        visible: card.title !== ""
        spacing: root.padLine

        // The note is a count or a filename -- a fact. The title is a fixed
        // string the reader already knows. So the note keeps its natural width
        // and the title is what gives way, rather than the other way round,
        // which is how "25 recorded" was reaching the reader as "25 ...ded".
        Item {
          width: parent.width
          height: cardTitle.implicitHeight
          Mono {
            id: cardTitle
            anchors.left: parent.left
            anchors.right: cardNote.left
            anchors.rightMargin: root.padCard
            anchors.verticalCenter: parent.verticalCenter
            elide: Text.ElideRight
            text: card.title
            font.pixelSize: root.typeLead
            font.bold: true
            font.letterSpacing: 0.6
            color: card.emphasis ? Qt.alpha(root.fg, 0.88)
              : Qt.alpha(root.fg, card.recessed ? 0.5 : 0.6)
          }
          Meta {
            id: cardNote
            anchors.right: parent.right
            anchors.baseline: cardTitle.baseline
            width: Math.min(implicitWidth, parent.width * 0.42)
            horizontalAlignment: Text.AlignRight
            elide: Text.ElideMiddle
            text: card.note
            color: Qt.alpha(root.fg, 0.38)
          }
        }
        Rectangle {
          width: parent.width
          height: 1
          color: card.emphasis ? Qt.alpha(root.accent, 0.20)
                               : Qt.alpha(root.fg, 0.08)
        }
      }

      Column {
        id: cardBody
        width: cardOuter.width
        spacing: root.padGroup
      }
    }
  }

  // What a section looks like before it holds anything.
  //
  // A brand-new vault has zero identities, zero recipients and an empty audit
  // log, and four cards each containing one dim paragraph is not a first run,
  // it is a wall of apology. So an empty section states what it is for, then
  // names the one action that fills it -- in the accent colour, because the
  // next step is the only thing on an empty surface worth looking at.
  component EmptyWell: Rectangle {
    id: well
    property string glyph: ""
    property string headline: ""
    property string body: ""
    property string nextStep: ""
    property string nextStepGlyph: Model.GLYPH.plus
    property bool actionable: true

    width: parent ? parent.width : 0
    implicitHeight: wellCol.implicitHeight + (root.padCard * 2)
    radius: Style.cornerRadius
    color: Qt.alpha(root.fg, 0.02)
    border.color: Qt.alpha(root.fg, 0.07)
    border.width: 1

    Column {
      id: wellCol
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      anchors.margins: root.padCard
      spacing: root.padLine

      Row {
        spacing: root.padGroup
        Mono {
          anchors.verticalCenter: parent.verticalCenter
          visible: well.glyph !== ""
          text: well.glyph
          font.pixelSize: root.typeBrand
          color: Qt.alpha(root.fg, 0.28)
        }
        Mono {
          anchors.verticalCenter: parent.verticalCenter
          text: well.headline
          font.bold: true
          color: Qt.alpha(root.fg, 0.6)
        }
      }
      Meta {
        width: wellCol.width
        wrapMode: Text.WordWrap
        visible: well.body !== ""
        text: well.body
        color: Qt.alpha(root.fg, 0.45)
      }
      Item { width: 1; height: root.padTight; visible: well.nextStep !== "" }
      Mono {
        width: wellCol.width
        wrapMode: Text.WordWrap
        visible: well.nextStep !== ""
        text: well.nextStepGlyph + "  " + well.nextStep
        font.bold: true
        color: well.actionable ? Qt.alpha(root.accent, 0.9)
                               : Qt.alpha(root.fg, 0.5)
      }
    }
  }

  component Chip: Rectangle {
    id: chip
    property string label: ""
    property color tone: root.fg
    property bool solid: false
    implicitWidth: chipText.implicitWidth + (root.padCard * 2)
    implicitHeight: chipText.implicitHeight + (root.padLine * 2)
    radius: height / 2
    color: Qt.alpha(chip.tone, chip.solid ? 0.18 : 0.06)
    border.color: Qt.alpha(chip.tone, chip.solid ? 0.55 : 0.30)
    border.width: 1

    Behavior on color {
      enabled: root.motion
      ColorAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
    }
    Behavior on border.color {
      enabled: root.motion
      ColorAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
    }

    Mono {
      id: chipText
      anchors.centerIn: parent
      text: chip.label
      font.pixelSize: root.typeMeta
      color: chip.tone
      font.bold: chip.solid
    }
  }

  // Reachable by mouse and by keyboard. Tab order is document order, which on
  // this surface runs left rail, console, right rail -- the same order the eye
  // takes -- so no explicit KeyNavigation chain is needed. An unavailable
  // button drops out of the tab ring entirely rather than accepting focus and
  // then refusing to fire.
  component ActionButton: Rectangle {
    id: btn
    property string label: ""
    property string glyph: ""
    property bool available: true
    property bool primary: false
    property color tone: btn.primary ? root.accent : root.fg
    signal activated

    implicitWidth: btnRow.implicitWidth + (root.padCard * 2)
    implicitHeight: btnRow.implicitHeight + (root.padGroup * 2) - root.padTight
    width: implicitWidth
    height: implicitHeight
    radius: Style.cornerRadius
    opacity: btn.available ? 1.0 : 0.35
    activeFocusOnTab: btn.available
    color: !btn.available ? Qt.alpha(root.fg, 0.04)
      : (btnArea.containsMouse ? Qt.alpha(btn.tone, 0.22)
                               : Qt.alpha(btn.tone, btn.primary ? 0.11 : 0.07))
    border.color: btn.activeFocus ? btn.tone
      : Qt.alpha(btn.tone, btn.available ? (btn.primary ? 0.5 : 0.32) : 0.18)
    border.width: 1

    Keys.onPressed: function (event) {
      if (event.key !== Qt.Key_Return && event.key !== Qt.Key_Enter
          && event.key !== Qt.Key_Space) return
      if (btn.available) btn.activated()
      event.accepted = true
    }

    Behavior on color {
      enabled: root.motion
      ColorAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
    }
    Behavior on border.color {
      enabled: root.motion
      ColorAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
    }

    // Focus ring, drawn outside the border so it reads as a ring rather than
    // as a thicker button. Keyboard focus has to be visible or the shortcut
    // legend below is a promise the surface does not keep.
    Rectangle {
      anchors.fill: parent
      anchors.margins: -root.padTight
      radius: Style.cornerRadius
      color: "transparent"
      border.color: Qt.alpha(btn.tone, 0.55)
      border.width: 1
      visible: opacity > 0
      opacity: btn.activeFocus ? 1.0 : 0.0
      Behavior on opacity {
        enabled: root.motion
        NumberAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
      }
    }

    Row {
      id: btnRow
      anchors.centerIn: parent
      spacing: root.padGroup - root.padTight
      Mono {
        anchors.verticalCenter: parent.verticalCenter
        visible: btn.glyph !== ""
        text: btn.glyph
        color: btn.tone
        font.pixelSize: root.typeBody
      }
      Mono {
        anchors.verticalCenter: parent.verticalCenter
        text: btn.label
        color: btn.tone
        font.pixelSize: root.typeBody
        font.bold: btn.primary
      }
    }

    MouseArea {
      id: btnArea
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: btn.available ? Qt.PointingHandCursor : Qt.ArrowCursor
      onClicked: {
        if (!btn.available) return
        btn.forceActiveFocus()
        btn.activated()
      }
    }
  }

  // A fingerprint rendered as the handle it is: five groups of four, short
  // enough to read aloud, which is the whole point of it. The full key, where
  // one exists, is reachable only through the explicit copy action beside it.
  //
  // Three rules are load-bearing here.
  //
  // The KIND is always shown. There are two fingerprint namespaces -- one over
  // the KEM recipient payload, one over the ML-DSA-87 verifying key -- and
  // they are not interchangeable. A bare fingerprint invites someone to
  // compare a recipient against a signer and conclude something false, so no
  // fingerprint is ever painted without saying which kind it is.
  //
  // The fingerprint gets its own line, under the label rather than beside it.
  // Twenty-four characters plus a label plus an action does not fit a rail at
  // every font size the theme allows, and the failure mode of trying is an
  // ELIDED fingerprint -- worse than none, because it silently invites exactly
  // the mistaken-identity error the fingerprint exists to prevent. Its own
  // line makes truncation impossible instead of unlikely.
  //
  // The five groups are painted as five texts against dim separators rather
  // than as one dashed string. Comparing two of these aloud or by eye is the
  // entire job, and grouping is what makes that survivable; the plate around
  // them says the whole thing is one copyable object.
  component FingerprintRow: Item {
    id: fpRow
    property string kind: "recipient"
    property string fingerprint: ""
    property string fullKey: ""
    readonly property bool known: fpRow.fingerprint !== ""
    implicitHeight: fpHead.height + fpPlate.implicitHeight + root.padTight

    // Line one names the namespace and offers the full key where there is one.
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
        onClicked: anubis.copyText(fpRow.fullKey,
                                   "full " + fpRow.kind + " key")
        Meta {
          id: copyKey
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          visible: fpRow.fullKey !== ""
          text: Model.GLYPH.copy + " key"
          color: keyArea.containsMouse ? root.accent : Qt.alpha(root.fg, 0.38)
          Behavior on color {
            enabled: root.motion
            ColorAnimation { duration: root.motionFast }
          }
        }
      }
    }

    // Line two: the plate, indented to the label's text column so the two
    // lines share one left edge instead of nearly sharing one.
    //
    // The digits are ONE Text, not a row of per-group items: a Row overflows
    // the rail and a Flow, measured here, will not fill an anchor-derived
    // width at all, and both failure modes end in a fingerprint the reader
    // cannot fully see -- the same silent half-truth as an elide.
    //
    // Twenty-four characters at the shipped theme (20px base font, 1.67
    // spacing scale) measures about 266px against roughly 230px of plate, so
    // this does not fit one line and no amount of tightening makes it. Rather
    // than let the wrap fall mid-group, fpMetrics measures the string and asks
    // Model for a break on the group-three boundary: 14 characters over 9,
    // both lines starting on a digit. A theme with room gets one line.
    // WrapAnywhere stays on underneath as the guarantee that nothing is ever
    // lost, whatever a theme does.
    //
    // The dim separators are StyledText, safe because
    // Model.fingerprintMarkup rebuilds the value out of hex and dashes only.
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

      Behavior on color {
        enabled: root.motion
        ColorAnimation { duration: root.motionFast }
      }
      Behavior on border.color {
        enabled: root.motion
        ColorAnimation { duration: root.motionFast }
      }

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
        Behavior on color {
          enabled: root.motion
          ColorAnimation { duration: root.motionFast }
        }
      }

      // Sits in the slack the shorter second line leaves rather than reserving
      // a column beside the digits: thirty pixels of permanently blank rail is
      // what pushed the wrap in the first place.
      Meta {
        id: copyHint
        anchors.right: parent.right
        anchors.rightMargin: root.padLine
        anchors.bottom: parent.bottom
        anchors.bottomMargin: root.padTight
        visible: opacity > 0
        opacity: fpArea.containsMouse && fpRow.known ? 1.0 : 0.0
        text: Model.GLYPH.copy
        color: root.accent
        Behavior on opacity {
          enabled: root.motion
          NumberAnimation { duration: root.motionFast }
        }
      }
    }

    MouseArea {
      id: fpArea
      anchors.fill: fpPlate
      hoverEnabled: true
      enabled: fpRow.known
      cursorShape: Qt.PointingHandCursor
      onClicked: anubis.copyText(fpRow.fingerprint,
                                 fpRow.kind + " fingerprint")
    }
  }

  // Label left, value right, both sitting on ONE baseline rather than each
  // vertically centred in its own half. Centring two texts of different sizes
  // against each other is what made these rows read as slightly crooked.
  component FieldRow: Item {
    id: kv
    property string label: ""
    property string value: ""
    property string tone: "neutral"
    property bool strong: false
    implicitHeight: Math.max(kvLabel.implicitHeight, kvValue.implicitHeight)
      + root.padTight

    Meta {
      id: kvLabel
      anchors.left: parent.left
      anchors.top: parent.top
      text: kv.label
      color: Qt.alpha(root.fg, 0.45)
    }
    Mono {
      id: kvValue
      anchors.right: parent.right
      anchors.left: kvLabel.right
      anchors.leftMargin: root.padCard
      anchors.baseline: kvLabel.baseline
      horizontalAlignment: Text.AlignRight
      elide: Text.ElideMiddle
      text: kv.value
      color: root.toneColor(kv.tone)
      font.bold: kv.strong || kv.tone === "good" || kv.tone === "bad"
    }
  }

  // The one text input on this surface.
  //
  // Qt Quick Controls' TextField draws a light-mode field with an underline,
  // which on a dark cockpit reads as a foreign element sitting on top of the
  // design rather than part of it. This is the same field in the vault's own
  // idiom: a tinted plate, a one-pixel edge, and the accent only on focus --
  // matching ActionButton and Chip exactly, so a focused control looks focused
  // whatever kind of control it is.
  component InputField: TextField {
    id: field
    property real horizontalPadding: root.padCard
    property real verticalPadding: root.padGroup - root.padTight

    font.family: root.fontFamily
    font.pixelSize: root.typeBody
    color: root.fg
    selectionColor: Qt.alpha(root.accent, 0.32)
    selectedTextColor: root.fg
    placeholderTextColor: Qt.alpha(root.fg, 0.32)

    leftPadding: field.horizontalPadding
    rightPadding: field.horizontalPadding
    topPadding: field.verticalPadding
    bottomPadding: field.verticalPadding

    background: Rectangle {
      radius: Style.cornerRadius
      color: field.activeFocus ? Qt.alpha(root.accent, 0.08)
                               : Qt.alpha(root.fg, 0.05)
      border.color: field.activeFocus ? Qt.alpha(root.accent, 0.55)
        : (field.hovered ? Qt.alpha(root.fg, 0.30) : Qt.alpha(root.fg, 0.16))
      border.width: 1

      Behavior on color {
        enabled: root.motion
        ColorAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
      }
      Behavior on border.color {
        enabled: root.motion
        ColorAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
      }
    }
  }

  // ==========================================================================
  // settings controls
  // ==========================================================================
  //
  // Three of them, and every one commits the moment it changes. There is no
  // Apply button and no Cancel, because a settings sheet with a pending state
  // has two answers to "what is the poll interval" and only one of them is
  // true. What is on screen is what is on disk.
  //
  // Each control carries a hint that says what the current value DOES, not
  // what the setting is called. A label that only restates its own key teaches
  // nobody anything.

  component PrefRow: Item {
    id: prefRow
    property string label: ""
    property string hint: ""
    property bool warn: false
    default property alias control: prefControl.data

    implicitHeight: prefLabel.implicitHeight + prefHint.implicitHeight
      + root.padLine + root.padTight

    Mono {
      id: prefLabel
      anchors.left: parent.left
      anchors.top: parent.top
      anchors.right: prefControl.left
      anchors.rightMargin: root.padCard
      elide: Text.ElideRight
      text: prefRow.label
      color: Qt.alpha(root.fg, 0.85)
    }
    Meta {
      id: prefHint
      anchors.left: parent.left
      anchors.top: prefLabel.bottom
      anchors.topMargin: root.padTight
      anchors.right: prefControl.left
      anchors.rightMargin: root.padCard
      wrapMode: Text.WordWrap
      text: prefRow.hint
      color: prefRow.warn ? Qt.alpha(root.urgent, 0.8) : Qt.alpha(root.fg, 0.38)
    }
    // The slot the concrete controls fill. It is centred against the row
    // here, once, so nothing inside it centres itself against the slot -- that
    // would make the slot's height depend on its child's position and its
    // child's position depend on the slot's height.
    Item {
      id: prefControl
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      implicitWidth: childrenRect.width
      implicitHeight: childrenRect.height
      width: implicitWidth
      height: implicitHeight
    }
  }

  // A bounded integer. Clamped at both ends by the control rather than
  // validated after the fact, so an out-of-range value is never something the
  // settings file has to hold and the engine has to refuse.
  component PrefStepper: PrefRow {
    id: stepper
    property int value: 0
    property int minimum: 0
    property int maximum: 100
    property int step: 1
    property string suffix: ""
    signal committed(int value)

    function nudge(delta) {
      var next = Math.min(stepper.maximum,
                          Math.max(stepper.minimum, stepper.value + delta))
      if (next !== stepper.value) stepper.committed(next)
    }

    Row {
      spacing: root.padGroup

      ActionButton {
        anchors.verticalCenter: parent.verticalCenter
        glyph: "−"
        label: ""
        available: stepper.value > stepper.minimum
        onActivated: stepper.nudge(-stepper.step)
      }
      Rectangle {
        anchors.verticalCenter: parent.verticalCenter
        implicitWidth: Math.max(stepperText.implicitWidth + (root.padCard * 2),
                                root.padRail * 3)
        implicitHeight: stepperText.implicitHeight + (root.padGroup * 2)
          - root.padTight
        radius: Style.cornerRadius
        color: Qt.alpha(root.fg, 0.05)
        border.color: Qt.alpha(root.fg, 0.16)
        border.width: 1
        Mono {
          id: stepperText
          anchors.centerIn: parent
          text: stepper.value + stepper.suffix
          color: root.fg
          font.bold: true
        }
      }
      ActionButton {
        anchors.verticalCenter: parent.verticalCenter
        glyph: "+"
        label: ""
        available: stepper.value < stepper.maximum
        onActivated: stepper.nudge(stepper.step)
      }
    }
  }

  component PrefToggle: PrefRow {
    id: toggle
    property bool checked: false
    signal toggled(bool value)

    Rectangle {
      implicitWidth: root.padRail * 2.4
      implicitHeight: root.padRail
      width: implicitWidth
      height: implicitHeight
      radius: height / 2
      activeFocusOnTab: true
      color: toggle.checked ? Qt.alpha(root.accent, 0.22)
                            : Qt.alpha(root.fg, 0.06)
      border.color: toggle.activeFocus
        ? (toggle.checked ? root.accent : root.fg)
        : (toggle.checked ? Qt.alpha(root.accent, 0.55)
                          : Qt.alpha(root.fg, 0.22))
      border.width: 1

      Behavior on color {
        enabled: root.motion
        ColorAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
      }

      Rectangle {
        y: (parent.height - height) / 2
        x: toggle.checked ? parent.width - width - ((parent.height - height) / 2)
                          : (parent.height - height) / 2
        width: parent.height - (root.padTight * 2)
        height: width
        radius: width / 2
        color: toggle.checked ? root.accent : Qt.alpha(root.fg, 0.45)

        Behavior on x {
          enabled: root.motion
          NumberAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
        }
        Behavior on color {
          enabled: root.motion
          ColorAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
        }
      }

      Keys.onPressed: function (event) {
        if (event.key !== Qt.Key_Return && event.key !== Qt.Key_Enter
            && event.key !== Qt.Key_Space) return
        toggle.toggled(!toggle.checked)
        event.accepted = true
      }

      MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: {
          parent.forceActiveFocus()
          toggle.toggled(!toggle.checked)
        }
      }
    }
  }

  // Committed on Enter and on losing focus, never per keystroke: writing the
  // settings file once per character would leave it holding a half-typed
  // identity name every time somebody paused.
  component PrefText: PrefRow {
    id: prefText
    property string value: ""
    property string placeholder: ""
    signal committed(string value)

    InputField {
      width: root.padRail * 11
      text: prefText.value
      placeholderText: prefText.placeholder
      font.pixelSize: root.typeBody
      font.family: root.fontFamily
      verticalPadding: root.padLine
      onAccepted: prefText.committed(text.trim())
      onActiveFocusChanged: if (!activeFocus && text.trim() !== prefText.value)
        prefText.committed(text.trim())
    }
  }

  // ==========================================================================
  // the surface
  // ==========================================================================

  Rectangle {
    id: win
    anchors.fill: parent
    color: Color.background

    // The cockpit arrives rather than appearing: a short fade with a small
    // rise on the first frame. It is opacity and one transform, nothing that
    // reflows, and the keyboard is already live while it plays -- typing
    // during the fade is never dropped.
    Item {
      id: keyCatcher
      anchors.fill: parent
      focus: true
      opacity: root.opened ? 1.0 : 0.0
      transform: Translate { y: keyCatcher.opacity < 1 ? root.padRail : 0 }
      Behavior on opacity {
        enabled: root.motion
        NumberAnimation {
          duration: root.motionBase
          easing.type: Easing.OutQuart
        }
      }
      Keys.priority: Keys.BeforeItem
      Keys.onPressed: function (event) {
        if (event.key === Qt.Key_Escape) {
          root.escapeAction()
          event.accepted = true
          return
        }
        if (event.key === Qt.Key_F1) {
          root.showPreferences = false
          root.showAbout = !root.showAbout
          event.accepted = true
          return
        }
        if (!(event.modifiers & Qt.ControlModifier)) return
        if (event.key === Qt.Key_Q || event.key === Qt.Key_W) {
          root.requestQuit()
          event.accepted = true
        } else if (event.key === Qt.Key_O) {
          root.browseForTarget()
          event.accepted = true
        } else if (event.key === Qt.Key_Comma) {
          root.showAbout = false
          root.showPreferences = !root.showPreferences
          event.accepted = true
        } else if (event.key === Qt.Key_E) {
          root.focusRequest = "encrypt"
          pathField.forceActiveFocus()
          pathField.selectAll()
          event.accepted = true
        } else if (event.key === Qt.Key_D) {
          root.focusRequest = "decrypt"
          pathField.forceActiveFocus()
          pathField.selectAll()
          event.accepted = true
        } else if (event.key === Qt.Key_G) {
          root.focusRequest = "keygen"
          identityNameField.forceActiveFocus()
          event.accepted = true
        } else if (event.key === Qt.Key_R) {
          anubis.refresh()
          event.accepted = true
        }
      }

      // ------------------------------------------------------------- header
      Item {
        id: header
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.margins: root.padRail
        height: Style.spacing.controlHeight + root.padCard

        // The brand rail is clipped against the action rail rather than
        // allowed to run under it: on a narrow display the FIPS chips drop
        // off the end instead of painting over the close button.
        Item {
          id: brandClip
          anchors.left: parent.left
          anchors.right: headerActions.left
          anchors.rightMargin: root.padRail
          anchors.top: parent.top
          anchors.bottom: parent.bottom
          clip: true

          Row {
            id: brand
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            spacing: root.padCard

            Mono {
              anchors.verticalCenter: parent.verticalCenter
              text: Model.GLYPH.shieldKey
              color: brandArea.containsMouse ? root.accent : root.fg
              font.pixelSize: Style.font.heading
            }
            Mono {
              anchors.verticalCenter: parent.verticalCenter
              text: "ANUBIS"
              color: brandArea.containsMouse ? root.accent : root.fg
              font.pixelSize: Style.font.title
              font.bold: true
            }
            Mono {
              anchors.verticalCenter: parent.verticalCenter
              text: anubis.version !== "" ? "v" + anubis.version
                : (anubis.engineMissing ? "engine absent" : "version unknown")
              color: Qt.alpha(root.fg, 0.45)
            }
            Rectangle {
              anchors.verticalCenter: parent.verticalCenter
              width: 1
              height: Style.spacing.xl
              color: Qt.alpha(root.fg, 0.18)
            }
            // Only when the engine actually named its suite. It used to fall
            // back to a hardcoded X25519 + ML-KEM-1024 / ML-DSA-87, which meant
            // a failed poll -- or a binary that could not execute at all --
            // still wore a full cryptographic badge in the accent colour that
            // on this surface means VERIFIED.
            Chip {
              anchors.verticalCenter: parent.verticalCenter
              visible: anubis.suite !== null
              label: Model.suiteBadge(anubis.suite)
              tone: root.accent
              solid: true
            }
            Chip {
              anchors.verticalCenter: parent.verticalCenter
              visible: anubis.suite === null
              label: "SUITE NOT STATED"
              tone: Qt.alpha(root.fg, 0.5)
            }
            Repeater {
              model: Model.fipsChips(anubis.suite)
              delegate: Chip {
                required property var modelData
                anchors.verticalCenter: parent.verticalCenter
                label: modelData
                tone: Qt.alpha(root.fg, 0.7)
              }
            }
          }

          MouseArea {
            id: brandArea
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            width: Math.min(brand.implicitWidth, brandClip.width)
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              root.showPreferences = false
              root.showAbout = !root.showAbout
            }
          }
        }

        Row {
          id: headerActions
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          spacing: root.padCard

          Rectangle {
            anchors.verticalCenter: parent.verticalCenter
            width: Style.spacing.md
            height: width
            radius: width / 2
            color: root.vaultState === "absent" ? Qt.alpha(root.fg, 0.3)
              : (root.vaultState === "failed" || root.vaultState === "error"
                 ? root.urgent
                 : (root.vaultState === "unknown" ? Qt.alpha(root.fg, 0.55)
                                                  : root.accent))
          }
          ActionButton {
            anchors.verticalCenter: parent.verticalCenter
            glyph: Model.GLYPH.refresh
            label: anubis.statusBusy ? "polling" : "poll"
            available: !anubis.engineMissing
            onActivated: anubis.refresh()
          }
          ActionButton {
            anchors.verticalCenter: parent.verticalCenter
            glyph: Model.GLYPH.folder
            label: "open"
            onActivated: root.browseForTarget()
          }
          ActionButton {
            anchors.verticalCenter: parent.verticalCenter
            glyph: Model.GLYPH.cog
            label: "settings"
            onActivated: {
              root.showAbout = false
              root.showPreferences = !root.showPreferences
            }
          }
          ActionButton {
            anchors.verticalCenter: parent.verticalCenter
            glyph: Model.GLYPH.close
            label: "quit"
            onActivated: root.requestQuit()
          }
        }
      }

      // ------------------------------------------------------------- footer
      //
      // One line: the assurance statement. It is pinned outside every scroll
      // area because it is the line that must never be scrolled away. The
      // shortcut legend used to sit under it; it now lives in the settings
      // sheet, because a reference card the operator has already read is
      // screen space taken from the work.
      Item {
        id: footer
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.margins: root.padRail
        height: footerCol.implicitHeight

        Column {
          id: footerCol
          anchors.left: parent.left
          anchors.right: parent.right
          spacing: root.padGroup

          Rectangle {
            width: footerCol.width
            height: 1
            color: Qt.alpha(root.fg, 0.10)
          }
          Meta {
            width: footerCol.width
            wrapMode: Text.WordWrap
            text: Model.GLYPH.info + "  " + Model.assuranceLine()
            color: Qt.alpha(root.fg, 0.5)
          }
        }
      }

      // --------------------------------------------------------------- body
      Item {
        id: body
        anchors.top: header.bottom
        anchors.bottom: footer.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.margins: root.padRail
        anchors.topMargin: root.padGroup
        anchors.bottomMargin: root.padGroup

        readonly property real gap: root.padRail
        readonly property var cols: Model.columnWidths(width, gap)

        // ======================================================== LEFT RAIL
        Flickable {
          id: leftScroll
          width: body.cols.left
          anchors.top: parent.top
          anchors.bottom: parent.bottom
          anchors.left: parent.left
          contentWidth: width
          contentHeight: leftPane.implicitHeight
          clip: true
          pixelAligned: true
          boundsBehavior: Flickable.StopAtBounds
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: leftPane
            width: leftScroll.width - root.padGroup
            spacing: body.gap

            // --------------------------------------------- identity vault
            SectionCard {
              width: leftPane.width
              recessed: true
              title: Model.GLYPH.accountKey + "  IDENTITY VAULT"
              note: anubis.identities.length
                + (anubis.identities.length === 1 ? " key" : " keys")

              EmptyWell {
                visible: anubis.identities.length === 0
                glyph: Model.GLYPH.accountKey
                headline: anubis.engineMissing ? "no engine" : "no identity yet"
                body: anubis.engineMissing
                  ? "Identities live in files the engine writes. Without the "
                    + "engine there is nothing to list."
                  : "An identity is one file holding X25519, ML-KEM-1024 and "
                    + "ML-DSA-87 material. It is what lets you decrypt, and "
                    + "what other people encrypt to."
                nextStep: anubis.engineMissing
                  ? "install the engine first -- the console has the command"
                  : "name one below and press generate. Ctrl+G jumps there."
                nextStepGlyph: anubis.engineMissing ? Model.GLYPH.alert
                                                    : Model.GLYPH.plus
                actionable: !anubis.engineMissing
              }

              Repeater {
                model: anubis.identities
                delegate: Rectangle {
                  id: idCard
                  required property var modelData
                  readonly property bool chosen:
                    root.effectiveIdentity === String(idCard.modelData.name)
                  width: parent.width
                  implicitHeight: idCol.implicitHeight + (root.padCard * 2)
                  radius: Style.cornerRadius
                  color: idCard.chosen ? Qt.alpha(root.accent, 0.08)
                                       : Qt.alpha(root.fg, 0.03)
                  border.color: idCard.chosen ? Qt.alpha(root.accent, 0.4)
                                              : Qt.alpha(root.fg, 0.12)
                  border.width: 1

                  Column {
                    id: idCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: root.padCard
                    spacing: root.padLine

                    Item {
                      width: idCol.width
                      height: idName.implicitHeight
                      Mono {
                        id: idName
                        anchors.left: parent.left
                        anchors.right: idUse.left
                        anchors.rightMargin: root.padGroup
                        anchors.verticalCenter: parent.verticalCenter
                        elide: Text.ElideMiddle
                        text: Model.GLYPH.key + "  "
                          + String(idCard.modelData.name)
                        color: idCard.chosen ? root.accent : root.fg
                        font.bold: true
                        font.pixelSize: root.typeLead
                      }
                      Meta {
                        id: idUse
                        anchors.right: parent.right
                        anchors.baseline: idName.baseline
                        text: idCard.chosen ? "IN USE" : "select"
                        font.bold: idCard.chosen
                        font.letterSpacing: idCard.chosen ? 1.1 : 0
                        color: idCard.chosen ? root.accent
                          : (idSelect.containsMouse ? root.fg
                                                    : Qt.alpha(root.fg, 0.35))
                      }
                      MouseArea {
                        id: idSelect
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.chosenIdentity =
                          String(idCard.modelData.name)
                      }
                    }

                    // Both namespaces, each labelled. The recipient
                    // fingerprint is what someone encrypts TO; the signer
                    // fingerprint is what they check a signature AGAINST.
                    // Showing them together, named, is what stops anyone
                    // comparing one against the other.
                    FingerprintRow {
                      width: idCol.width
                      kind: "recipient"
                      fingerprint: Model.formatFingerprint(
                        idCard.modelData.fingerprint)
                      fullKey: String(idCard.modelData.recipient || "")
                    }
                    FingerprintRow {
                      width: idCol.width
                      visible: Model.signingFingerprint(idCard.modelData) !== ""
                      kind: "signer"
                      fingerprint: Model.signingFingerprint(idCard.modelData)
                      fullKey: ""
                    }

                    FieldRow {
                      width: idCol.width
                      label: "created"
                      value: Model.stampLocal(idCard.modelData.created) || "--"
                    }
                    FieldRow {
                      width: idCol.width
                      label: "signing"
                      value: idCard.modelData.signing === true
                        ? "ML-DSA-87 key" : "none"
                      tone: idCard.modelData.signing === true
                        ? "good" : "unknown"
                    }
                    Meta {
                      width: idCol.width
                      elide: Text.ElideMiddle
                      text: String(idCard.modelData.path || "")
                      color: Qt.alpha(root.fg, 0.3)
                    }
                  }
                }
              }

              Rectangle {
                width: parent.width
                height: 1
                color: Qt.alpha(root.fg, 0.08)
              }

              Legend {
                width: parent.width
                text: "GENERATE IDENTITY"
              }
              // Field over button rather than beside it. Side by side, the
              // button's label pushed the field down to about ninety pixels,
              // which elided its own placeholder -- a form field that cannot
              // show what it wants.
              Column {
                width: parent.width
                spacing: root.padLine

                InputField {
                  id: identityNameField
                  width: parent.width
                  placeholderText: "identity name"
                  font.pixelSize: root.typeBody
                  verticalPadding: root.padLine + root.padTight
                  text: root.newIdentityName
                  onTextChanged: root.newIdentityName = text
                  onAccepted: anubis.generateIdentity(root.newIdentityName)
                }
                Item {
                  width: parent.width
                  height: genButton.implicitHeight
                  ActionButton {
                    id: genButton
                    anchors.left: parent.left
                    glyph: Model.GLYPH.plus
                    label: "generate"
                    primary: anubis.identities.length === 0
                    available: !anubis.engineMissing && !anubis.actionBusy
                      && Model.validIdentityName(root.newIdentityName)
                    onActivated: anubis.generateIdentity(root.newIdentityName)
                  }
                  // Why the button is refusing, said where the refusal is,
                  // instead of leaving a dimmed control with no explanation.
                  Meta {
                    anchors.left: genButton.right
                    anchors.leftMargin: root.padGroup
                    anchors.right: parent.right
                    anchors.verticalCenter: genButton.verticalCenter
                    horizontalAlignment: Text.AlignRight
                    wrapMode: Text.WordWrap
                    visible: !anubis.engineMissing && !genButton.available
                      && !anubis.actionBusy
                    text: root.newIdentityName === ""
                      ? "needs a name" : "letters, digits, - and _ only"
                    color: Qt.alpha(root.fg, 0.38)
                  }
                }
              }
              Meta {
                width: parent.width
                wrapMode: Text.WordWrap
                text: "Signing is chosen per file at encrypt time, never at "
                  + "keygen: every identity already holds the ML-DSA-87 key."
                color: Qt.alpha(root.fg, 0.32)
              }
            }

            // ---------------------------------------- recipient address book
            SectionCard {
              width: leftPane.width
              recessed: true
              title: Model.GLYPH.keyChain + "  ADDRESS BOOK"
              note: anubis.recipients.length
                + (anubis.recipients.length === 1 ? " entry" : " entries")

              // With an identity already in hand, an empty address book is not
              // a dead end: encrypting to yourself works right now. Saying so
              // is the difference between an empty section and a blocked one.
              EmptyWell {
                visible: anubis.recipients.length === 0
                glyph: Model.GLYPH.keyChain
                headline: anubis.engineMissing ? "no engine" : "no one else yet"
                body: anubis.engineMissing
                  ? "The address book is a file the engine owns. Without the "
                    + "engine there is nothing to read."
                  : "The book holds other people's public recipient keys, so "
                    + "you pick them by label instead of by 2573 characters."
                nextStep: anubis.engineMissing
                  ? "install the engine first"
                  : (anubis.identities.length > 0
                     ? "you can already encrypt to yourself -- the self chip "
                       + "in the console. Paste someone else's anubis1 key "
                       + "below to add them."
                     : "paste an anubis1 key below, or generate an identity "
                       + "first and encrypt to yourself.")
                nextStepGlyph: anubis.engineMissing ? Model.GLYPH.alert
                                                    : Model.GLYPH.plus
                actionable: !anubis.engineMissing
              }

              Repeater {
                model: anubis.recipients
                delegate: Rectangle {
                  id: recCard
                  required property var modelData
                  readonly property string recKey:
                    String(recCard.modelData.key || "")
                  readonly property bool picked:
                    Model.isMember(root.selection, recCard.recKey)
                  width: parent.width
                  implicitHeight: recCol.implicitHeight + (root.padCard * 2)
                  radius: Style.cornerRadius
                  color: recCard.picked ? Qt.alpha(root.accent, 0.08)
                                        : Qt.alpha(root.fg, 0.03)
                  border.color: recCard.picked ? Qt.alpha(root.accent, 0.4)
                                               : Qt.alpha(root.fg, 0.12)
                  border.width: 1

                  Column {
                    id: recCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: root.padCard
                    spacing: root.padLine

                    Item {
                      width: recCol.width
                      height: recLabel.implicitHeight

                      Rectangle {
                        id: recBox
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        width: root.padCard
                        height: width
                        radius: Style.cornerRadius
                        color: recCard.picked ? Qt.alpha(root.accent, 0.35)
                                              : "transparent"
                        border.color: recCard.picked
                          ? root.accent : Qt.alpha(root.fg, 0.35)
                        border.width: 1
                        Mono {
                          anchors.centerIn: parent
                          visible: recCard.picked
                          text: Model.GLYPH.check
                          color: root.accent
                        }
                      }
                      Mono {
                        id: recLabel
                        anchors.left: recBox.right
                        anchors.leftMargin: root.padGroup
                        anchors.right: recRemoveArea.left
                        anchors.rightMargin: root.padGroup
                        anchors.verticalCenter: parent.verticalCenter
                        elide: Text.ElideRight
                        text: String(recCard.modelData.label || "unlabelled")
                        color: recCard.picked ? root.accent : root.fg
                        font.bold: true
                        font.pixelSize: root.typeLead
                      }
                      MouseArea {
                        anchors.left: parent.left
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        anchors.right: recRemoveArea.left
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.toggleRecipient(recCard.recKey)
                      }
                      MouseArea {
                        id: recRemoveArea
                        anchors.right: parent.right
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        width: recRemove.implicitWidth + root.padGroup
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: anubis.removeRecipient(
                          String(recCard.modelData.label))
                        Mono {
                          id: recRemove
                          anchors.right: parent.right
                          anchors.verticalCenter: parent.verticalCenter
                          text: Model.GLYPH.trash
                          color: recRemoveArea.containsMouse
                            ? root.urgent : Qt.alpha(root.fg, 0.3)
                        }
                      }
                    }

                    FingerprintRow {
                      width: recCol.width
                      kind: "recipient"
                      fingerprint: Model.formatFingerprint(
                        recCard.modelData.fingerprint)
                      fullKey: recCard.recKey
                    }
                  }
                }
              }

              Rectangle {
                width: parent.width
                height: 1
                color: Qt.alpha(root.fg, 0.08)
              }

              Legend {
                width: parent.width
                text: "ADD RECIPIENT"
              }
              Column {
                width: parent.width
                spacing: root.padLine

                InputField {
                  id: recipientLabelField
                  width: parent.width
                  placeholderText: "label"
                  font.pixelSize: root.typeBody
                  verticalPadding: root.padLine + root.padTight
                  text: root.newRecipientLabel
                  onTextChanged: root.newRecipientLabel = text
                }
                InputField {
                  id: recipientKeyField
                  width: parent.width
                  placeholderText: "anubis1... (about 2573 characters)"
                  font.pixelSize: root.typeBody
                  verticalPadding: root.padLine + root.padTight
                  text: root.newRecipientKey
                  onTextChanged: root.newRecipientKey = text.replace(/\s+/g, "")
                }
                Item {
                  width: parent.width
                  height: addRecipientButton.implicitHeight
                  ActionButton {
                    id: addRecipientButton
                    anchors.left: parent.left
                    glyph: Model.GLYPH.plus
                    label: "add to book"
                    available: !anubis.engineMissing && !anubis.actionBusy
                      && Model.recipientRefusal(root.newRecipientLabel,
                                                root.newRecipientKey,
                                                anubis.recipients) === ""
                    onActivated: {
                      anubis.addRecipient(root.newRecipientLabel,
                                          root.newRecipientKey)
                      root.newRecipientLabel = ""
                      root.newRecipientKey = ""
                    }
                  }
                  Meta {
                    anchors.left: addRecipientButton.right
                    anchors.leftMargin: root.padGroup
                    anchors.right: parent.right
                    anchors.verticalCenter: addRecipientButton.verticalCenter
                    horizontalAlignment: Text.AlignRight
                    elide: Text.ElideRight
                    text: root.newRecipientKey === "" ? ""
                      : Model.keyLengthNote(root.newRecipientKey)
                    color: Qt.alpha(root.fg, 0.4)
                  }
                }
              }
              Mono {
                width: parent.width
                wrapMode: Text.WordWrap
                visible: anubis.actionError !== ""
                text: Model.GLYPH.alert + "  " + anubis.actionError
                color: root.urgent
              }
              Mono {
                width: parent.width
                visible: anubis.actionStatus !== ""
                text: anubis.actionStatus
                color: root.accent
              }
            }
          }
        }

        // =========================================================== CENTRE
        Flickable {
          id: centreScroll
          anchors.top: parent.top
          anchors.bottom: parent.bottom
          anchors.left: leftScroll.right
          anchors.leftMargin: body.gap
          width: body.cols.centre
          contentWidth: width
          contentHeight: centrePane.implicitHeight
          clip: true
          pixelAligned: true
          boundsBehavior: Flickable.StopAtBounds
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: centrePane
            width: centreScroll.width - root.padGroup
            spacing: body.gap

            // ----------------------------------------------------- first run
            //
            // A brand-new vault has nothing in it, and the console it lands on
            // has every control disabled: no identity to encrypt from, no
            // recipient to encrypt to, no container to inspect. Four dim
            // paragraphs is not an introduction. This card owns the space the
            // inspector will eventually fill and says, in order, what the
            // three steps are -- with the current one lit and the rest banked.
            SectionCard {
              id: firstRun
              readonly property bool haveIdentity: anubis.identities.length > 0
              readonly property bool haveTarget: root.targetPath !== ""
              width: centrePane.width
              visible: !anubis.engineMissing
                && anubis.identities.length === 0
                && anubis.recipients.length === 0
              title: Model.GLYPH.shieldKey + "  FIRST RUN"
              emphasis: true

              Mono {
                width: parent.width
                wrapMode: Text.WordWrap
                text: "This vault is empty. Three steps put a post-quantum "
                  + "container on disk, and the first one is the only one that "
                  + "cannot be undone by deleting a file."
                color: Qt.alpha(root.fg, 0.7)
              }

              Repeater {
                model: [
                  {
                    n: "1",
                    head: "generate an identity",
                    body: "One file holding X25519, ML-KEM-1024 and ML-DSA-87 "
                      + "material. It is what lets you decrypt later, so back "
                      + "it up before you rely on it.",
                    live: !firstRun.haveIdentity
                  },
                  {
                    n: "2",
                    head: "pick who can read the file",
                    body: "Your own identity appears in the console as a self "
                      + "chip, so you can encrypt to yourself immediately. "
                      + "Other people go in the address book by label.",
                    live: firstRun.haveIdentity
                  },
                  {
                    n: "3",
                    head: "drop a file and encrypt",
                    body: "Drag one onto the target field or type a path. "
                      + "Signing is chosen here, per file, not at keygen.",
                    live: firstRun.haveIdentity && firstRun.haveTarget
                  }
                ]
                delegate: Item {
                  id: step
                  required property var modelData
                  readonly property bool live: step.modelData.live === true
                  width: parent.width
                  implicitHeight: stepCol.implicitHeight

                  Rectangle {
                    id: stepBadge
                    anchors.left: parent.left
                    anchors.top: parent.top
                    width: stepNum.implicitHeight + root.padGroup
                    height: width
                    radius: width / 2
                    color: step.live ? Qt.alpha(root.accent, 0.18)
                                     : Qt.alpha(root.fg, 0.05)
                    border.color: step.live ? Qt.alpha(root.accent, 0.55)
                                            : Qt.alpha(root.fg, 0.14)
                    border.width: 1
                    Mono {
                      id: stepNum
                      anchors.centerIn: parent
                      text: String(step.modelData.n)
                      font.bold: true
                      color: step.live ? root.accent : Qt.alpha(root.fg, 0.4)
                    }
                  }

                  Column {
                    id: stepCol
                    anchors.left: stepBadge.right
                    anchors.leftMargin: root.padCard
                    anchors.right: parent.right
                    anchors.top: parent.top
                    spacing: root.padTight

                    Mono {
                      width: stepCol.width
                      text: String(step.modelData.head)
                      font.pixelSize: root.typeLead
                      font.bold: true
                      color: step.live ? root.accent : Qt.alpha(root.fg, 0.45)
                    }
                    Meta {
                      width: stepCol.width
                      wrapMode: Text.WordWrap
                      text: String(step.modelData.body)
                      color: Qt.alpha(root.fg, step.live ? 0.55 : 0.34)
                    }
                  }
                }
              }

              // One control, and it escalates rather than duplicating the
              // canonical form in the left rail. With no name typed it takes
              // you to the field that wants one; once the name is valid it
              // generates. Two generate forms would be two places for the same
              // state to disagree, and silently defaulting the name would be
              // this panel choosing something it has no business choosing.
              Row {
                spacing: root.padCard
                ActionButton {
                  glyph: Model.GLYPH.plus
                  primary: true
                  label: Model.validIdentityName(root.newIdentityName)
                    ? "generate \"" + root.newIdentityName + "\""
                    : "name an identity"
                  available: !anubis.actionBusy
                  onActivated: {
                    if (Model.validIdentityName(root.newIdentityName)) {
                      anubis.generateIdentity(root.newIdentityName)
                      return
                    }
                    root.focusRequest = "keygen"
                    leftScroll.contentY = 0
                    identityNameField.forceActiveFocus()
                  }
                }
                Meta {
                  anchors.verticalCenter: parent.verticalCenter
                  text: Model.validIdentityName(root.newIdentityName)
                    ? "or press Enter in the name field"
                    : "jumps to the name field in the identity vault -- Ctrl+G"
                  color: Qt.alpha(root.fg, 0.4)
                }
              }
            }

            // ------------------------------------------------ engine absent
            SectionCard {
              width: centrePane.width
              visible: anubis.engineMissing
              title: Model.GLYPH.alert + "  ENGINE NOT INSTALLED"
              tint: Qt.alpha(root.fg, 0.05)
              edge: Qt.alpha(root.fg, 0.25)

              Mono {
                width: parent.width
                wrapMode: Text.WordWrap
                text: "No `anubis` executable was found in ~/.cargo/bin, "
                  + "~/.local/bin, /usr/local/bin, /usr/bin, or on PATH. "
                  + "ANUBIS is pure Rust with no system libraries to install, "
                  + "so one cargo command is the whole dependency story."
                color: Qt.alpha(root.fg, 0.7)
              }
              Rectangle {
                width: parent.width
                implicitHeight: hintText.implicitHeight + (root.padCard * 2)
                radius: Style.cornerRadius
                color: Qt.alpha(root.fg, 0.06)
                border.color: Qt.alpha(root.fg, 0.15)
                border.width: 1
                Mono {
                  id: hintText
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  anchors.margins: root.padCard
                  wrapMode: Text.WrapAnywhere
                  text: Model.installHint()
                  color: root.fg
                }
              }
              Row {
                spacing: root.padCard
                ActionButton {
                  glyph: Model.GLYPH.copy
                  label: "copy command"
                  onActivated: anubis.copyText(Model.installHint(),
                                               "install command")
                }
                ActionButton {
                  glyph: Model.GLYPH.refresh
                  label: "re-probe"
                  primary: true
                  onActivated: anubis.probeEngine()
                }
              }
            }

            // -------------------------------------------- operation console
            SectionCard {
              width: centrePane.width
              title: Model.GLYPH.lock + "  OPERATION CONSOLE"
              note: anubis.enginePath
              // The primary workspace, and the only card that says so. The
              // rails carry the same information density but at a lower tint
              // and a smaller type step, so the eye lands here first.
              emphasis: true
              tint: Qt.alpha(root.fg, 0.055)

              Rectangle {
                id: dropZone
                width: parent.width
                implicitHeight: dropCol.implicitHeight + (root.padCard * 2)
                radius: Style.cornerRadius
                color: fileDrop.containsDrag ? Qt.alpha(root.accent, 0.12)
                                             : Qt.alpha(root.fg, 0.03)
                border.color: fileDrop.containsDrag
                  ? root.accent : Qt.alpha(root.fg, 0.18)
                border.width: 1

                Column {
                  id: dropCol
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.top: parent.top
                  anchors.margins: root.padCard
                  spacing: root.padGroup

                  Legend {
                    width: dropCol.width
                    text: (root.targetIsVault ? Model.GLYPH.fileLock
                                              : Model.GLYPH.file)
                      + "  TARGET FILE -- drop one here, or type a path"
                  }
                  InputField {
                    id: pathField
                    width: dropCol.width
                    placeholderText: "/path/to/file"
                    font.pixelSize: root.typeBody
                    verticalPadding: root.padLine
                    onTextChanged: pathSettle.restart()
                    onAccepted: root.targetPath =
                      Model.normalizePath(text, root.home)
                  }
                  Item {
                    width: dropCol.width
                    height: outLabel.implicitHeight
                    Meta {
                      id: outLabel
                      anchors.left: parent.left
                      anchors.top: parent.top
                      text: "output"
                      color: Qt.alpha(root.fg, 0.4)
                    }
                    Mono {
                      anchors.left: outLabel.right
                      anchors.leftMargin: root.padCard
                      anchors.right: parent.right
                      anchors.baseline: outLabel.baseline
                      horizontalAlignment: Text.AlignRight
                      elide: Text.ElideMiddle
                      text: root.targetPath === "" ? "--"
                        : Model.outputFor(root.targetIsVault
                                          ? "decrypt" : "encrypt",
                                          root.targetPath)
                      color: root.targetPath === "" ? Qt.alpha(root.fg, 0.4)
                                                    : Qt.alpha(root.fg, 0.75)
                    }
                  }
                }

                DropArea {
                  id: fileDrop
                  anchors.fill: parent
                  keys: ["text/uri-list"]
                  onDropped: function (drop) {
                    if (drop.hasUrls && drop.urls.length > 0)
                      root.selectPath(String(drop.urls[0]))
                    else if (drop.hasText) root.selectPath(drop.text)
                    drop.accept()
                  }
                }
              }

              Item {
                width: parent.width
                height: recipientHeader.implicitHeight
                Legend {
                  id: recipientHeader
                  anchors.left: parent.left
                  anchors.top: parent.top
                  text: "RECIPIENTS -- " + root.selectedKeys.length + " selected"
                }
                Meta {
                  id: clearSelection
                  anchors.right: parent.right
                  anchors.baseline: recipientHeader.baseline
                  visible: root.selection.length > 0
                  text: "clear"
                  color: clearArea.containsMouse
                    ? root.accent : Qt.alpha(root.fg, 0.35)
                }
                MouseArea {
                  id: clearArea
                  anchors.right: parent.right
                  anchors.top: parent.top
                  anchors.bottom: parent.bottom
                  width: clearSelection.implicitWidth + root.padGroup
                  hoverEnabled: true
                  enabled: clearSelection.visible
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.selection = []
                }
              }

              Flow {
                width: parent.width
                spacing: root.padGroup

                Repeater {
                  model: anubis.identities
                  delegate: Chip {
                    id: selfChip
                    required property var modelData
                    readonly property string chipKey:
                      String(selfChip.modelData.recipient || "")
                    label: "self " + String(selfChip.modelData.name) + "  "
                      + Model.formatFingerprint(selfChip.modelData.fingerprint)
                    tone: Model.isMember(root.selection, selfChip.chipKey)
                      ? root.accent : Qt.alpha(root.fg, 0.6)
                    solid: Model.isMember(root.selection, selfChip.chipKey)
                    MouseArea {
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.toggleRecipient(selfChip.chipKey)
                    }
                  }
                }
                Repeater {
                  model: anubis.recipients
                  delegate: Chip {
                    id: bookChip
                    required property var modelData
                    readonly property string chipKey:
                      String(bookChip.modelData.key || "")
                    label: String(bookChip.modelData.label) + "  "
                      + Model.formatFingerprint(bookChip.modelData.fingerprint)
                    tone: Model.isMember(root.selection, bookChip.chipKey)
                      ? root.accent : Qt.alpha(root.fg, 0.6)
                    solid: Model.isMember(root.selection, bookChip.chipKey)
                    MouseArea {
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.toggleRecipient(bookChip.chipKey)
                    }
                  }
                }
              }

              // The first-run card already says this at length, so when it is
              // on screen this line would be the third copy of the same
              // sentence. It exists for the case where the book has entries
              // but nothing is picked.
              Meta {
                width: parent.width
                wrapMode: Text.WordWrap
                visible: anubis.identities.length === 0
                  && anubis.recipients.length === 0 && !anubis.engineMissing
                  && !firstRun.visible
                text: "Nothing to encrypt to yet. Generate an identity or add "
                  + "a recipient in the left rail."
                color: Qt.alpha(root.fg, 0.45)
              }

              Item {
                width: parent.width
                height: Math.max(signToggle.height, identityNote.implicitHeight)

                Rectangle {
                  id: signToggle
                  anchors.left: parent.left
                  anchors.verticalCenter: parent.verticalCenter
                  readonly property bool on: root.signRequested && anubis.canSign
                  width: signRow.implicitWidth + (root.padCard * 2)
                  height: signRow.implicitHeight + (root.padGroup * 2)
                  radius: Style.cornerRadius
                  opacity: anubis.canSign ? 1.0 : 0.4
                  color: signToggle.on ? Qt.alpha(root.accent, 0.18)
                                       : Qt.alpha(root.fg, 0.05)
                  border.color: signToggle.on ? root.accent
                                              : Qt.alpha(root.fg, 0.2)
                  border.width: 1

                  Row {
                    id: signRow
                    anchors.centerIn: parent
                    spacing: root.padGroup
                    Rectangle {
                      anchors.verticalCenter: parent.verticalCenter
                      width: root.padCard
                      height: width
                      radius: Style.cornerRadius
                      color: signToggle.on ? Qt.alpha(root.accent, 0.4)
                                           : "transparent"
                      border.color: signToggle.on ? root.accent
                                                  : Qt.alpha(root.fg, 0.35)
                      border.width: 1
                      Mono {
                        anchors.centerIn: parent
                        visible: signToggle.on
                        text: Model.GLYPH.check
                        color: root.accent
                      }
                    }
                    Mono {
                      anchors.verticalCenter: parent.verticalCenter
                      text: Model.GLYPH.signature + "  sign with ML-DSA-87"
                      color: signToggle.on ? root.accent
                                           : Qt.alpha(root.fg, 0.7)
                    }
                  }
                  MouseArea {
                    anchors.fill: parent
                    hoverEnabled: true
                    enabled: anubis.canSign
                    cursorShape: anubis.canSign ? Qt.PointingHandCursor
                                                : Qt.ArrowCursor
                    onClicked: root.signRequested = !root.signRequested
                  }
                }

                Meta {
                  id: identityNote
                  anchors.left: signToggle.right
                  anchors.leftMargin: root.padCard
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  horizontalAlignment: Text.AlignRight
                  elide: Text.ElideRight
                  text: root.effectiveIdentity === ""
                    ? "no identity available"
                    : "identity " + root.effectiveIdentity
                      + (root.chosenIdentity === "" ? " (default)" : "")
                  color: root.effectiveIdentity === ""
                    ? Qt.alpha(root.fg, 0.45) : Qt.alpha(root.fg, 0.5)
                }
              }

              // Confirmation surface: fingerprints, never truncated keys.
              Column {
                width: parent.width
                spacing: root.padLine
                visible: root.selectedKeys.length > 0
                Legend {
                  width: parent.width
                  text: "WILL BE READABLE BY"
                }
                Repeater {
                  model: Model.selectionHandles(anubis.status, root.selection)
                  delegate: Mono {
                    required property var modelData
                    width: parent.width
                    elide: Text.ElideRight
                    text: Model.GLYPH.fingerprint + "  " + modelData
                    color: Qt.alpha(root.accent, 0.85)
                  }
                }
              }

              Row {
                spacing: root.padCard

                ActionButton {
                  glyph: Model.GLYPH.lock
                  label: "Encrypt"
                  primary: root.focusRequest !== "decrypt"
                  available: !anubis.engineMissing && !anubis.opBusy
                    && root.targetPath !== "" && root.selectedKeys.length > 0
                  onActivated: root.runEncrypt()
                }
                ActionButton {
                  glyph: Model.GLYPH.lockOpen
                  label: "Decrypt"
                  primary: root.focusRequest === "decrypt"
                  available: !anubis.engineMissing && !anubis.opBusy
                    && root.targetPath !== ""
                  onActivated: root.runDecrypt()
                }
                ActionButton {
                  glyph: Model.GLYPH.eye
                  label: "Inspect"
                  available: !anubis.engineMissing && root.targetPath !== ""
                    && !anubis.inspectBusy
                  onActivated: anubis.runInspect(root.targetPath)
                }
                ActionButton {
                  visible: anubis.opBusy
                  glyph: Model.GLYPH.close
                  label: "Abort"
                  tone: root.urgent
                  onActivated: anubis.abortOperation()
                }
              }

              // Overwrite gate. Destroying an existing file is the one thing
              // this panel will not do without a second, explicit click.
              Rectangle {
                width: parent.width
                visible: anubis.pendingOverwrite !== null
                implicitHeight: overwriteCol.implicitHeight + (root.padCard * 2)
                radius: Style.cornerRadius
                color: Qt.alpha(root.urgent, 0.08)
                border.color: Qt.alpha(root.urgent, 0.45)
                border.width: 1

                Column {
                  id: overwriteCol
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.top: parent.top
                  anchors.margins: root.padCard
                  spacing: root.padGroup

                  Mono {
                    width: overwriteCol.width
                    wrapMode: Text.WrapAnywhere
                    text: Model.GLYPH.alert + "  The output already exists: "
                      + (anubis.pendingOverwrite
                         ? String(anubis.pendingOverwrite.output) : "")
                    color: root.urgent
                    font.bold: true
                  }
                  Row {
                    spacing: root.padCard
                    ActionButton {
                      label: "overwrite it"
                      tone: root.urgent
                      onActivated: anubis.confirmPending()
                    }
                    ActionButton {
                      label: "cancel"
                      onActivated: anubis.cancelPending()
                    }
                  }
                }
              }

              // The whole block appears at once when an operation starts, so it
              // fades rather than snapping into the middle of the console. The
              // fade is on opacity only -- the layout takes its space
              // immediately, so nothing below it slides while a bar animates.
              Column {
                id: progressBlock
                width: parent.width
                spacing: root.padGroup
                readonly property bool active: anubis.opBusy
                  || anubis.opResult !== null || anubis.opError !== ""
                visible: progressBlock.active
                opacity: progressBlock.active ? 1.0 : 0.0
                Behavior on opacity {
                  enabled: root.motion
                  NumberAnimation {
                    duration: root.motionBase
                    easing.type: Easing.OutQuart
                  }
                }

                Item {
                  width: parent.width
                  height: progressText.implicitHeight
                  Mono {
                    id: progressText
                    anchors.left: parent.left
                    text: anubis.opBusy
                      ? (anubis.opIndeterminate
                         ? anubis.opKind + "  |  working"
                         : Model.progressLabel(anubis.opKind, anubis.opDone,
                                               anubis.opTotal,
                                               anubis.opElapsedMs))
                      : (anubis.opResult
                         ? (anubis.opResult.ok === true ? "completed" : "failed")
                         : "")
                    color: anubis.opBusy ? root.accent
                      : (anubis.opResult && anubis.opResult.ok === true
                         ? root.accent : root.urgent)
                    font.bold: true
                  }
                  Meta {
                    anchors.right: parent.right
                    anchors.baseline: progressText.baseline
                    text: anubis.opBusy
                      ? Model.formatMillis(anubis.opElapsedMs)
                      : (anubis.opResult ? Model.opSummary(anubis.opResult) : "")
                    color: Qt.alpha(root.fg, 0.5)
                  }
                }

                // Progress events are throttled to roughly one per 4 MiB, so
                // a small file produces none at all. Until a total is known
                // the bar sweeps instead of sitting dead at zero, and it is
                // labelled "working", not "0%": claiming a percentage the
                // engine never reported would be a small lie.
                Rectangle {
                  id: progressTrack
                  width: parent.width
                  height: root.padGroup
                  radius: height / 2
                  color: Qt.alpha(root.fg, 0.08)
                  clip: true

                  Rectangle {
                    visible: !anubis.opIndeterminate
                    height: parent.height
                    radius: parent.radius
                    width: parent.width * Math.max(0, Math.min(1,
                      (anubis.opBusy ? anubis.opPct
                       : (anubis.opResult && anubis.opResult.ok === true
                          ? 100 : 0)) / 100))
                    color: anubis.opError !== "" ? root.urgent : root.accent
                    Behavior on width {
                      enabled: root.motion
                      NumberAnimation {
                        duration: root.motionBase
                        easing.type: Easing.OutQuart
                      }
                    }
                  }

                  Rectangle {
                    id: sweep
                    visible: anubis.opIndeterminate
                    height: parent.height
                    radius: parent.radius
                    width: parent.width * 0.28
                    color: Qt.alpha(root.accent, 0.75)
                    x: -width
                    NumberAnimation on x {
                      running: sweep.visible && root.motion
                      loops: Animation.Infinite
                      from: -sweep.width
                      to: progressTrack.width
                      duration: 900
                    }
                  }
                }

                Mono {
                  width: parent.width
                  wrapMode: Text.WordWrap
                  visible: anubis.opError !== ""
                  text: Model.noticeGlyph(anubis.opError) + "  " + anubis.opError
                  color: root.toneColor(Model.noticeTone(anubis.opError))
                }
                Mono {
                  width: parent.width
                  elide: Text.ElideMiddle
                  visible: anubis.opResult !== null
                    && anubis.opResult.ok === true
                  text: Model.GLYPH.check + "  wrote "
                    + (anubis.opResult ? String(anubis.opResult.out || "") : "")
                  color: Qt.alpha(root.accent, 0.85)
                }
              }
            }

            // ------------------------------------------------- inspector
            SectionCard {
              id: inspector
              width: centrePane.width
              // The MAC answer can come from two places: the inspect payload
              // (always null -- it holds no key) or a decrypt of this exact
              // container that already had to check it. The second is a fact
              // about a check that ran, so it is allowed to promote the chip.
              readonly property var macAttestation:
                anubis.macAttestationFor(anubis.inspectResult)
              readonly property string macTone:
                Model.macToneAttested(anubis.inspectResult,
                                      inspector.macAttestation)
              readonly property bool tampered:
                anubis.inspectResult !== null && inspector.macTone === "bad"
              // Accent means verified. The card only earns it when something
              // actually verified; a header nobody could check leaves the card
              // neutral rather than borrowing a pass.
              readonly property bool attested:
                anubis.inspectResult !== null && inspector.macTone === "good"

              title: Model.GLYPH.eye + "  CONTAINER INSPECTOR"
              note: anubis.inspectPath === "" ? "nothing selected"
                : Model.basename(anubis.inspectPath)
              tint: inspector.tampered ? Qt.alpha(root.urgent, 0.07)
                : (inspector.attested ? Qt.alpha(root.accent, 0.045)
                                      : Qt.alpha(root.fg, 0.035))
              edge: inspector.tampered ? Qt.alpha(root.urgent, 0.5)
                : (inspector.attested ? Qt.alpha(root.accent, 0.28)
                                      : Qt.alpha(root.fg, 0.09))
              // Idle, this card used to be a two-line strip with four hundred
              // pixels of nothing under it, which read as an unfinished layout
              // rather than as a console waiting for input. Given a floor it
              // becomes a well: the same waiting state, deliberately shaped.
              // The floor drops away the moment there is a header to show, so
              // it never pads a populated inspector.
              minHeight: anubis.inspectPath === "" && anubis.inspectError === ""
                && !firstRun.visible ? Style.spacing.searchablePopupMinHeight
                                     : 0

              Item {
                width: parent.width
                visible: anubis.inspectPath === "" && anubis.inspectError === ""
                implicitHeight: idleCol.implicitHeight
                Column {
                  id: idleCol
                  anchors.horizontalCenter: parent.horizontalCenter
                  anchors.top: parent.top
                  anchors.topMargin: root.padRail
                  width: Math.min(parent.width, Style.spacing.dropdownWidth * 2)
                  spacing: root.padGroup

                  Mono {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: Model.GLYPH.fileLock
                    font.pixelSize: Style.font.display
                    color: Qt.alpha(root.fg, 0.14)
                  }
                  Mono {
                    width: idleCol.width
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    text: "Pick a .anubis container above and its header is "
                      + "parsed here."
                    color: Qt.alpha(root.fg, 0.5)
                  }
                  Meta {
                    width: idleCol.width
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    text: "Reading a header decrypts nothing. An audit row on "
                      + "the right is also clickable -- it loads the file it "
                      + "wrote."
                    color: Qt.alpha(root.fg, 0.35)
                  }
                }
              }

              Mono {
                width: parent.width
                visible: anubis.inspectBusy
                text: "reading header..."
                color: Qt.alpha(root.fg, 0.55)
              }

              // Two different things wear two different faces. A legacy
              // container is an upgrade path; anything else that stops the
              // header being read is a genuine problem.
              Rectangle {
                width: parent.width
                visible: anubis.inspectError !== "" && !anubis.inspectBusy
                implicitHeight: noticeCol.implicitHeight + (root.padCard * 2)
                radius: Style.cornerRadius
                readonly property string tone:
                  Model.noticeTone(anubis.inspectError)
                color: tone === "notice" ? Qt.alpha(root.fg, 0.06)
                                         : Qt.alpha(root.urgent, 0.10)
                border.color: tone === "notice" ? Qt.alpha(root.fg, 0.22)
                                                : Qt.alpha(root.urgent, 0.5)
                border.width: 1

                Column {
                  id: noticeCol
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.top: parent.top
                  anchors.margins: root.padCard
                  spacing: root.padLine

                  Mono {
                    width: noticeCol.width
                    wrapMode: Text.WordWrap
                    text: Model.noticeGlyph(anubis.inspectError) + "  "
                      + Model.noticeHeading(anubis.inspectError)
                    color: root.toneColor(Model.noticeTone(anubis.inspectError))
                    font.bold: true
                    font.pixelSize: Style.font.bodySmall
                  }
                  Mono {
                    width: noticeCol.width
                    wrapMode: Text.WordWrap
                    text: anubis.inspectError
                    color: Qt.alpha(root.fg, 0.75)
                  }
                  Mono {
                    width: noticeCol.width
                    wrapMode: Text.WordWrap
                    visible: text !== ""
                    text: Model.noticeAdvice(anubis.inspectError)
                    color: Qt.alpha(root.fg, 0.5)
                  }
                }
              }

              // The two verdicts. They answer different questions and are
              // allowed to disagree, so they are never merged into one badge.
              Row {
                width: parent.width
                spacing: root.padCard
                visible: anubis.inspectResult !== null

                Rectangle {
                  id: macPanel
                  width: (parent.width - root.padCard) / 2
                  implicitHeight: macCol.implicitHeight + (root.padCard * 2)
                  height: implicitHeight
                  radius: Style.cornerRadius
                  color: Qt.alpha(root.toneColor(inspector.macTone), 0.12)
                  border.color: Qt.alpha(root.toneColor(inspector.macTone), 0.6)
                  border.width: inspector.macTone === "bad" ? 2 : 1

                  Column {
                    id: macCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: root.padCard
                    spacing: root.padLine
                    Mono {
                      width: macCol.width
                      wrapMode: Text.WordWrap
                      text: (inspector.macTone === "good"
                             ? Model.GLYPH.shieldCheck
                             : (inspector.macTone === "bad"
                                ? Model.GLYPH.shieldAlert : Model.GLYPH.shield))
                        + "  " + Model.macLabelAttested(anubis.inspectResult,
                                                   inspector.macAttestation)
                      color: root.toneColor(inspector.macTone)
                      font.bold: true
                      font.pixelSize: Style.font.bodySmall
                    }
                    Mono {
                      width: macCol.width
                      wrapMode: Text.WordWrap
                      text: Model.macExplanationAttested(anubis.inspectResult,
                                                   inspector.macAttestation)
                      color: Qt.alpha(root.fg, 0.45)
                    }
                  }
                }

                Rectangle {
                  id: sigPanel
                  // A verify that actually ran over these exact bytes may
                  // promote this chip, exactly as a decrypt promotes the
                  // header MAC. Presence alone never does: inspect reads the
                  // header, and a signature is only checked by hashing the
                  // whole payload.
                  readonly property var attested:
                    anubis.sigAttestedFor(anubis.inspectResult)
                  readonly property string sigTone:
                    Model.signatureToneAttested(anubis.inspectResult,
                                                sigPanel.attested)
                  readonly property string paintTone:
                    sigPanel.sigTone === "none" ? "neutral" : sigPanel.sigTone
                  readonly property string signerFp:
                    Model.signerFingerprint(anubis.inspectResult)
                  // Compared ONLY against each identity's signing_fingerprint.
                  // A recipient fingerprint is a different hash of a different
                  // key and comparing the two would manufacture a falsehood.
                  readonly property var signer:
                    Model.signedByIdentity(anubis.status, anubis.inspectResult)
                  width: (parent.width - root.padCard) / 2
                  implicitHeight: sigCol.implicitHeight + (root.padCard * 2)
                  height: implicitHeight
                  radius: Style.cornerRadius
                  color: Qt.alpha(root.toneColor(sigPanel.paintTone), 0.10)
                  border.color: Qt.alpha(root.toneColor(sigPanel.paintTone), 0.5)
                  border.width: sigPanel.sigTone === "bad" ? 2 : 1

                  Column {
                    id: sigCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: root.padCard
                    spacing: root.padLine
                    Mono {
                      width: sigCol.width
                      wrapMode: Text.WordWrap
                      text: (sigPanel.sigTone === "good"
                             ? Model.GLYPH.shieldCheck
                             : (sigPanel.sigTone === "bad"
                                ? Model.GLYPH.shieldAlert
                                : Model.GLYPH.signature))
                        + "  " + Model.signatureLabelAttested(
                                   anubis.inspectResult, sigPanel.attested)
                      color: root.toneColor(sigPanel.paintTone)
                      font.bold: true
                      font.pixelSize: Style.font.bodySmall
                    }
                    Mono {
                      width: sigCol.width
                      wrapMode: Text.WordWrap
                      // Attribution keys off whether a signer fingerprint
                      // EXISTS, never off whether the signature has been
                      // checked. Keying it on tone once made an unverified
                      // signature report "no signature to attribute", which
                      // is simply false: there is a signer, it just has not
                      // been verified yet.
                      text: sigPanel.signer
                        ? "signed by your identity \""
                          + sigPanel.signer.name + "\""
                        : (sigPanel.signerFp !== ""
                           ? "signer is not an identity in this vault -- "
                             + "check the fingerprint out of band before "
                             + "trusting it"
                           : "no signature to attribute")
                      color: sigPanel.signer ? Qt.alpha(root.accent, 0.85)
                                             : Qt.alpha(root.fg, 0.5)
                    }
                    Mono {
                      width: sigCol.width
                      wrapMode: Text.WordWrap
                      text: Model.signatureExplanationAttested(
                              anubis.inspectResult, sigPanel.attested)
                      color: Qt.alpha(root.fg, 0.45)
                    }
                    Mono {
                      width: sigCol.width
                      wrapMode: Text.WordWrap
                      text: "A signature says who wrote the file. The header "
                        + "MAC does not."
                      color: Qt.alpha(root.fg, 0.32)
                    }
                    // Offered only while there is something to check and no
                    // answer yet. Verifying needs no key, so it is offered
                    // even for a container this vault cannot decrypt.
                    ActionButton {
                      visible: sigPanel.sigTone === "notice"
                      glyph: Model.GLYPH.shieldCheck
                      label: anubis.verifyBusy ? "verifying" : "verify signature"
                      available: !anubis.verifyBusy && !anubis.engineMissing
                      onActivated: anubis.verifySignature(anubis.inspectPath)
                    }
                  }
                }
              }

              // The engine reports the signer as a fingerprint already
              // (signer_fingerprint), so there is no raw key to offer. It is
              // labelled "signer" so it can never be mistaken for the
              // recipient fingerprints shown in the rails.
              FingerprintRow {
                width: parent.width
                visible: Model.signerFingerprint(anubis.inspectResult) !== ""
                kind: "signer"
                fingerprint: Model.signerFingerprint(anubis.inspectResult)
                fullKey: ""
              }

              // Format string comes straight from the engine's JSON, never
              // from a constant here: the wire format versions on its own
              // schedule and this panel must not drift from it.
              Repeater {
                model: anubis.inspectResult
                  ? Model.inspectFacts(anubis.inspectResult) : []
                delegate: FieldRow {
                  required property var modelData
                  width: parent.width
                  label: modelData.label
                  value: modelData.value
                  tone: modelData.tone
                }
              }

              Mono {
                width: parent.width
                visible: anubis.inspectResult !== null && text !== ""
                text: Model.chunkNote(anubis.inspectResult)
                color: Qt.alpha(root.fg, 0.35)
              }

              Mono {
                width: parent.width
                visible: Model.stanzaRows(anubis.inspectResult).length > 0
                text: "STANZAS"
                color: Qt.alpha(root.fg, 0.45)
                font.bold: true
              }
              Repeater {
                model: Model.stanzaRows(anubis.inspectResult)
                delegate: Item {
                  id: stanzaRow
                  required property var modelData
                  width: parent.width
                  implicitHeight: stanzaType.implicitHeight + root.padLine
                  Mono {
                    id: stanzaType
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    text: Model.GLYPH.atom + "  "
                      + String(stanzaRow.modelData.type)
                    color: Qt.alpha(root.fg, 0.75)
                  }
                  Mono {
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    text: String(stanzaRow.modelData.recipients)
                      + (Number(stanzaRow.modelData.recipients) === 1
                         ? " recipient" : " recipients")
                    color: root.accent
                  }
                }
              }
            }
          }
        }

        // ======================================================= RIGHT RAIL
        Flickable {
          id: rightScroll
          anchors.top: parent.top
          anchors.bottom: parent.bottom
          anchors.right: parent.right
          width: body.cols.right
          contentWidth: width
          contentHeight: rightPane.implicitHeight
          clip: true
          pixelAligned: true
          boundsBehavior: Flickable.StopAtBounds
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          Column {
            id: rightPane
            width: rightScroll.width - root.padGroup
            spacing: body.gap

            // ------------------------------------------------------ ledger
            SectionCard {
              width: rightPane.width
              recessed: true
              title: Model.GLYPH.pulse + "  LEDGER"
              note: anubis.status
                ? Model.timeAgo(anubis.status.generated, root.nowMs) : ""

              // Label left, count right, on the rail's full width -- not a
              // two-column grid whose second column floated in the middle of
              // the card with the numbers unaligned against everything else.
              Repeater {
                model: [
                  { label: "encrypted", value: String(anubis.counts.encrypt),
                    tone: "neutral" },
                  { label: "decrypted", value: String(anubis.counts.decrypt),
                    tone: "neutral" },
                  { label: "failed", value: String(anubis.counts.failed),
                    tone: anubis.counts.failed > 0 ? "bad" : "unknown" },
                  { label: "identities",
                    value: String(anubis.identities.length), tone: "good" },
                  { label: "recipients",
                    value: String(anubis.recipients.length), tone: "good" }
                ]
                delegate: FieldRow {
                  required property var modelData
                  width: parent.width
                  label: modelData.label
                  value: modelData.value
                  tone: modelData.tone
                  strong: true
                }
              }

              Legend {
                width: parent.width
                topPadding: root.padLine
                text: "ACTIVITY"
              }

              Canvas {
                id: activityStrip
                width: parent.width
                height: Style.spacing.controlHeight + root.padCard

                onPaint: {
                  var ctx = getContext("2d")
                  ctx.reset()
                  ctx.clearRect(0, 0, width, height)

                  var slots = 40
                  var series = Model.activitySeries(anubis.status, slots)
                  var bw = width / slots

                  // Baseline: an empty ledger reads as a ledger, not as a
                  // rendering failure.
                  ctx.fillStyle = Qt.alpha(root.fg, 0.10)
                  ctx.fillRect(0, height - 1, width, 1)
                  if (series.length === 0) return

                  var maxV = Model.activityMax(series)
                  var offset = slots - series.length
                  for (var i = 0; i < series.length; i++) {
                    var v = series[i].bytes
                    var h = v > 0
                      ? Math.max(2, (Math.log(1 + v) / Math.log(1 + maxV))
                                 * (height - 4))
                      : 2
                    ctx.fillStyle = series[i].ok
                      ? Qt.alpha(root.accent, 0.85) : root.urgent
                    ctx.fillRect((offset + i) * bw, height - h,
                                 Math.max(1, bw - 1.5), h)
                  }
                }

                Connections {
                  target: anubis
                  function onStatusChanged() { activityStrip.requestPaint() }
                }
              }

              Meta {
                width: parent.width
                wrapMode: Text.WordWrap
                text: Model.activitySummary(anubis.status, 40)
                color: Qt.alpha(root.fg, 0.42)
              }
              Meta {
                width: parent.width
                wrapMode: Text.WordWrap
                text: "One bar per operation, log scale, bytes. A failed one "
                  + "is drawn in the urgent colour at minimum height, so it is "
                  + "never an empty gap."
                color: Qt.alpha(root.fg, 0.28)
              }
            }

            // ---------------------------------------------- audit timeline
            SectionCard {
              width: rightPane.width
              recessed: true
              title: Model.GLYPH.history + "  AUDIT TIMELINE"
              note: anubis.recentOps.length + " rows"

              EmptyWell {
                visible: anubis.recentOps.length === 0
                glyph: Model.GLYPH.history
                headline: anubis.engineMissing ? "no engine" : "nothing yet"
                body: anubis.engineMissing
                  ? "The audit log is a file the engine appends to. Without "
                    + "the engine there is nothing to read."
                  : "Every encrypt, decrypt and keygen lands here with its "
                    + "size, duration and verdict."
                nextStep: anubis.engineMissing ? "" : "the first operation "
                  + "you run writes the first row"
                nextStepGlyph: Model.GLYPH.timer
                actionable: false
              }

              // Provenance, stated once and quietly. The append-only log is
              // the engine's, not this panel's; SIA reads the same file.
              Meta {
                width: parent.width
                wrapMode: Text.Wrap
                visible: !anubis.engineMissing
                text: "Appended by the engine to "
                  + anubis.stateDir + "/audit.jsonl. Any log tailer "
                  + "can consume it; no key material ever enters it."
                color: Qt.alpha(root.fg, 0.28)
              }

              Repeater {
                model: anubis.recentOps
                delegate: Rectangle {
                  id: auditRow
                  required property var modelData
                  readonly property bool ok: auditRow.modelData.ok !== false
                  readonly property string errorTone:
                    Model.noticeTone(auditRow.modelData.error)
                  width: parent.width
                  implicitHeight: auditCol.implicitHeight + (root.padCard * 2)
                  radius: Style.cornerRadius
                  color: auditArea.containsMouse
                    ? Qt.alpha(root.fg, 0.06) : "transparent"
                  border.color: auditRow.ok ? Qt.alpha(root.fg, 0.08)
                    : (auditRow.errorTone === "notice"
                       ? Qt.alpha(root.fg, 0.22)
                       : Qt.alpha(root.urgent, 0.35))
                  border.width: 1

                  Column {
                    id: auditCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: root.padCard
                    spacing: root.padTight

                    Item {
                      width: auditCol.width
                      height: auditName.implicitHeight
                      Mono {
                        id: auditGlyph
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        text: Model.opGlyph(String(auditRow.modelData.op))
                        font.pixelSize: root.typeMeta
                        color: auditRow.ok ? root.accent
                          : root.toneColor(auditRow.errorTone)
                      }
                      Mono {
                        id: auditName
                        anchors.left: auditGlyph.right
                        anchors.leftMargin: root.padGroup
                        anchors.right: auditVerdict.left
                        anchors.rightMargin: root.padGroup
                        anchors.verticalCenter: parent.verticalCenter
                        elide: Text.ElideMiddle
                        text: Model.basename(
                          String(auditRow.modelData.path || ""))
                        color: root.fg
                        font.pixelSize: root.typeBody
                      }
                      Meta {
                        id: auditVerdict
                        anchors.right: parent.right
                        anchors.baseline: auditName.baseline
                        text: auditRow.ok ? "ok"
                          : (auditRow.errorTone === "notice"
                             ? "unsupported" : "FAILED")
                        color: auditRow.ok ? Qt.alpha(root.accent, 0.8)
                          : root.toneColor(auditRow.errorTone)
                        font.bold: !auditRow.ok
                          && auditRow.errorTone !== "notice"
                      }
                    }

                    // Two facts, two ends of the row. Concatenated with a pipe
                    // these overran the rail and the relative time -- the part
                    // a reader actually scans -- was what got elided.
                    Item {
                      width: auditCol.width
                      height: auditStamp.implicitHeight
                      Meta {
                        id: auditStamp
                        anchors.left: parent.left
                        anchors.top: parent.top
                        text: Model.stampLocal(auditRow.modelData.ts)
                        color: Qt.alpha(root.fg, 0.42)
                      }
                      Meta {
                        anchors.right: parent.right
                        anchors.baseline: auditStamp.baseline
                        text: Model.timeAgo(auditRow.modelData.ts, root.nowMs)
                        color: Qt.alpha(root.fg, 0.42)
                      }
                    }
                    // Wraps rather than elides. A throughput cut to "517..."
                    // is a number the reader cannot use; a second line is.
                    Meta {
                      width: auditCol.width
                      wrapMode: Text.WordWrap
                      visible: text !== ""
                      text: Model.opSummary(auditRow.modelData)
                      color: Qt.alpha(root.fg, 0.42)
                    }
                    Meta {
                      width: auditCol.width
                      elide: Text.ElideMiddle
                      visible: text !== ""
                      text: String(auditRow.modelData.out || "")
                      color: Qt.alpha(root.fg, 0.28)
                    }
                    Mono {
                      width: auditCol.width
                      wrapMode: Text.WordWrap
                      visible: !auditRow.ok && text !== ""
                      text: String(auditRow.modelData.error || "")
                      color: auditRow.errorTone === "notice"
                        ? Qt.alpha(root.fg, 0.6) : Qt.alpha(root.urgent, 0.9)
                    }
                  }

                  MouseArea {
                    id: auditArea
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      var target = String(auditRow.modelData.out || "")
                      if (target === "" || !Model.isVaultFile(target))
                        target = String(auditRow.modelData.path || "")
                      if (target !== "") root.selectPath(target)
                    }
                  }
                }
              }
            }

            // ------------------------------------------------- boundaries
            SectionCard {
              width: rightPane.width
              recessed: true
              title: Model.GLYPH.seal + "  WHAT THIS PANEL IS"

              // Reference prose, so it sits at metadata weight. Every claim
              // here is load-bearing and none of it changes, which is exactly
              // what should recede once it has been read once.
              Meta {
                width: parent.width
                wrapMode: Text.WordWrap
                text: "It spawns the anubis binary, reads its JSON, and draws "
                  + "it. It holds no key material, derives no secret, and "
                  + "reaches no verification verdict of its own."
                color: Qt.alpha(root.fg, 0.48)
              }
              Meta {
                width: parent.width
                wrapMode: Text.WordWrap
                text: "A field the engine did not state is rendered as NOT "
                  + "STATED, never as a pass. A failed poll clears the status "
                  + "rather than leaving the last good one on screen."
                color: Qt.alpha(root.fg, 0.48)
              }
              Meta {
                width: parent.width
                wrapMode: Text.WordWrap
                text: "The urgent colour means authentication failed. An "
                  + "unsupported legacy container is drawn as a plain notice, "
                  + "because an old file is not a tampered file."
                color: Qt.alpha(root.fg, 0.48)
              }
              Meta {
                width: parent.width
                wrapMode: Text.WordWrap
                text: "Fingerprints are 80 bits of SHA-256 over the recipient "
                  + "payload. They are the handle because a 2573-character "
                  + "bech32 string is past the length where its checksum "
                  + "still guarantees error detection."
                color: Qt.alpha(root.fg, 0.48)
              }
              FieldRow {
                width: parent.width
                label: "AEAD"
                value: anubis.suite && anubis.suite.aead
                  ? String(anubis.suite.aead) : "not stated"
                tone: anubis.suite && anubis.suite.aead ? "neutral" : "unknown"
              }
              FieldRow {
                width: parent.width
                label: "KDF"
                value: anubis.suite && anubis.suite.kdf
                  ? String(anubis.suite.kdf) : "not stated"
                tone: anubis.suite && anubis.suite.kdf ? "neutral" : "unknown"
              }
              FieldRow {
                width: parent.width
                label: "wire format"
                value: Model.wireFormat(anubis.suite) === ""
                  ? "not stated" : Model.wireFormat(anubis.suite)
                tone: Model.wireFormat(anubis.suite) === "" ? "unknown" : "neutral"
              }
              FieldRow {
                width: parent.width
                label: "dependencies"
                // Three states, not two. Absent is not "native libraries".
                value: !anubis.suite || anubis.suite.pure_rust === undefined
                  ? "not stated"
                  : (anubis.suite.pure_rust === true ? "pure Rust"
                                                     : "native libraries")
                tone: !anubis.suite || anubis.suite.pure_rust === undefined
                  ? "unknown" : "neutral"
              }
              FieldRow {
                width: parent.width
                label: "engine"
                value: anubis.enginePath === "" ? "not found" : anubis.enginePath
                tone: anubis.enginePath === "" ? "unknown" : "neutral"
              }
              FieldRow {
                width: parent.width
                label: "config"
                value: anubis.configDir
              }
              FieldRow {
                width: parent.width
                label: "state"
                value: anubis.stateDir
              }
              FieldRow {
                width: parent.width
                label: "poll"
                value: "every " + root.opts.pollIntervalSec + "s"
              }
              FieldRow {
                width: parent.width
                label: "overwrite"
                value: root.opts.confirmOverwrite ? "confirm first"
                                                  : "no confirmation"
                tone: root.opts.confirmOverwrite ? "neutral" : "unknown"
              }
              Mono {
                width: parent.width
                wrapMode: Text.WordWrap
                visible: anubis.statusError !== ""
                text: Model.GLYPH.alert + "  " + anubis.statusError
                color: root.urgent
              }
            }
          }
        }
      }

    // ======================================================================
    // sheets
    // ======================================================================
    //
    // Settings and provenance, over the cockpit rather than beside it. Neither
    // one stops the engine: an operation launched before a sheet opened keeps
    // streaming behind it and the progress bar keeps moving, because a sheet
    // that quietly suspended a running decrypt would be lying about what the
    // machine is doing.

    // -------------------------------------------------------- preferences
    Item {
      id: prefSheet
      anchors.fill: parent
      visible: opacity > 0
      opacity: root.showPreferences ? 1.0 : 0.0
      Behavior on opacity {
        enabled: root.motion
        NumberAnimation { duration: root.motionBase; easing.type: Easing.OutQuart }
      }

      Rectangle {
        anchors.fill: parent
        color: Qt.alpha(Color.background, 0.90)
        MouseArea {
          anchors.fill: parent
          onClicked: root.showPreferences = false
        }
      }

      // Swallows clicks that land on the card but on none of its controls.
      // It sits below the card, so the card's own buttons are still reached
      // first, and above the backdrop, so a stray click never dismisses the
      // sheet somebody is in the middle of using.
      // The card's own fill is a 3.5% tint, which is right on the cockpit
      // and wrong over it -- the rails read straight through. This is the
      // ground it needs to be a sheet rather than a wash.
      Rectangle {
        anchors.fill: prefCard
        radius: Style.cornerRadius
        color: Color.background
      }

      MouseArea {
        anchors.fill: prefCard
        onClicked: {}
      }

      SectionCard {
        id: prefCard
        anchors.centerIn: parent
        width: Math.min(parent.width - (root.padRail * 4), root.padRail * 30)
        emphasis: true
        title: Model.GLYPH.cog + "  SETTINGS"
        note: "written to " + App.configPath

        Legend {
          width: parent.width
          text: "ENGINE"
        }
        PrefStepper {
          width: parent.width
          label: "status poll interval"
          suffix: "s"
          minimum: 5
          maximum: 600
          step: 5
          value: root.opts.pollIntervalSec
          hint: "how often `anubis status --json` is re-read"
          onCommitted: function (v) { App.setSetting("pollIntervalSec", v) }
        }
        PrefToggle {
          width: parent.width
          label: "confirm before overwriting"
          checked: root.opts.confirmOverwrite
          hint: root.opts.confirmOverwrite
            ? "an existing output takes a second, explicit click"
            : "an existing output is replaced without asking"
          // Turning the gate off is the one setting here that can lose data,
          // so the surface says what it now does rather than only that it is
          // off.
          warn: !root.opts.confirmOverwrite
          onToggled: function (v) { App.setSetting("confirmOverwrite", v) }
        }
        PrefText {
          width: parent.width
          label: "default identity"
          value: root.opts.defaultIdentity
          placeholder: "the engine decides"
          hint: anubis.identities.length === 0
            ? "no identities yet -- generate one in the vault rail"
            : "known: " + Model.identityNames(anubis.status).join(", ")
          onCommitted: function (v) { App.setSetting("defaultIdentity", v) }
        }

        Rectangle {
          width: parent.width
          height: 1
          color: Qt.alpha(root.fg, 0.10)
        }

        Legend {
          width: parent.width
          text: "SURFACE"
        }
        PrefToggle {
          width: parent.width
          label: "motion"
          checked: root.opts.motionEnabled
          hint: "fades and colour ramps; off makes every state change snap"
          onToggled: function (v) { App.setSetting("motionEnabled", v) }
        }
        PrefStepper {
          width: parent.width
          label: "base font size"
          suffix: "px"
          minimum: 8
          maximum: 24
          step: 1
          value: Style.fontBaseSize
          hint: "the whole type and spacing scale is derived from this"
          onCommitted: function (v) { App.setSetting("fontBaseSize", v) }
        }
        PrefStepper {
          width: parent.width
          label: "corner radius"
          suffix: "px"
          minimum: 0
          maximum: 16
          step: 1
          value: Style.cornerRadius
          hint: "0 is square"
          onCommitted: function (v) { App.setSetting("cornerRadius", v) }
        }

        Rectangle {
          width: parent.width
          height: 1
          color: Qt.alpha(root.fg, 0.10)
        }

        Legend {
          width: parent.width
          text: "SHORTCUTS"
        }
          // Key caps, not a sentence of pipes: the key gets the plate and the
        // label sits beside it. The legend lives here rather than under the
        // cockpit because it is reference material -- read once, then it was
        // paying rent in screen space at the bottom of every session.
        Flow {
          width: parent.width
          spacing: root.padRail

          Repeater {
            model: [
              { key: "Ctrl+O", what: "choose a file" },
              { key: "Ctrl+E", what: "encrypt" },
              { key: "Ctrl+D", what: "decrypt" },
              { key: "Ctrl+G", what: "generate identity" },
              { key: "Ctrl+R", what: "poll" },
              { key: "Ctrl+,", what: "settings" },
              { key: "F1", what: "about" },
              { key: "Esc", what: "cancel what is pending" },
              { key: "Ctrl+Q", what: "quit" },
              { key: "Tab", what: "walk the controls" },
              { key: "click", what: "a fingerprint copies it" }
            ]
            delegate: Row {
              required property var modelData
              spacing: root.padGroup

              Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                implicitWidth: capText.implicitWidth + (root.padGroup * 2)
                implicitHeight: capText.implicitHeight + root.padLine
                radius: Style.cornerRadius
                color: Qt.alpha(root.fg, 0.05)
                border.color: Qt.alpha(root.fg, 0.16)
                border.width: 1
                Meta {
                  id: capText
                  anchors.centerIn: parent
                  text: String(parent.parent.modelData.key)
                  font.bold: true
                  color: Qt.alpha(root.fg, 0.6)
                }
              }
              Meta {
                anchors.verticalCenter: parent.verticalCenter
                text: String(parent.modelData.what)
                color: Qt.alpha(root.fg, 0.38)
              }
            }
          }
        }

        Item {
          width: parent.width
          height: prefClose.implicitHeight
          ActionButton {
            id: prefClose
            anchors.right: parent.right
            glyph: Model.GLYPH.check
            label: "done"
            primary: true
            onActivated: root.showPreferences = false
          }
        }
      }
    }

    // -------------------------------------------------------------- about
    Item {
      id: aboutSheet
      anchors.fill: parent
      visible: opacity > 0
      opacity: root.showAbout ? 1.0 : 0.0
      Behavior on opacity {
        enabled: root.motion
        NumberAnimation { duration: root.motionBase; easing.type: Easing.OutQuart }
      }

      Rectangle {
        anchors.fill: parent
        color: Qt.alpha(Color.background, 0.90)
        MouseArea {
          anchors.fill: parent
          onClicked: root.showAbout = false
        }
      }

      Rectangle {
        anchors.fill: aboutCard
        radius: Style.cornerRadius
        color: Color.background
      }

      MouseArea {
        anchors.fill: aboutCard
        onClicked: {}
      }

      SectionCard {
        id: aboutCard
        anchors.centerIn: parent
        width: Math.min(parent.width - (root.padRail * 4), root.padRail * 30)
        emphasis: true
        title: Model.GLYPH.shieldKey + "  ANUBIS VAULT"

        // Two versions, never one. The application and the engine ship
        // separately and can disagree, and the engine's is the one that
        // determines what a container actually is.
        FieldRow {
          width: parent.width
          label: "application"
          value: "v" + App.appVersion
        }
        FieldRow {
          width: parent.width
          label: "engine"
          value: anubis.version !== "" ? "v" + anubis.version
            : (anubis.engineMissing ? "not installed" : "version unknown")
          tone: anubis.version !== "" ? "neutral" : "unknown"
        }
        FieldRow {
          width: parent.width
          label: "engine path"
          value: anubis.enginePath === "" ? "not found" : anubis.enginePath
          tone: anubis.enginePath === "" ? "unknown" : "neutral"
        }
        FieldRow {
          width: parent.width
          label: "suite"
          value: anubis.suite !== null ? Model.suiteBadge(anubis.suite)
                                       : "not stated"
          tone: anubis.suite !== null ? "neutral" : "unknown"
        }
        FieldRow {
          width: parent.width
          label: "licence"
          value: "MIT OR Apache-2.0"
        }

        Rectangle {
          width: parent.width
          height: 1
          color: Qt.alpha(root.fg, 0.10)
        }

        Meta {
          width: parent.width
          wrapMode: Text.WordWrap
          text: "This application spawns the anubis binary, reads its JSON, "
            + "and draws it. It holds no key material, derives no secret, "
            + "performs no cryptography, and reaches no verification verdict "
            + "of its own."
          color: Qt.alpha(root.fg, 0.55)
        }
        Meta {
          width: parent.width
          wrapMode: Text.WordWrap
          text: "Every cryptographic claim on screen is the engine's own "
            + "statement, carried through verbatim. A field the engine did "
            + "not state is rendered as NOT STATED, never as a pass."
          color: Qt.alpha(root.fg, 0.55)
        }

        Item {
          width: parent.width
          height: aboutClose.implicitHeight
          ActionButton {
            anchors.left: parent.left
            glyph: Model.GLYPH.folder
            label: "state directory"
            onActivated: App.revealInFileManager(anubis.stateDir + "/")
          }
          ActionButton {
            id: aboutClose
            anchors.right: parent.right
            glyph: Model.GLYPH.check
            label: "done"
            primary: true
            onActivated: root.showAbout = false
          }
        }
      }
    }

    // ------------------------------------------------------- quit confirm
    //
    // The only thing that makes quitting a question. A half-written output is
    // the engine's to clean up, so the operator is told what is running and
    // asked, rather than having the process killed underneath them.
    //
    // The operation can finish while the question is still on screen -- this
    // sheet does not stop the engine -- and when it does, the sheet says so
    // and changes what it is offering. Leaving \"AN OPERATION IS RUNNING\" up
    // after the operation ended would make this surface assert something that
    // is no longer true, which is the one thing it is not allowed to do.
    Item {
      id: quitConfirm
      anchors.fill: parent
      visible: opacity > 0
      opacity: quitConfirm.asking ? 1.0 : 0.0
      property bool asking: false

      function open() { asking = true }

      Behavior on opacity {
        enabled: root.motion
        NumberAnimation { duration: root.motionFast; easing.type: Easing.OutQuart }
      }

      Rectangle {
        anchors.fill: parent
        color: Qt.alpha(Color.background, 0.88)
        MouseArea {
          anchors.fill: parent
          onClicked: quitConfirm.asking = false
        }
      }

      Rectangle {
        anchors.fill: quitCard
        radius: Style.cornerRadius
        color: Color.background
      }

      MouseArea {
        anchors.fill: quitCard
        onClicked: {}
      }

      SectionCard {
        id: quitCard
        anchors.centerIn: parent
        width: Math.min(parent.width - (root.padRail * 4), root.padRail * 26)
        emphasis: true
        title: anubis.opBusy
          ? Model.GLYPH.alert + "  AN OPERATION IS RUNNING"
          : Model.GLYPH.check + "  THE OPERATION FINISHED"

        Mono {
          width: parent.width
          wrapMode: Text.WordWrap
          text: anubis.opBusy
            ? (anubis.opKind === ""
               ? "The engine is working."
               : "A " + anubis.opKind + " of " + Model.basename(anubis.opInput)
                 + " is in progress.")
            : "It finished while this was on screen. Nothing is running now."
          color: root.fg
        }
        Meta {
          width: parent.width
          wrapMode: Text.WordWrap
          text: anubis.opBusy
            ? "Quitting sends the engine SIGTERM. Whatever it has already "
              + "written to " + Model.basename(anubis.opOutput) + " stays on "
              + "disk, and a partial container is not a container."
            : "The console behind this sheet has the result. Quitting now "
              + "leaves nothing half-written."
          color: Qt.alpha(root.fg, 0.55)
        }

        Item {
          width: parent.width
          height: quitStay.implicitHeight
          ActionButton {
            id: quitStay
            anchors.left: parent.left
            glyph: anubis.opBusy ? Model.GLYPH.timer : Model.GLYPH.eye
            label: anubis.opBusy ? "let it finish" : "stay"
            onActivated: quitConfirm.asking = false
          }
          ActionButton {
            anchors.right: parent.right
            glyph: Model.GLYPH.close
            // Terminating and quitting are one act only while something is
            // running. Once nothing is, this is an ordinary quit and must not
            // keep offering to kill a process that has already exited.
            label: anubis.opBusy ? "terminate and quit" : "quit"
            tone: anubis.opBusy ? root.urgent : root.fg
            onActivated: {
              if (anubis.opBusy) anubis.abortOperation()
              Qt.quit()
            }
          }
        }
      }
    }

    }
  }
}

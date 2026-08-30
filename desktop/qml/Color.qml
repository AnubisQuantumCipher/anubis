pragma Singleton
import QtQuick
import Anubis

// The four colours this surface is allowed to use, and nothing else.
//
// They come from the desktop's theme when there is one, so the vault looks
// like the rest of the machine rather than inventing its own palette. A
// `theme` block in the settings file overrides any of them.
//
// The narrowness is the point. `urgent` means AUTHENTICATION FAILED and is
// never spent on anything else; `accent` means the engine verified something.
// A palette with more colours in it would make both of those claims cheaper.
QtObject {
  id: root

  readonly property var values: App.palette

  readonly property color foreground: root.values.foreground
  readonly property color background: root.values.background
  readonly property color accent: root.values.accent
  readonly property color urgent: root.values.urgent
  readonly property color muted: root.values.muted
}

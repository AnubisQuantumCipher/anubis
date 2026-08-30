// Everything the vault needs from the desktop that is not a child process.
//
// Locating the engine, the clipboard, existence checks, settings, and the
// theme palette. Each one used to be a subprocess or a compositor service the
// plugin borrowed from its shell host; a standalone application owns them, so
// the only binary this program still shells out to is `anubis` itself.
//
// Nothing here performs cryptography or reaches a verification verdict. It
// reads files, writes one settings file, and answers questions about the
// machine.
#pragma once

#include <QColor>
#include <QFileSystemWatcher>
#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class App : public QObject {
  Q_OBJECT
  QML_ELEMENT
  QML_SINGLETON

  Q_PROPERTY(QString home READ home CONSTANT)
  Q_PROPERTY(QString configPath READ configPath CONSTANT)
  Q_PROPERTY(QString appVersion READ appVersion CONSTANT)
  Q_PROPERTY(QVariantMap settings READ settings NOTIFY settingsChanged)
  Q_PROPERTY(QVariantMap palette READ palette NOTIFY paletteChanged)
  Q_PROPERTY(QString pendingOpenPath READ pendingOpenPath NOTIFY openPathRequested)

public:
  explicit App(QObject* parent = nullptr);

  static App* instance();

  [[nodiscard]] QString home() const;
  [[nodiscard]] QString configPath() const;
  [[nodiscard]] QString appVersion() const;

  // Kept for the QML the plugin was written against, which asked the shell
  // host for HOME rather than assuming one.
  Q_INVOKABLE QString env(const QString& name) const;

  // Where `anubis` actually is. Checked in the places cargo and the
  // distribution packages put one, then on PATH. Empty means absent, which is
  // an ordinary state on a machine that has not installed the engine yet.
  Q_INVOKABLE QString locateEngine() const;

  // Content check for a candidate engine, so a different program that happens
  // to be called `anubis` is never driven as the engine.
  [[nodiscard]] bool looksLikeTheEngine(const QString& path) const;

  // Replaces the `test -e` subprocess the overwrite gate used to spawn. Says
  // nothing about contents and touches nothing.
  Q_INVOKABLE bool fileExists(const QString& path) const;
  Q_INVOKABLE bool isDirectory(const QString& path) const;

  // A full ANUBIS recipient runs to thousands of characters, so the clipboard
  // is the only sane way to move one.
  Q_INVOKABLE void copyToClipboard(const QString& text) const;

  Q_INVOKABLE QString pathFromUrl(const QString& url) const;
  Q_INVOKABLE QString urlFromPath(const QString& path) const;
  Q_INVOKABLE QString parentDirectory(const QString& path) const;

  // Open the containing directory in whatever the desktop registered. The
  // file itself is never opened: handing a container to an unknown handler is
  // not this program's decision to make.
  Q_INVOKABLE bool revealInFileManager(const QString& path) const;

  [[nodiscard]] QVariantMap settings() const { return mSettings; }
  Q_INVOKABLE void setSetting(const QString& key, const QVariant& value);
  Q_INVOKABLE void reloadSettings();

  [[nodiscard]] QVariantMap palette() const { return mPalette; }
  Q_INVOKABLE void reloadPalette();

  // Window geometry, remembered between runs. Stored beside the settings so
  // there is one file to delete to get a clean slate.
  Q_INVOKABLE void rememberGeometry(int width, int height, bool maximized);

  [[nodiscard]] QString pendingOpenPath() const { return mPendingOpenPath; }
  Q_INVOKABLE void clearPendingOpenPath();

  // Called by the single-instance server when a second launch hands this one
  // a file to look at.
  void requestOpenPath(const QString& path);

signals:
  void settingsChanged();
  void paletteChanged();
  void openPathRequested(const QString& path);
  void raiseRequested();

private:
  void loadSettings();
  void writeSettings();
  void rewatchSettings();

  QFileSystemWatcher mWatcher;
  QVariantMap mSettings;
  QVariantMap mPalette;
  QString mPendingOpenPath;
};

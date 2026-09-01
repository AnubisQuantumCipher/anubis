// A watched file, API-compatible with Quickshell.Io's FileView.
//
// The engine rewrites its status file after every operation, including ones
// run from a terminal. Watching that file is what keeps the vault current
// without shortening the poll interval, so the surface is right within a
// moment of a change it did not itself cause.
//
// A missing file is an ordinary state here, not an error: a machine that has
// never run the engine simply has no status file yet.
#pragma once

#include <QFileSystemWatcher>
#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class FileView : public QObject {
  Q_OBJECT
  QML_ELEMENT

  Q_PROPERTY(QString path READ path WRITE setPath NOTIFY pathChanged)
  Q_PROPERTY(bool watchChanges READ watchChanges WRITE setWatchChanges NOTIFY watchChangesChanged)
  Q_PROPERTY(bool readContents READ readContents WRITE setReadContents NOTIFY readContentsChanged)
  Q_PROPERTY(bool printErrors READ printErrors WRITE setPrintErrors NOTIFY printErrorsChanged)
  Q_PROPERTY(bool exists READ exists NOTIFY loaded)

public:
  explicit FileView(QObject* parent = nullptr);

  [[nodiscard]] QString path() const { return mPath; }
  void setPath(const QString& path);

  [[nodiscard]] bool watchChanges() const { return mWatch; }
  void setWatchChanges(bool watch);

  [[nodiscard]] bool readContents() const { return mReadContents; }
  void setReadContents(bool read);

  [[nodiscard]] bool printErrors() const { return mPrintErrors; }
  void setPrintErrors(bool print);

  [[nodiscard]] bool exists() const { return mExists; }

  // The file's contents as of the last read. Empty when the file is absent,
  // which callers must treat as "nothing stated" rather than as a value.
  Q_INVOKABLE QString text() const { return mText; }

  Q_INVOKABLE void reload();

signals:
  void pathChanged();
  void watchChangesChanged();
  void readContentsChanged();
  void printErrorsChanged();
  void loaded();
  void fileChanged();

private:
  void rewatch();
  void onWatchFired(const QString& changedPath);

  QFileSystemWatcher mWatcher;
  QString mPath;
  QString mText;
  bool mWatch = false;
  bool mReadContents = true;
  bool mPrintErrors = true;
  bool mExists = false;
};

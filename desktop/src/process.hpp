// An asynchronous child process, API-compatible with Quickshell.Io's Process.
//
// The vault never blocks on the engine. Every `anubis` invocation is one of
// these: the command is assigned, `running` is set true, and the answer
// arrives later through a stream sink and the `exited` signal. A gigabyte can
// be moving and the surface still repaints.
//
// This type spawns and reports. It does not know what `anubis` is, does not
// parse its output, and never decides that a command succeeded -- the exit
// code and the bytes go to QML exactly as the OS produced them.
#pragma once

// glibc defines these as macros, which would otherwise mangle the property
// names the QML was written against. The QML says `stdout:` and `stderr:`, so
// that is what has to reach moc.
#ifdef stdout
#undef stdout
#endif
#ifdef stderr
#undef stderr
#endif

#include <QObject>
#include <QProcess>
#include <QStringDecoder>
#include <QStringList>
#include <QTimer>
#include <QtQml/qqmlregistration.h>

#include "datastream.hpp"

class Process : public QObject {
  Q_OBJECT
  QML_ELEMENT

  Q_PROPERTY(QStringList command READ command WRITE setCommand NOTIFY commandChanged)
  Q_PROPERTY(bool running READ running WRITE setRunning NOTIFY runningChanged)
  Q_PROPERTY(DataStream* stdout READ stdoutSink WRITE setStdoutSink NOTIFY stdoutSinkChanged)
  Q_PROPERTY(DataStream* stderr READ stderrSink WRITE setStderrSink NOTIFY stderrSinkChanged)
  Q_PROPERTY(int processId READ processId NOTIFY runningChanged)
  Q_PROPERTY(int timeoutMs READ timeoutMs WRITE setTimeoutMs NOTIFY timeoutMsChanged)
  Q_PROPERTY(qint64 maximumOutputBytes READ maximumOutputBytes WRITE setMaximumOutputBytes NOTIFY maximumOutputBytesChanged)
  Q_PROPERTY(bool timedOut READ timedOut NOTIFY timedOutChanged)
  Q_PROPERTY(bool outputLimitExceeded READ outputLimitExceeded NOTIFY outputLimitExceededChanged)

public:
  explicit Process(QObject* parent = nullptr);
  ~Process() override;

  [[nodiscard]] QStringList command() const { return mCommand; }
  void setCommand(const QStringList& command);

  [[nodiscard]] bool running() const { return mRunning; }
  void setRunning(bool running);

  [[nodiscard]] DataStream* stdoutSink() const { return mStdout; }
  void setStdoutSink(DataStream* sink);

  [[nodiscard]] DataStream* stderrSink() const { return mStderr; }
  void setStderrSink(DataStream* sink);

  [[nodiscard]] int processId() const;

  // Both controls are opt-in. Long encrypt/decrypt jobs keep their existing
  // unlimited lifetime and streaming output; the short status reader enables
  // them explicitly so a broken or wrong executable cannot pin the UI or grow
  // its long-lived collectors without bound.
  [[nodiscard]] int timeoutMs() const { return mTimeoutMs; }
  void setTimeoutMs(int timeoutMs);

  [[nodiscard]] qint64 maximumOutputBytes() const {
    return mMaximumOutputBytes;
  }
  void setMaximumOutputBytes(qint64 maximumOutputBytes);

  [[nodiscard]] bool timedOut() const { return mTimedOut; }
  [[nodiscard]] bool outputLimitExceeded() const {
    return mOutputLimitExceeded;
  }

  // Deliver a POSIX signal to the child. The vault uses SIGTERM to abort a
  // running encrypt or decrypt; the engine's own cleanup decides what a
  // half-written output becomes.
  Q_INVOKABLE void signal(int signum);

signals:
  void commandChanged();
  void runningChanged();
  void stdoutSinkChanged();
  void stderrSinkChanged();
  void timeoutMsChanged();
  void maximumOutputBytesChanged();
  void timedOutChanged();
  void outputLimitExceededChanged();
  void started();
  void exited(int exitCode, int exitStatus);

private:
  void start();
  void stop();
  void drain(QProcess::ProcessChannel channel);
  void onFinished(int exitCode, QProcess::ExitStatus status);
  void onFailed(QProcess::ProcessError error);
  void settle(int exitCode, int exitStatus);

  QProcess* mProc = nullptr;
  QStringList mCommand;
  DataStream* mStdout = nullptr;
  DataStream* mStderr = nullptr;
  QStringDecoder mOutDecoder{QStringDecoder::Utf8};
  QStringDecoder mErrDecoder{QStringDecoder::Utf8};
  QTimer mDeadline;
  int mTimeoutMs = 0;
  qint64 mMaximumOutputBytes = 0;
  qint64 mOutputBytes = 0;
  bool mRunning = false;
  bool mSettled = false;
  bool mTimedOut = false;
  bool mOutputLimitExceeded = false;
};

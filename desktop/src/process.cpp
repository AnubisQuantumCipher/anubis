#include "process.hpp"

#include <QDebug>
#include <QTimer>

#include <cstdlib>
#include <csignal>

Process::Process(QObject* parent) : QObject(parent) {
  mDeadline.setSingleShot(true);
  connect(&mDeadline, &QTimer::timeout, this, [this] {
    if (!mRunning || !mProc || mSettled) return;
    mTimedOut = true;
    emit timedOutChanged();
    if (mStdout) mStdout->reset();
    if (mStderr) mStderr->reset();
    stop();
  });
}

Process::~Process() {
  if (mProc) {
    mProc->disconnect(this);
    if (mProc->state() != QProcess::NotRunning) {
      mProc->terminate();
      if (!mProc->waitForFinished(500)) mProc->kill();
    }
  }
}

void Process::setCommand(const QStringList& command) {
  if (mCommand == command) return;
  mCommand = command;
  emit commandChanged();
}

void Process::setStdoutSink(DataStream* sink) {
  if (mStdout == sink) return;
  mStdout = sink;
  emit stdoutSinkChanged();
}

void Process::setStderrSink(DataStream* sink) {
  if (mStderr == sink) return;
  mStderr = sink;
  emit stderrSinkChanged();
}

int Process::processId() const {
  return mProc ? static_cast<int>(mProc->processId()) : 0;
}

void Process::setTimeoutMs(int timeoutMs) {
  if (timeoutMs < 0) timeoutMs = 0;
  if (mTimeoutMs == timeoutMs) return;
  mTimeoutMs = timeoutMs;
  emit timeoutMsChanged();
}

void Process::setMaximumOutputBytes(qint64 maximumOutputBytes) {
  if (maximumOutputBytes < 0) maximumOutputBytes = 0;
  if (mMaximumOutputBytes == maximumOutputBytes) return;
  mMaximumOutputBytes = maximumOutputBytes;
  emit maximumOutputBytesChanged();
}

void Process::setRunning(bool running) {
  if (running == mRunning) return;
  if (running) start();
  else stop();
}

void Process::start() {
  if (mCommand.isEmpty()) {
    qWarning() << "anubis-desktop: refusing to start a process with no command";
    return;
  }

  // The QML-owned sinks outlive an individual QProcess. Reset them before
  // replacing the child so a successful prior response can never satisfy a
  // later run that emitted nothing or failed before writing.
  if (mStdout) mStdout->reset();
  if (mStderr) mStderr->reset();

  mDeadline.stop();
  mOutputBytes = 0;
  if (mTimedOut) {
    mTimedOut = false;
    emit timedOutChanged();
  }
  if (mOutputLimitExceeded) {
    mOutputLimitExceeded = false;
    emit outputLimitExceededChanged();
  }

  // A fresh QProcess per run. Reusing one would carry the previous run's
  // buffered bytes and exit state into this one, which is exactly the sort of
  // stale-state bleed the vault's honesty rules exist to prevent.
  if (mProc) {
    mProc->disconnect(this);
    mProc->deleteLater();
  }
  mProc = new QProcess(this);
  mProc->setProcessChannelMode(QProcess::SeparateChannels);

  mOutDecoder = QStringDecoder(QStringDecoder::Utf8);
  mErrDecoder = QStringDecoder(QStringDecoder::Utf8);
  mSettled = false;

  connect(mProc, &QProcess::readyReadStandardOutput, this,
          [this] { drain(QProcess::StandardOutput); });
  connect(mProc, &QProcess::readyReadStandardError, this,
          [this] { drain(QProcess::StandardError); });
  connect(mProc, &QProcess::finished, this, &Process::onFinished);
  connect(mProc, &QProcess::errorOccurred, this, &Process::onFailed);

  const QString program = mCommand.first();
  const QStringList arguments = mCommand.mid(1);

  mRunning = true;
  emit runningChanged();

  mProc->start(program, arguments);
  if (mTimeoutMs > 0) mDeadline.start(mTimeoutMs);
  emit started();
}

void Process::stop() {
  if (!mProc || mProc->state() == QProcess::NotRunning) {
    if (mRunning) {
      mRunning = false;
      emit runningChanged();
    }
    return;
  }

  auto* proc = mProc;
  proc->terminate();
  // Escalate only if the child ignores SIGTERM. A cooperative engine gets the
  // chance to finish its own teardown before it is taken apart.
  QTimer::singleShot(1500, proc, [proc] {
    if (proc->state() != QProcess::NotRunning) proc->kill();
  });
}

void Process::signal(int signum) {
  if (!mProc) return;
  const auto pid = mProc->processId();
  if (pid <= 0) return;
  ::kill(static_cast<pid_t>(pid), signum);
}

void Process::drain(QProcess::ProcessChannel channel) {
  if (!mProc) return;

  const bool isOut = channel == QProcess::StandardOutput;
  DataStream* sink = isOut ? mStdout : mStderr;
  const QByteArray raw = isOut ? mProc->readAllStandardOutput()
                               : mProc->readAllStandardError();
  if (raw.isEmpty()) return;

  // Once a run has failed its resource boundary, drain the pipe but do not
  // retain or decode any more of its bytes. The outcome flag, not a plausible
  // prefix, is the only result the caller may consume.
  if (mTimedOut || mOutputLimitExceeded) return;

  const qint64 chunkBytes = raw.size();
  if (mMaximumOutputBytes > 0
      && (chunkBytes > mMaximumOutputBytes
          || mOutputBytes > mMaximumOutputBytes - chunkBytes)) {
    mOutputLimitExceeded = true;
    emit outputLimitExceededChanged();
    mDeadline.stop();
    if (mStdout) mStdout->reset();
    if (mStderr) mStderr->reset();
    stop();
    return;
  }
  mOutputBytes += chunkBytes;

  // Decoded incrementally: a pipe read can land mid-codepoint, and a naive
  // per-chunk fromUtf8 would turn a split multi-byte character into two
  // replacement characters inside an otherwise valid JSON line.
  const QString text = isOut ? mOutDecoder.decode(raw) : mErrDecoder.decode(raw);
  if (sink && !text.isEmpty()) sink->feed(text);
}

void Process::onFinished(int exitCode, QProcess::ExitStatus status) {
  settle(exitCode, status == QProcess::NormalExit ? 0 : 1);
}

void Process::onFailed(QProcess::ProcessError error) {
  if (error != QProcess::FailedToStart) return;
  // The shell's convention for "could not execute". The vault already reads
  // 127 as exactly that, so a binary that vanished between the probe and the
  // call surfaces as a refusal rather than as silence.
  settle(127, 1);
}

void Process::settle(int exitCode, int exitStatus) {
  if (mSettled) return;
  mSettled = true;
  mDeadline.stop();

  if (mProc) {
    drain(QProcess::StandardOutput);
    drain(QProcess::StandardError);
  }

  // A decoder can retain an incomplete UTF-8 prefix after the pipe reaches
  // EOF. Feed a private ASCII sentinel through each decoder to force any such
  // prefix into its error state; an ASCII byte can never continue a multibyte
  // UTF-8 sequence. The decoded probes are deliberately not sent to the
  // stream sinks. This works across the supported Qt 6.5+ API surface, where
  // QStringDecoder::finalize() is not yet available.
  const QString outProbe = mOutDecoder.decode(QByteArray(1, '\0'));
  const QString errProbe = mErrDecoder.decode(QByteArray(1, '\0'));
  const bool encodingError = mOutDecoder.hasError() || mErrDecoder.hasError();
  Q_UNUSED(outProbe)
  Q_UNUSED(errProbe)
  if (encodingError && exitCode == EXIT_SUCCESS) exitCode = EXIT_FAILURE;

  // Streams close before the exit is announced, because the QML handler for
  // `exited` reads what those streams collected.
  if (mStdout) mStdout->finish();
  if (mStderr) mStderr->finish();

  if (mRunning) {
    mRunning = false;
    emit runningChanged();
  }

  emit exited(exitCode, exitStatus);
}

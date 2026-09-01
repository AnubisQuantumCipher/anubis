#include <QFile>
#include <QFileInfo>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtTest>

#include "datastream.hpp"
#include "fileview.hpp"
#include "openrequest.hpp"
#include "process.hpp"

class ProcessLifecycleTest final : public QObject {
  Q_OBJECT

private slots:
  void openRequestPreservesExactStructuredPath() {
    const QString exact = QStringLiteral(" /tmp/\"quoted\"\ncontainer.anubis ");
    const QString requestId = QStringLiteral("request-token");
    const QByteArray message = AnubisOpenRequest::encode(exact, requestId);
    QString decoded;
    QString decodedId;

    QVERIFY(AnubisOpenRequest::decode(message, &decoded, &decodedId));
    QCOMPARE(decoded, exact);
    QCOMPARE(decodedId, requestId);
  }

  void openRequestCarriesEmptyRaiseMessage() {
    const QString requestId = QStringLiteral("request-token");
    const QByteArray message =
      AnubisOpenRequest::encode(QString(), requestId);
    QString decoded = QStringLiteral("stale");
    QString decodedId;

    QVERIFY(AnubisOpenRequest::decode(message, &decoded, &decodedId));
    QCOMPARE(decoded, QString());
    QCOMPARE(decodedId, requestId);
  }

  void openRequestRejectsUnstructuredBytes() {
    QString decoded = QStringLiteral("unchanged");
    QString decodedId;

    QVERIFY(!AnubisOpenRequest::decode(
      QByteArrayLiteral(" /tmp/container.anubis\n"), &decoded, &decodedId));
    QCOMPARE(decoded, QStringLiteral("unchanged"));
  }

  void openRequestRejectsOversizedFrames() {
    QByteArray oversized(AnubisOpenRequest::MaxFrameBytes + 1, 'x');
    oversized[oversized.size() - 1] = '\n';
    QString decoded = QStringLiteral("unchanged");
    QString decodedId = QStringLiteral("unchanged-id");

    QVERIFY(!AnubisOpenRequest::decode(oversized, &decoded, &decodedId));
    QCOMPARE(decoded, QStringLiteral("unchanged"));
    QCOMPARE(decodedId, QStringLiteral("unchanged-id"));
  }

  void acknowledgementMustMatchRequest() {
    const QString requestId = QStringLiteral("request-token");
    const QByteArray response = AnubisOpenRequest::encodeAck(requestId);

    QVERIFY(AnubisOpenRequest::decodeAck(response, requestId));
    QVERIFY(!AnubisOpenRequest::decodeAck(
      response, QStringLiteral("different-request")));
    QVERIFY(!AnubisOpenRequest::decodeAck(
      QByteArrayLiteral("{\"type\":\"accepted\"}\n"), requestId));
  }

  void runtimeDirectoryMustBeOwnedAndPrivate() {
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const QFile::Permissions privatePermissions = QFile::ReadOwner
      | QFile::WriteOwner | QFile::ExeOwner;
    QVERIFY(QFile::setPermissions(directory.path(), privatePermissions));
    const uint ownerId = QFileInfo(directory.path()).ownerId();
    QVERIFY(AnubisOpenRequest::isPrivateRuntimeDirectory(
      directory.path(), ownerId));

    QVERIFY(QFile::setPermissions(
      directory.path(), privatePermissions | QFile::ReadGroup));
    QVERIFY(!AnubisOpenRequest::isPrivateRuntimeDirectory(
      directory.path(), ownerId));
  }

  void fileViewCanWatchWithoutReadingContainerContents() {
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("sealed.anubis"));
    QFile file(path);
    QVERIFY(file.open(QIODevice::WriteOnly));
    const QByteArray payload = QByteArrayLiteral("container bytes");
    QCOMPARE(file.write(payload), qint64(payload.size()));
    file.close();

    FileView view;
    view.setReadContents(false);
    view.setPath(path);
    QVERIFY(view.exists());
    QCOMPARE(view.text(), QString());

    view.setReadContents(true);
    QCOMPARE(view.text(), QStringLiteral("container bytes"));
  }

  void collectorResetClearsPreviousRun() {
    StdioCollector collector;
    collector.feed(QStringLiteral("previous"));
    QCOMPARE(collector.text(), QStringLiteral("previous"));

    collector.reset();
    QCOMPARE(collector.text(), QString());
  }

  void splitResetDropsIncompleteRecord() {
    SplitParser parser;
    QSignalSpy records(&parser, &SplitParser::read);

    parser.feed(QStringLiteral("stale partial"));
    parser.reset();
    parser.feed(QStringLiteral("current\n"));

    QCOMPARE(records.count(), 1);
    QCOMPARE(records.takeFirst().at(0).toString(), QStringLiteral("current"));
  }

  void processStartsWithFreshSinks() {
    Process process;
    StdioCollector output;
    process.setStdoutSink(&output);

    process.setCommand({QStringLiteral("/usr/bin/printf"),
                        QStringLiteral("first")});
    QSignalSpy firstExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(firstExit.wait(15000));
    QCOMPARE(firstExit.takeFirst().at(0).toInt(), 0);
    QCOMPARE(output.text(), QStringLiteral("first"));

    process.setCommand({QStringLiteral("/usr/bin/printf"),
                        QStringLiteral("second")});
    QSignalSpy secondExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(secondExit.wait(15000));
    QCOMPARE(secondExit.takeFirst().at(0).toInt(), 0);
    QCOMPARE(output.text(), QStringLiteral("second"));

    // Failed-to-start emits no bytes. The previous successful answer must not
    // survive and masquerade as this run's output.
    process.setCommand({QStringLiteral("/definitely/not/an/executable")});
    QSignalSpy failedExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(failedExit.wait(15000));
    QCOMPARE(failedExit.takeFirst().at(0).toInt(), 127);
    QCOMPARE(output.text(), QString());
  }

  void incompleteUtf8TailMakesSuccessfulChildFailClosed() {
    Process process;
    StdioCollector output;
    process.setStdoutSink(&output);

    // GNU printf interprets this as one leading byte of a two-byte UTF-8
    // sequence and then exits successfully. Process must not discard that
    // pending byte and preserve the child's zero exit status.
    process.setCommand({QStringLiteral("/usr/bin/printf"),
                        QStringLiteral("\\303")});
    QSignalSpy exited(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(exited.wait(15000));
    QVERIFY(exited.takeFirst().at(0).toInt() != 0);
  }

  void processDeadlineSettlesAndResets() {
    Process process;
    StdioCollector output;
    process.setStdoutSink(&output);
    process.setTimeoutMs(50);
    process.setCommand({QStringLiteral("/usr/bin/sh"),
                        QStringLiteral("-c"),
                        QStringLiteral("trap '' TERM; exec /usr/bin/sleep 10")});

    QSignalSpy timedExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(timedExit.wait(5000));
    QVERIFY(process.timedOut());
    QVERIFY(!process.outputLimitExceeded());
    QCOMPARE(output.text(), QString());

    process.setTimeoutMs(0);
    process.setCommand({QStringLiteral("/usr/bin/printf"),
                        QStringLiteral("current")});
    QSignalSpy currentExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(currentExit.wait(5000));
    QVERIFY(!process.timedOut());
    QVERIFY(!process.outputLimitExceeded());
    QCOMPARE(output.text(), QStringLiteral("current"));
  }

  void processOutputLimitIsRawBytesAndResets() {
    Process process;
    StdioCollector output;
    StdioCollector errors;
    process.setStdoutSink(&output);
    process.setStderrSink(&errors);
    process.setMaximumOutputBytes(4);

    process.setCommand({QStringLiteral("/usr/bin/printf"),
                        QStringLiteral("four")});
    QSignalSpy exactExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(exactExit.wait(5000));
    QVERIFY(!process.outputLimitExceeded());
    QCOMPARE(output.text(), QStringLiteral("four"));

    process.setCommand({QStringLiteral("/usr/bin/printf"),
                        QStringLiteral("12345")});
    QSignalSpy oversizedExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(oversizedExit.wait(5000));
    QVERIFY(process.outputLimitExceeded());
    QCOMPARE(output.text(), QString());

    process.setMaximumOutputBytes(5);
    process.setCommand({QStringLiteral("/usr/bin/sh"),
                        QStringLiteral("-c"),
                        QStringLiteral("printf 123; printf 456 >&2")});
    QSignalSpy combinedExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(combinedExit.wait(5000));
    QVERIFY(process.outputLimitExceeded());
    QCOMPARE(output.text(), QString());
    QCOMPARE(errors.text(), QString());

    process.setMaximumOutputBytes(1);
    process.setCommand({QStringLiteral("/usr/bin/printf"),
                        QString::fromUtf8("\xC3\xA9")});
    QSignalSpy multibyteExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(multibyteExit.wait(5000));
    QVERIFY(process.outputLimitExceeded());
    QCOMPARE(output.text(), QString());

    process.setMaximumOutputBytes(8);
    process.setCommand({QStringLiteral("/usr/bin/printf"),
                        QStringLiteral("reset")});
    QSignalSpy resetExit(&process, &Process::exited);
    process.setRunning(true);
    QVERIFY(resetExit.wait(5000));
    QVERIFY(!process.outputLimitExceeded());
    QVERIFY(!process.timedOut());
    QCOMPARE(output.text(), QStringLiteral("reset"));
  }
};

QTEST_GUILESS_MAIN(ProcessLifecycleTest)

#include "process_lifecycle_test.moc"

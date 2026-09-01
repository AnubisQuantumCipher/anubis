#include <QSignalSpy>
#include <QtTest>

#include "datastream.hpp"
#include "process.hpp"

class ProcessLifecycleTest final : public QObject {
  Q_OBJECT

private slots:
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
};

QTEST_GUILESS_MAIN(ProcessLifecycleTest)

#include "process_lifecycle_test.moc"

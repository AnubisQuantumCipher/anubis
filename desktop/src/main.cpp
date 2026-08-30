// ANUBIS Vault -- a standalone desktop application for post-quantum file
// encryption.
//
// This program is a renderer and a process driver. It holds no key material,
// derives no secret, performs no cryptography, and reaches no verification
// verdict of its own: every cryptographic claim on screen is the `anubis`
// engine's own JSON, carried through verbatim. When the engine declines to
// state something, the surface says so rather than filling in a pass.
//
// Started with a path, it opens that container in the inspector. Started
// while an instance is already running, it hands the path to that instance and
// exits, so a file manager's "Open with" never ends up with two vaults
// polling the same engine.

#include <QCommandLineParser>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QIcon>
#include <QLocalServer>
#include <QLocalSocket>
#include <QQmlApplicationEngine>
#include <QQmlError>
#include <QQmlContext>
#include <QQuickStyle>
#include <QUrl>

#include <unistd.h>
#include <cstdio>

#include "app.hpp"

namespace {

QString socketName() {
  // Per-user, so two people on one machine each get their own vault rather
  // than one silently steering the other's.
  return QStringLiteral("anubis-desktop-%1").arg(::getuid());
}

// Absolute, symlink-resolved where possible. A relative path handed in from a
// terminal means nothing once it has crossed into another process.
QString canonicalTarget(const QString& raw) {
  if (raw.isEmpty()) return {};
  QString path = raw;
  if (path.startsWith(QStringLiteral("file://"))) path = QUrl(path).toLocalFile();
  const QFileInfo info(path);
  const QString resolved = info.canonicalFilePath();
  return resolved.isEmpty() ? info.absoluteFilePath() : resolved;
}

// Hand the path to the instance that is already running. Returns false when
// there is nothing listening, which is the ordinary first-launch case.
bool forwardToRunningInstance(const QString& target) {
  QLocalSocket socket;
  socket.connectToServer(socketName());
  if (!socket.waitForConnected(300)) return false;
  // The newline matters. Writing an empty target writes zero bytes, and a
  // zero-byte write never wakes the other side's readyRead -- so a launch with
  // no argument connected, proved an instance was alive, and then silently
  // failed to raise it. The receiving end already trims, so the terminator
  // costs nothing and makes the empty case a real message.
  socket.write(target.toUtf8() + '\n');
  socket.flush();
  socket.waitForBytesWritten(300);
  socket.disconnectFromServer();
  return true;
}

} // namespace

int main(int argc, char* argv[]) {
  QGuiApplication::setApplicationName(QStringLiteral("ANUBIS Vault"));
  QGuiApplication::setApplicationVersion(QStringLiteral(ANUBIS_DESKTOP_VERSION));
  QGuiApplication::setOrganizationName(QStringLiteral("Anubis Quantum Cipher"));
  QGuiApplication::setDesktopFileName(QStringLiteral("dev.anubis.Vault"));

  QGuiApplication app(argc, argv);

  QCommandLineParser parser;
  parser.setApplicationDescription(
    QStringLiteral("Post-quantum file encryption vault. Drives the `anubis` "
                   "engine; performs no cryptography itself."));
  parser.addHelpOption();
  parser.addVersionOption();
  parser.addPositionalArgument(
    QStringLiteral("file"),
    QStringLiteral("Container or plaintext to load into the console."));
  parser.process(app);

  const QStringList positional = parser.positionalArguments();
  const QString target = positional.isEmpty() ? QString()
                                              : canonicalTarget(positional.first());

  if (forwardToRunningInstance(target)) return 0;

  // Nothing was listening, so this process becomes the instance. A stale
  // socket from a crashed run would otherwise block the listen forever.
  QLocalServer::removeServer(socketName());
  QLocalServer server;
  server.setSocketOptions(QLocalServer::UserAccessOption);
  if (!server.listen(socketName()))
    qWarning() << "anubis-desktop: single-instance socket unavailable;"
               << "a second launch will open its own window";

  QQuickStyle::setStyle(QStringLiteral("Basic"));
  QGuiApplication::setWindowIcon(QIcon(QStringLiteral(":/icons/anubis-vault.svg")));

  QQmlApplicationEngine engine;

  // Written straight to stderr rather than through the logging categories,
  // which a distribution's logging rules can and do switch off. A program that
  // cannot build its own window has to be able to say so unconditionally --
  // exiting silently is the one outcome that leaves nothing to act on.
  QObject::connect(&engine, &QQmlApplicationEngine::warnings, &app,
                   [](const QList<QQmlError>& warnings) {
                     for (const QQmlError& warning : warnings)
                       fprintf(stderr, "anubis-desktop: %s\n",
                               warning.toString().toUtf8().constData());
                   });
  QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                   [](const QUrl& url) {
                     fprintf(stderr, "anubis-desktop: could not create %s\n",
                             url.toString().toUtf8().constData());
                   });

  engine.loadFromModule("Anubis", "Main");
  if (engine.rootObjects().isEmpty()) {
    fprintf(stderr, "anubis-desktop: the window could not be built\n");
    return 1;
  }

  auto* appSingleton = App::instance();
  if (appSingleton && !target.isEmpty()) appSingleton->requestOpenPath(target);

  QObject::connect(&server, &QLocalServer::newConnection, &app, [&server] {
    auto* socket = server.nextPendingConnection();
    if (!socket) return;
    QObject::connect(socket, &QLocalSocket::readyRead, socket, [socket] {
      const QString path = QString::fromUtf8(socket->readAll()).trimmed();
      if (auto* instance = App::instance()) {
        if (path.isEmpty()) emit instance->raiseRequested();
        else instance->requestOpenPath(path);
      }
    });
    QObject::connect(socket, &QLocalSocket::disconnected, socket,
                     &QLocalSocket::deleteLater);
  });

  return app.exec();
}

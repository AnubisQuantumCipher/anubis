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
#include <QDeadlineTimer>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QIcon>
#include <QLocalServer>
#include <QLocalSocket>
#include <QLockFile>
#include <QQmlApplicationEngine>
#include <QQmlError>
#include <QQmlContext>
#include <QQuickStyle>
#include <QUuid>
#include <QUrl>

#include <cstdio>
#include <memory>

#include "app.hpp"
#include "openrequest.hpp"

namespace {

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

// Hand the path to the instance that is already running. The caller
// distinguishes an absent endpoint from one that accepted a connection but
// did not return the matching acknowledgement.
enum class ForwardResult { NoServer, Acknowledged, Unacknowledged };

ForwardResult forwardToRunningInstance(const QString& socketPath,
                                       const QString& target) {
  QLocalSocket socket;
  socket.setReadBufferSize(AnubisOpenRequest::MaxFrameBytes + 1);
  socket.connectToServer(socketPath);
  if (!socket.waitForConnected(300)) return ForwardResult::NoServer;
  // A JSON message preserves path whitespace and embedded newlines while also
  // making an empty target a real non-empty message that raises the window.
  // The random request ID binds the acknowledgement to this connection.
  const QString requestId = QUuid::createUuid().toString(QUuid::WithoutBraces);
  const QByteArray request = AnubisOpenRequest::encode(target, requestId);
  if (request.size() > AnubisOpenRequest::MaxFrameBytes)
    return ForwardResult::Unacknowledged;
  socket.write(request);
  socket.flush();
  if (!socket.waitForBytesWritten(300) && socket.bytesToWrite() != 0)
    return ForwardResult::Unacknowledged;

  QByteArray response;
  QDeadlineTimer deadline(300);
  while (!response.endsWith('\n')) {
    if (socket.bytesAvailable() == 0
        && !socket.waitForReadyRead(deadline.remainingTime()))
      return ForwardResult::Unacknowledged;
    const QByteArray chunk = socket.readAll();
    if (chunk.size() > AnubisOpenRequest::MaxFrameBytes - response.size())
      return ForwardResult::Unacknowledged;
    response += chunk;
  }
  socket.disconnectFromServer();
  return AnubisOpenRequest::decodeAck(response, requestId)
    ? ForwardResult::Acknowledged : ForwardResult::Unacknowledged;
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

  const QString socketPath = AnubisOpenRequest::privateSocketPath();
  ForwardResult forward = ForwardResult::NoServer;
  if (!socketPath.isEmpty()) {
    forward = forwardToRunningInstance(socketPath, target);
    if (forward == ForwardResult::Acknowledged) return 0;
  } else {
    qWarning() << "anubis-desktop: private runtime directory unavailable;"
               << "single-instance forwarding disabled";
  }

  // Nothing was listening, so this process may become the instance. The lock
  // serialises the stale-socket check/remove/listen transition: two launches
  // can no longer unlink each other's newly live socket and split into two
  // primaries.
  QLocalServer server;
  server.setSocketOptions(QLocalServer::UserAccessOption);
  bool serverListening = false;
  std::unique_ptr<QLockFile> instanceLock;
  if (!socketPath.isEmpty() && forward == ForwardResult::NoServer) {
    instanceLock = std::make_unique<QLockFile>(socketPath
      + QStringLiteral(".lock"));
    if (instanceLock->tryLock(300)) {
      // Recheck after winning the launch lock. This also coexists safely with
      // an older instance that predates the lock but began listening meanwhile.
      forward = forwardToRunningInstance(socketPath, target);
      if (forward == ForwardResult::Acknowledged) return 0;
      if (forward == ForwardResult::NoServer
          && AnubisOpenRequest::privateSocketPath() == socketPath) {
        QLocalServer::removeServer(socketPath);
        serverListening = server.listen(socketPath);
      }
      if (!serverListening) {
        instanceLock->unlock();
        instanceLock.reset();
      }
    } else {
      // The lock winner creates the server before loading QML. One bounded
      // reconnect distinguishes that launch window from an unavailable peer.
      forward = forwardToRunningInstance(socketPath, target);
      if (forward == ForwardResult::Acknowledged) return 0;
    }
  }
  if (!socketPath.isEmpty() && !serverListening)
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
    socket->setReadBufferSize(AnubisOpenRequest::MaxFrameBytes + 1);
    socket->setProperty("anubisOpenRequest", QByteArray());
    QObject::connect(socket, &QLocalSocket::readyRead, socket, [socket] {
      QByteArray message = socket->property("anubisOpenRequest").toByteArray();
      const QByteArray chunk = socket->readAll();
      if (chunk.size() > AnubisOpenRequest::MaxFrameBytes - message.size()) {
        qWarning() << "anubis-desktop: oversized local open request";
        socket->abort();
        return;
      }
      message += chunk;
      socket->setProperty("anubisOpenRequest", message);
      if (!message.endsWith('\n')) return;
      QString path;
      QString requestId;
      if (!AnubisOpenRequest::decode(message, &path, &requestId)) {
        qWarning() << "anubis-desktop: invalid local open request";
        socket->disconnectFromServer();
        return;
      }
      if (auto* instance = App::instance()) {
        if (path.isEmpty()) emit instance->raiseRequested();
        else instance->requestOpenPath(path);
      }
      socket->write(AnubisOpenRequest::encodeAck(requestId));
      socket->flush();
      socket->disconnectFromServer();
    });
    QObject::connect(socket, &QLocalSocket::disconnected, socket,
                     &QLocalSocket::deleteLater);
  });

  return app.exec();
}

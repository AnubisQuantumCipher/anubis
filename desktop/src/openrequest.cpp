#include "openrequest.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

#include <unistd.h>

namespace AnubisOpenRequest {

namespace {

QByteArray framed(const QJsonObject& object) {
  return QJsonDocument(object).toJson(QJsonDocument::Compact) + '\n';
}

bool parseFrame(const QByteArray& frame, QJsonObject* object) {
  if (!object || frame.isEmpty() || frame.size() > MaxFrameBytes
      || !frame.endsWith('\n'))
    return false;
  const QByteArray message = frame.first(frame.size() - 1);
  if (message.contains('\n')) return false;
  QJsonParseError parseError{};
  const QJsonDocument document = QJsonDocument::fromJson(message, &parseError);
  if (parseError.error != QJsonParseError::NoError || !document.isObject())
    return false;
  *object = document.object();
  return true;
}

} // namespace

QByteArray encode(const QString& path, const QString& requestId) {
  QJsonObject request;
  request.insert(QStringLiteral("type"), QStringLiteral("open"));
  request.insert(QStringLiteral("request_id"), requestId);
  request.insert(QStringLiteral("path"), path);
  return framed(request);
}

bool decode(const QByteArray& frame, QString* path, QString* requestId) {
  if (!path || !requestId) return false;
  QJsonObject request;
  if (!parseFrame(frame, &request)) return false;
  const QJsonValue type = request.value(QStringLiteral("type"));
  const QJsonValue target = request.value(QStringLiteral("path"));
  const QJsonValue id = request.value(QStringLiteral("request_id"));
  if (!type.isString() || type.toString() != QStringLiteral("open")
      || !target.isString() || !id.isString() || id.toString().isEmpty())
    return false;

  *path = target.toString();
  *requestId = id.toString();
  return true;
}

QByteArray encodeAck(const QString& requestId) {
  QJsonObject response;
  response.insert(QStringLiteral("type"), QStringLiteral("accepted"));
  response.insert(QStringLiteral("request_id"), requestId);
  return framed(response);
}

bool decodeAck(const QByteArray& frame, const QString& expectedRequestId) {
  if (expectedRequestId.isEmpty()) return false;
  QJsonObject response;
  if (!parseFrame(frame, &response)) return false;
  const QJsonValue type = response.value(QStringLiteral("type"));
  const QJsonValue id = response.value(QStringLiteral("request_id"));
  return type.isString() && type.toString() == QStringLiteral("accepted")
    && id.isString() && id.toString() == expectedRequestId;
}

bool isPrivateRuntimeDirectory(const QString& path, uint expectedOwnerId) {
  const QFileInfo info(path);
  if (path.isEmpty() || !QDir::isAbsolutePath(path) || !info.isDir()
      || info.isSymLink() || info.ownerId() != expectedOwnerId)
    return false;

  const QFile::Permissions shared = QFile::ReadGroup | QFile::WriteGroup
    | QFile::ExeGroup | QFile::ReadOther | QFile::WriteOther | QFile::ExeOther;
  return (info.permissions() & shared) == QFile::Permissions();
}

QString privateSocketPath() {
  const QString runtime =
    QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
  if (!isPrivateRuntimeDirectory(runtime, ::geteuid())) return {};
  return QDir(runtime).filePath(QStringLiteral("anubis-vault.sock"));
}

} // namespace AnubisOpenRequest

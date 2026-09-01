#pragma once

#include <QByteArray>
#include <QString>
#include <QtGlobal>

namespace AnubisOpenRequest {

// Local IPC never needs an attacker-sized frame. This cap bounds both the
// client response and the server's per-connection accumulation.
inline constexpr qsizetype MaxFrameBytes = 64 * 1024;

// Local-instance messages are structured so every QString code point in a
// path, including whitespace and newlines, survives the process boundary.
[[nodiscard]] QByteArray encode(const QString& path, const QString& requestId);
[[nodiscard]] bool decode(const QByteArray& frame, QString* path,
                          QString* requestId);
[[nodiscard]] QByteArray encodeAck(const QString& requestId);
[[nodiscard]] bool decodeAck(const QByteArray& frame,
                             const QString& expectedRequestId);

// QStandardPaths may fall back to an unsafe directory when the session has no
// runtime directory. Single-instance forwarding is disabled in that case.
[[nodiscard]] bool isPrivateRuntimeDirectory(const QString& path,
                                             uint expectedOwnerId);
[[nodiscard]] QString privateSocketPath();

} // namespace AnubisOpenRequest

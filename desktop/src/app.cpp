#include "app.hpp"

#include <QClipboard>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDebug>
#include <QGuiApplication>
#include <QProcess>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QUrl>

namespace {

App* gInstance = nullptr;

// The foundational palette, used when no theme file is readable. These are the
// values Omarchy's own shell falls back to, so an unthemed machine gets a
// coherent surface rather than Qt's defaults.
const QVariantMap kFallbackPalette = {
  {QStringLiteral("foreground"), QStringLiteral("#cacccc")},
  {QStringLiteral("background"), QStringLiteral("#101315")},
  {QStringLiteral("accent"), QStringLiteral("#cacccc")},
  {QStringLiteral("urgent"), QStringLiteral("#a55555")},
  {QStringLiteral("muted"), QStringLiteral("#707880")},
};

// A deliberately small reader for the four keys this program needs out of a
// theme's colors.toml. It is not a TOML parser and does not pretend to be: it
// takes top-level `key = "value"` pairs and ignores everything else, so a
// theme that grows a section this program has never heard of is simply not
// read rather than mis-read.
QVariantMap readThemeColors(const QString& path) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return {};

  static const QRegularExpression pair(
    QStringLiteral("^\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*\"([^\"]*)\"\\s*$"));
  static const QRegularExpression section(QStringLiteral("^\\s*\\["));

  QVariantMap out;
  const QStringList lines = QString::fromUtf8(file.readAll()).split(u'\n');
  for (const QString& line : lines) {
    // Stop at the first table header: anything below it is scoped to that
    // table and its bare keys mean something else.
    if (section.match(line).hasMatch()) break;
    const auto hit = pair.match(line);
    if (!hit.hasMatch()) continue;
    const QString key = hit.captured(1);
    const QString value = hit.captured(2);
    if (!QColor::isValidColorName(value)) continue;
    out.insert(key, value);
  }
  return out;
}

} // namespace

App::App(QObject* parent) : QObject(parent) {
  gInstance = this;
  loadSettings();
  reloadPalette();

  // The settings file is watched, so an edit made in a text editor lands on
  // the surface without a restart. The directory is watched alongside it
  // because this program rewrites the file atomically-ish and an editor may
  // replace the inode outright, which drops a file-only watch.
  const auto onChange = [this] {
    rewatchSettings();
    loadSettings();
    reloadPalette();
  };
  connect(&mWatcher, &QFileSystemWatcher::fileChanged, this, onChange);
  connect(&mWatcher, &QFileSystemWatcher::directoryChanged, this, onChange);
  rewatchSettings();
}

void App::rewatchSettings() {
  const QString path = configPath();
  const QString dir = QFileInfo(path).absolutePath();
  if (QFile::exists(path) && !mWatcher.files().contains(path))
    mWatcher.addPath(path);
  if (QDir(dir).exists() && !mWatcher.directories().contains(dir))
    mWatcher.addPath(dir);
}

App* App::instance() { return gInstance; }

QString App::home() const {
  const QString fromEnv = qEnvironmentVariable("HOME");
  if (!fromEnv.isEmpty()) return fromEnv;
  return QDir::homePath();
}

QString App::configPath() const {
  return home() + QStringLiteral("/.config/anubis/desktop.json");
}

QString App::appVersion() const {
  return QGuiApplication::applicationVersion();
}

QString App::env(const QString& name) const {
  return qEnvironmentVariable(name.toUtf8().constData());
}

// Is this actually the encryption engine?
//
// There is more than one program called `anubis` in the wild -- notably a
// language toolchain of the same name, which has been seen installed
// under that name before. Accepting a candidate on its filename and executable
// bit alone means a different tool can be silently spawned as "the engine",
// and every status, encrypt and decrypt then fails in a way that names no
// cause.
//
// `--help` is pure argument parsing: it reads no key, touches no file, and
// writes nothing. That makes it the cheapest thing that can be run on a
// candidate before trusting it.
bool App::looksLikeTheEngine(const QString& path) const {
  QProcess probe;
  probe.setProgram(path);
  probe.setArguments({QStringLiteral("--help")});
  probe.setProcessChannelMode(QProcess::SeparateChannels);
  probe.start();
  if (!probe.waitForFinished(1500)) {
    probe.kill();
    probe.waitForFinished(200);
    return false;
  }
  const QString out = QString::fromUtf8(probe.readAllStandardOutput());
  return out.contains(QStringLiteral("post-quantum file encryption"),
                      Qt::CaseInsensitive);
}

QString App::locateEngine() const {
  // An explicit override wins, so a developer can point the app at a build
  // tree without touching the installed engine. It is still identity-checked:
  // an override that is not the engine is a mistake worth reporting, not
  // worth honouring.
  const QString override = qEnvironmentVariable("ANUBIS_ENGINE");
  if (!override.isEmpty() && QFileInfo(override).isExecutable()
      && looksLikeTheEngine(override))
    return override;

  const QString h = home();
  const QStringList candidates = {
    h + QStringLiteral("/.cargo/bin/anubis"),
    h + QStringLiteral("/.local/bin/anubis"),
    QStringLiteral("/usr/local/bin/anubis"),
    QStringLiteral("/usr/bin/anubis"),
  };
  for (const QString& candidate : candidates) {
    const QFileInfo info(candidate);
    if (info.isFile() && info.isExecutable() && looksLikeTheEngine(candidate))
      return candidate;
  }

  const QString onPath = QStandardPaths::findExecutable(QStringLiteral("anubis"));
  if (!onPath.isEmpty() && looksLikeTheEngine(onPath)) return onPath;
  return {};
}

bool App::fileExists(const QString& path) const {
  if (path.isEmpty()) return false;
  return QFileInfo::exists(path);
}

bool App::isDirectory(const QString& path) const {
  if (path.isEmpty()) return false;
  return QFileInfo(path).isDir();
}

void App::copyToClipboard(const QString& text) const {
  if (text.isEmpty()) return;
  auto* clipboard = QGuiApplication::clipboard();
  if (!clipboard) return;
  clipboard->setText(text, QClipboard::Clipboard);
  if (clipboard->supportsSelection())
    clipboard->setText(text, QClipboard::Selection);
}

QString App::pathFromUrl(const QString& url) const {
  if (url.isEmpty()) return {};
  if (!url.startsWith(QStringLiteral("file://"))) return url;
  return QUrl(url).toLocalFile();
}

QString App::urlFromPath(const QString& path) const {
  if (path.isEmpty()) return {};
  return QUrl::fromLocalFile(path).toString();
}

QString App::parentDirectory(const QString& path) const {
  if (path.isEmpty()) return home();
  const QFileInfo info(path);
  const QString dir = info.isDir() ? info.absoluteFilePath() : info.absolutePath();
  return QDir(dir).exists() ? dir : home();
}

bool App::revealInFileManager(const QString& path) const {
  const QString dir = parentDirectory(path);
  if (dir.isEmpty()) return false;
  return QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
}

void App::loadSettings() {
  QVariantMap loaded;
  QFile file(configPath());
  if (file.open(QIODevice::ReadOnly)) {
    QJsonParseError error{};
    const auto doc = QJsonDocument::fromJson(file.readAll(), &error);
    // A settings file that has been edited into invalid JSON leaves the
    // running values alone rather than resetting the program to defaults
    // mid-session. The next valid save fixes it.
    if (error.error != QJsonParseError::NoError) {
      qWarning().noquote() << "anubis-desktop: ignoring" << configPath()
                           << "--" << error.errorString();
      return;
    }
    if (doc.isObject()) loaded = doc.object().toVariantMap();
  }

  // Only announce a real change. This is what stops the write -> watcher ->
  // reload path from becoming a loop that repaints the surface forever.
  if (loaded == mSettings) return;
  mSettings = loaded;
  emit settingsChanged();
}

void App::reloadSettings() { loadSettings(); }

void App::writeSettings() {
  const QFileInfo info(configPath());
  QDir().mkpath(info.absolutePath());

  QFile file(configPath());
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    qWarning().noquote() << "anubis-desktop: cannot write" << configPath()
                         << "--" << file.errorString();
    return;
  }
  const auto doc = QJsonDocument(QJsonObject::fromVariantMap(mSettings));
  file.write(doc.toJson(QJsonDocument::Indented));
  file.close();
  rewatchSettings();
}

void App::setSetting(const QString& key, const QVariant& value) {
  if (key.isEmpty()) return;
  if (mSettings.value(key) == value) return;
  mSettings.insert(key, value);
  writeSettings();
  emit settingsChanged();
  if (key == QStringLiteral("theme")) reloadPalette();
}

void App::rememberGeometry(int width, int height, bool maximized) {
  QVariantMap window;
  window.insert(QStringLiteral("width"), width);
  window.insert(QStringLiteral("height"), height);
  window.insert(QStringLiteral("maximized"), maximized);
  if (mSettings.value(QStringLiteral("window")).toMap() == window) return;
  mSettings.insert(QStringLiteral("window"), window);
  writeSettings();
  emit settingsChanged();
}

void App::reloadPalette() {
  QVariantMap resolved = kFallbackPalette;

  // The desktop theme, when there is one. This program follows whatever the
  // machine is themed to rather than inventing its own colours.
  const QString themeFile =
    home() + QStringLiteral("/.local/state/omarchy/current/theme/colors.toml");
  const QVariantMap themed = readThemeColors(themeFile);
  for (auto it = themed.cbegin(); it != themed.cend(); ++it)
    if (resolved.contains(it.key())) resolved.insert(it.key(), it.value());

  // An explicit override in the settings file beats the theme, because a user
  // who typed a colour meant it.
  const QVariantMap override = mSettings.value(QStringLiteral("theme")).toMap();
  for (auto it = override.cbegin(); it != override.cend(); ++it) {
    if (!resolved.contains(it.key())) continue;
    const QString value = it.value().toString();
    if (QColor::isValidColorName(value)) resolved.insert(it.key(), value);
  }

  if (resolved == mPalette) return;
  mPalette = resolved;
  emit paletteChanged();
}

void App::requestOpenPath(const QString& path) {
  mPendingOpenPath = path;
  emit openPathRequested(path);
  emit raiseRequested();
}

void App::clearPendingOpenPath() {
  if (mPendingOpenPath.isEmpty()) return;
  mPendingOpenPath.clear();
}

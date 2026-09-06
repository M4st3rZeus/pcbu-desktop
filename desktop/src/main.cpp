#include <QGuiApplication>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <spdlog/spdlog.h>

#include "connection/lock/LockServer.h"
#include "platform/SessionLocker.h"
#include "storage/LoggingSystem.h"

int main(int argc, char *argv[]) {
  qputenv("QT_QUICK_CONTROLS_STYLE", QByteArray("Material"));
  qputenv("QT_QUICK_CONTROLS_MATERIAL_THEME", QByteArray("Dark"));
  qputenv("QT_QUICK_CONTROLS_MATERIAL_VARIANT", QByteArray("Dense"));
  qputenv("QT_QUICK_CONTROLS_MATERIAL_PRIMARY", QByteArray("Red"));
  qputenv("QT_QUICK_CONTROLS_MATERIAL_ACCENT", QByteArray("Teal"));
  LoggingSystem::Init("desktop");

  QGuiApplication app(argc, argv);
  QGuiApplication::setWindowIcon(QIcon(":/res/icons/icon.png"));

  // The lock listener has to live inside the user's interactive session -
  // every platform's lock API refuses to act on a session the caller is not
  // part of. This app is the only component that already runs there, so it
  // hosts the server for as long as it is open.
  //
  // Consequence worth knowing: closing the window stops the listener, so
  // remote lock only works while the app is running. Making it survive a
  // closed window needs a tray agent or a per-user autostart entry, which is
  // a deployment change rather than a code one.
  LockServer lockServer{};
  if(SessionLocker::IsAvailable()) {
    lockServer.Start();
  } else {
    spdlog::warn("Remote lock disabled: {}", SessionLocker::UnavailableReason());
  }

  auto url = QUrl("qrc:/ui/MainWindow.qml");
  QQmlApplicationEngine engine{};
  QObject::connect(
      &engine, &QQmlApplicationEngine::objectCreated, &app,
      [url](QObject *obj, const QUrl &objUrl) {
        if(!obj && url == objUrl) {
          QCoreApplication::exit(-1);
        }
      },
      Qt::QueuedConnection);
  engine.load(url);

  auto result = QGuiApplication::exec();
  lockServer.Stop();
  LoggingSystem::Destroy();
  return result;
}

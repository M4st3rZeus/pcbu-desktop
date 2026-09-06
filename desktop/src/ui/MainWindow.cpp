#include "MainWindow.h"

#include "installer/ServiceInstaller.h"
#include "shell/Elevator.h"
#include "platform/PlatformHelper.h"
#include "shell/Shell.h"
#include "storage/AppSettings.h"
#include "storage/PairedDevicesStorage.h"
#include "utils/AppInfo.h"
#include "utils/ResourceHelper.h"

MainWindow::~MainWindow() {
  if(m_LoadingThread.joinable())
    m_LoadingThread.join();
}

bool MainWindow::IsInstalled() {
  return ServiceInstaller::IsInstalled();
}

bool MainWindow::IsPaired() {
  return !PairedDevicesStorage::GetDevices().empty();
}

QString MainWindow::GetInstalledVersion() {
  auto installedVersion = AppSettings::Get().installedVersion;
  if(installedVersion.empty())
    return QString::fromUtf8(I18n::Get("installed_version_none"));
  return QString::fromUtf8(installedVersion);
}

QString MainWindow::GetLicenseText() {
  try {
    return QString::fromUtf8(ResourceHelper::GetResource(":/res/licenses.txt"));
  } catch(...) {
  }
  return {};
}

bool MainWindow::PerformStartupChecks(QObject *viewLoader, QObject *window) {
  // Running unprivileged is no longer fatal. Privileged work (installing the
  // login component, writing the paired-devices store) goes through the
  // elevator helper, which prompts once and runs only that work as root.
  //
  // Deliberately not relaunching the whole GUI elevated: the lock server has
  // to live in the user's own interactive session, and every platform's lock
  // API refuses to act on a session the caller is not part of.
  if(!Shell::IsRunningAsAdmin()) {
    // No elevation at startup.
    //
    // The store is owned by this user and mode 0600, so reading and writing
    // paired devices needs no privileges at all. Only install and uninstall
    // do, and those prompt when clicked - which is where a password prompt
    // belongs.
    //
    // Elevating here previously blocked the UI thread on a password dialog
    // before the window had drawn, which looked exactly like a hang.
    spdlog::info("Running without admin rights; install and uninstall will prompt when used.");
  }
#if defined(LINUX) || defined(APPLE)
  if(Shell::RunUserCommand("which bash").exitCode != 0) {
    QMetaObject::invokeMethod(window, "showFatalErrorMessage", Q_ARG(QVariant, QString::fromUtf8(I18n::Get("error_unix_missing_dep", "bash"))));
    return false;
  }
#ifdef LINUX
  if(Shell::RunUserCommand("test -f /etc/shadow").exitCode != 0) {
    QMetaObject::invokeMethod(window, "showFatalErrorMessage",
                              Q_ARG(QVariant, QString::fromUtf8(I18n::Get("error_unix_missing_dep", "Shadow file"))));
    return false;
  }
  if(!PlatformHelper::HasNativeLibrary("libcrypt.so.1")) {
    QMetaObject::invokeMethod(window, "showFatalErrorMessage",
                              Q_ARG(QVariant, QString::fromUtf8(I18n::Get("error_unix_missing_dep", "libcrypt.so.1 (libxcrypt-compat)"))));
    return false;
  }
  if(!PlatformHelper::HasNativeLibrary("libcrypto.so.3") || !PlatformHelper::HasNativeLibrary("libssl.so.3")) {
    QMetaObject::invokeMethod(window, "showFatalErrorMessage", Q_ARG(QVariant, QString::fromUtf8(I18n::Get("error_unix_missing_dep", "OpenSSL 3"))));
    return false;
  }
  if(!PlatformHelper::HasNativeLibrary("libbluetooth.so") && !PlatformHelper::HasNativeLibrary("libbluetooth.so.3")) {
    QMetaObject::invokeMethod(window, "showFatalErrorMessage",
                              Q_ARG(QVariant, QString::fromUtf8(I18n::Get("error_unix_missing_dep", "libbluetooth"))));
    return false;
  }
#endif
#endif
  const auto installedVersion = AppSettings::Get().installedVersion;
  if(ServiceInstaller::IsInstalled() && (AppInfo::CompareVersion(installedVersion, AppInfo::GetVersion()) == 1 || installedVersion.empty()))
    OnReinstallClicked(window);
  return true;
}

void MainWindow::Show(QObject *viewLoader) {
  QMetaObject::invokeMethod(viewLoader, "setSource", Q_ARG(QUrl, QUrl("qrc:/ui/forms/MainForm.qml")));
}

void MainWindow::OnInstallClicked(QObject *window) {
  if(m_LoadingThread.joinable())
    m_LoadingThread.join();
  m_LoadingThread = std::thread([window]() {
    QMetaObject::invokeMethod(window, "showLoadingScreen", Q_ARG(QVariant, QString::fromUtf8(I18n::Get("please_wait"))));
    auto logCallback = [window](const std::string &str) {
      spdlog::info(str);
      QMetaObject::invokeMethod(window, "appendLoadingOutput", Q_ARG(QVariant, QString::fromUtf8(str)));
    };
    // User asked for this, so privileged steps may prompt. thread_local, so
    // it has to be declared on the worker thread rather than the caller's.
    ElevationScope elevation{};
    auto installer = ServiceInstaller(logCallback);
    try {
      if(ServiceInstaller::IsInstalled()) {
        // Uninstall() deregisters from PAM itself before deleting anything.
        // ClearSettings() is no longer called here: doing it after Uninstall
        // left the PAM config pointing at a module that had already been
        // deleted, and an exception in between made that permanent.
        installer.Uninstall();
      } else {
        installer.Install();
        installer.ApplySettings(installer.GetSettings(), true);
      }
      AppSettings::SetInstalledVersion(ServiceInstaller::IsInstalled());
      QMetaObject::invokeMethod(window, "finishLoadingScreen", Q_ARG(QVariant, QString::fromUtf8(I18n::Get("success"))));
    } catch(const std::exception &ex) {
      logCallback(ex.what());
      QMetaObject::invokeMethod(window, "finishLoadingScreen", Q_ARG(QVariant, QString::fromUtf8(I18n::Get("error"))));
    }
  });
}

void MainWindow::OnReinstallClicked(QObject *window) {
  if(m_LoadingThread.joinable())
    m_LoadingThread.join();
  m_LoadingThread = std::thread([window]() {
    QMetaObject::invokeMethod(window, "showLoadingScreen", Q_ARG(QVariant, QString::fromUtf8(I18n::Get("please_wait"))));
    auto logCallback = [window](const std::string &str) {
      spdlog::info(str);
      QMetaObject::invokeMethod(window, "appendLoadingOutput", Q_ARG(QVariant, QString::fromUtf8(str)));
    };
    ElevationScope elevation{};
    auto installer = ServiceInstaller(logCallback);
    try {
      if(ServiceInstaller::IsInstalled())
        installer.Uninstall();
      installer.Install();
      installer.ApplySettings(installer.GetSettings(), false);
      AppSettings::SetInstalledVersion(true);
      QMetaObject::invokeMethod(window, "finishLoadingScreen", Q_ARG(QVariant, QString::fromUtf8(I18n::Get("success"))));
    } catch(const std::exception &ex) {
      logCallback(ex.what());
      QMetaObject::invokeMethod(window, "finishLoadingScreen", Q_ARG(QVariant, QString::fromUtf8(I18n::Get("error"))));
    }
  });
}

void MainWindow::OnRemoveDeviceClicked(QObject *viewLoader, const QString &pairingId) {
  PairedDevicesStorage::RemoveDevice(pairingId.toStdString());
  Show(viewLoader);
}

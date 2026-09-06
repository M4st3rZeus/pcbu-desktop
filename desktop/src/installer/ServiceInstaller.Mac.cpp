#include "ServiceInstaller.h"

#include "shell/Shell.h"
#include "utils/ResourceHelper.h"

#define EXE_MODULE_DIR std::filesystem::path("/usr/local/sbin/")
#define EXE_MODULE_FILE "pcbu_auth"

#define PAM_MODULE_DIR std::filesystem::path("/usr/local/lib/pam/")
#define PAM_MODULE_FILE "pam_pcbiounlock.dylib"

#define PAM_CONFIG_ENTRY "auth sufficient /usr/local/lib/pam/pam_pcbiounlock.dylib"

ServiceInstaller::ServiceInstaller(const std::function<void(const std::string &)> &logCallback) {
  m_Logger = logCallback;
  m_PAMHelper = PAMHelper(m_Logger);
}

std::vector<ServiceSetting> ServiceInstaller::GetSettings() {
  return {{"sudo", I18n::Get("service_setting_sudo"), PAMHelper::HasConfigEntry("sudo", PAM_CONFIG_ENTRY), true},
          {"macOS", I18n::Get("service_setting_macos"), PAMHelper::HasConfigEntry("authorization", PAM_CONFIG_ENTRY), false}};
}

void ServiceInstaller::ApplySettings(const std::vector<ServiceSetting> &settings, bool useDefault) {
  for(auto setting : settings) {
    auto isEnabled = useDefault ? setting.defaultVal : setting.enabled;
    if(setting.id == "sudo") {
      m_PAMHelper.SetConfigEntry("sudo", PAM_CONFIG_ENTRY, isEnabled);
    } else if(setting.id == "macOS") {
      m_PAMHelper.SetConfigEntry("authorization", PAM_CONFIG_ENTRY, isEnabled);
    } else {
      spdlog::warn("Unknown service setting {}.", setting.id);
    }
  }
}

bool ServiceInstaller::IsInstalled() {
  return std::filesystem::exists(EXE_MODULE_DIR / EXE_MODULE_FILE) && std::filesystem::exists(PAM_MODULE_DIR / PAM_MODULE_FILE);
}

void ServiceInstaller::Install() {
  m_Logger("Copying binary module...");
  auto nativeExe = ResourceHelper::GetResource(":/res/natives/{}", EXE_MODULE_FILE);
  auto exePath = EXE_MODULE_DIR / EXE_MODULE_FILE;
  auto result = Shell::WriteBytes(exePath, nativeExe);
  if(!result)
    throw std::runtime_error(I18n::Get("error_file_write", exePath.string()));
  result = Shell::RunCommand(fmt::format("chmod +x {0} && chmod u+s {0}", exePath.string())).exitCode == 0;
  if(!result)
    throw std::runtime_error(I18n::Get("error_exec_setuid", exePath.string()));

  m_Logger("Copying PAM module...");
  Shell::CreateDir(PAM_MODULE_DIR);
  auto pamModule = ResourceHelper::GetResource(":/res/natives/{}", PAM_MODULE_FILE);
  auto pamPath = PAM_MODULE_DIR / PAM_MODULE_FILE;
  result = Shell::WriteBytes(pamPath, pamModule);
  if(!result)
    throw std::runtime_error(I18n::Get("error_file_write", pamPath.string()));
  // ToDo: Firewall echo "pass in proto tcp from any to any port 43295" | sudo pfctl -ef -
  m_Logger("Done.");
}

void ServiceInstaller::Uninstall() {
  // Deregister from PAM *before* deleting anything.
  //
  // A `sufficient` line pointing at a missing module does not fail soft: PAM
  // refuses to initialise the whole stack, so sudo and every admin dialog
  // start rejecting correct passwords with "unable to initialize PAM". Doing
  // this in the caller (Uninstall then ClearSettings) left exactly that
  // window open, and an exception in between made it permanent - which is
  // how a failed reinstall locked a user out of authentication entirely.
  //
  // Removing the entries here means the config is never left referencing a
  // file that is about to disappear, whatever the caller does or however
  // this fails partway.
  m_Logger("Deregistering from PAM...");
  try {
    ClearSettings();
  } catch(const std::exception &ex) {
    // Keep going: leaving the binaries behind is recoverable, leaving PAM
    // pointing at a deleted module is not. Report it and continue.
    spdlog::error("Failed clearing PAM settings: {}", ex.what());
    m_Logger("Warning: could not fully deregister from PAM.");
  }

  m_Logger("Removing binary module...");
  auto exePath = EXE_MODULE_DIR / EXE_MODULE_FILE;
  auto result = Shell::RemoveFile(exePath);
  if(!result)
    throw std::runtime_error(I18n::Get("error_file_remove", exePath.string()));

  m_Logger("Removing PAM module...");
  auto pamPath = PAM_MODULE_DIR / PAM_MODULE_FILE;
  result = Shell::RemoveFile(pamPath);
  if(!result)
    throw std::runtime_error(I18n::Get("error_file_remove", pamPath.string()));
  m_Logger("Done.");
}

bool ServiceInstaller::IsProgramInstalled(const std::string &pathName) {
  return false;
}

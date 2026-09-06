#include "SessionLocker.h"

#include <cstdlib>
#include <spdlog/spdlog.h>
#include <vector>

#include "shell/Shell.h"

// Linux session lock.
//
// There is no single API. systemd-logind is the closest thing to a standard
// and covers most modern distros, but it only works when the session is
// registered with logind *and* the desktop environment implements the
// resulting Lock signal - a bare WM often does not. So this walks a chain of
// mechanisms and reports which one worked.
//
// Ordering is deliberate: logind first because it is the session manager and
// the DE-specific tools below all ultimately ask it or their own daemon,
// then the two big desktop buses, then generic screen lockers.
namespace {

struct LockMethod {
  const char *name;
  const char *probe;   // command that succeeds iff the mechanism exists
  const char *command; // the actual lock
};

// `probe` must not lock anything - it only establishes availability.
const std::vector<LockMethod> &Methods() {
  static const std::vector<LockMethod> methods = {
      // systemd-logind: locks the current session via the session manager.
      {"logind", "command -v loginctl", "loginctl lock-session"},
      // GNOME / Cinnamon.
      {"gnome-screensaver-dbus", "command -v gdbus",
       "gdbus call --session --dest org.gnome.ScreenSaver "
       "--object-path /org/gnome/ScreenSaver --method org.gnome.ScreenSaver.Lock"},
      // KDE Plasma.
      {"kde-screensaver-dbus", "command -v qdbus",
       "qdbus org.freedesktop.ScreenSaver /ScreenSaver Lock"},
      // Generic freedesktop screensaver interface.
      {"freedesktop-dbus", "command -v dbus-send",
       "dbus-send --session --dest=org.freedesktop.ScreenSaver "
       "--type=method_call /org/freedesktop/ScreenSaver "
       "org.freedesktop.ScreenSaver.Lock"},
      // Standalone lockers, for bare window managers.
      {"xdg-screensaver", "command -v xdg-screensaver", "xdg-screensaver lock"},
      {"swaylock", "command -v swaylock", "swaylock -f"},
      {"i3lock", "command -v i3lock", "i3lock"},
  };
  return methods;
}

bool HasMethod(const LockMethod &m) {
  return Shell::RunCommand(fmt::format("{} >/dev/null 2>&1", m.probe)).exitCode == 0;
}

// A lock needs a session to talk to. Without these the D-Bus calls below have
// no bus to reach, which is the usual symptom of running from a daemon
// context rather than inside the user's session.
bool HasSessionEnvironment() {
  return std::getenv("DBUS_SESSION_BUS_ADDRESS") != nullptr ||
         std::getenv("XDG_RUNTIME_DIR") != nullptr;
}

} // namespace

bool SessionLocker::LockSession() {
  if(!HasSessionEnvironment()) {
    spdlog::warn("SessionLocker: no session bus in the environment; the lock "
                 "agent is probably not running inside the user's session.");
  }

  for(const auto &m : Methods()) {
    if(!HasMethod(m))
      continue;
    auto result = Shell::RunCommand(fmt::format("{} >/dev/null 2>&1", m.command));
    if(result.exitCode == 0) {
      spdlog::info("Session locked. (Method={})", m.name);
      return true;
    }
    // Present but failed - try the next one rather than giving up, since a
    // machine can have loginctl installed while the DE ignores its signal.
    spdlog::debug("SessionLocker: {} failed. (Code={})", m.name, result.exitCode);
  }

  spdlog::error("Failed to lock session: no working mechanism found.");
  return false;
}

bool SessionLocker::IsAvailable() {
  for(const auto &m : Methods()) {
    if(HasMethod(m))
      return true;
  }
  return false;
}

std::string SessionLocker::UnavailableReason() {
  if(IsAvailable())
    return {};
  return "No supported screen locker found. Install one of loginctl, "
         "xdg-screensaver, swaylock or i3lock, or enable your desktop's "
         "screensaver D-Bus interface.";
}

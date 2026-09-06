#include "SessionLocker.h"

#include <dlfcn.h>
#include <spdlog/spdlog.h>

#include "shell/Shell.h"

// macOS session lock.
//
// There is no public API for "lock the screen now". The three candidates:
//
//   1. SACLockScreenImmediate() in the private login.framework. This is what
//      the Apple menu's "Lock Screen" item calls, so it is the real thing and
//      it locks immediately. Private, hence resolved with dlsym at runtime
//      rather than linked: if a future macOS drops it we log and fall back
//      instead of failing to launch.
//
//   2. CGSession -suspend. Fast-user-switches to the login window rather than
//      locking, and the binary no longer exists at its documented path on
//      recent macOS. Not used.
//
//   3. pmset displaysleepnow. Only sleeps the display. It locks *if* the user
//      has "require password after sleep" set, which many do not, so on its
//      own it is not a lock. Used only as a last resort, and logged as such
//      so nobody mistakes it for a guarantee.
namespace {

constexpr auto LOGIN_FRAMEWORK = "/System/Library/PrivateFrameworks/login.framework/Versions/Current/login";
using SACLockScreenImmediateFn = int (*)(void);

// Resolved once; dlopen on a system framework is cheap but not free, and the
// lock path can be hit repeatedly.
SACLockScreenImmediateFn ResolveLockFn() {
  static SACLockScreenImmediateFn cached = [] {
    auto handle = dlopen(LOGIN_FRAMEWORK, RTLD_LAZY);
    if(handle == nullptr) {
      spdlog::warn("SessionLocker: could not open login.framework. ({})", dlerror());
      return static_cast<SACLockScreenImmediateFn>(nullptr);
    }
    // Intentionally not dlclose'd: the pointer must stay valid for the
    // process lifetime, and the framework is a system library anyway.
    auto fn = reinterpret_cast<SACLockScreenImmediateFn>(dlsym(handle, "SACLockScreenImmediate"));
    if(fn == nullptr)
      spdlog::warn("SessionLocker: SACLockScreenImmediate not found in login.framework.");
    return fn;
  }();
  return cached;
}

} // namespace

bool SessionLocker::LockSession() {
  if(auto fn = ResolveLockFn(); fn != nullptr) {
    auto result = fn();
    if(result == 0) {
      spdlog::info("Session locked.");
      return true;
    }
    spdlog::error("SACLockScreenImmediate failed. (Code={})", result);
  }

  // Fallback. This only truly locks when the user requires a password after
  // sleep, so say plainly that it is not equivalent.
  spdlog::warn("Falling back to display sleep; this locks only if 'require password after sleep' is enabled.");
  auto cmd = Shell::RunCommand("pmset displaysleepnow");
  if(cmd.exitCode == 0)
    return true;

  spdlog::error("Failed to lock session. (pmset exit={})", cmd.exitCode);
  return false;
}

bool SessionLocker::IsAvailable() {
  return ResolveLockFn() != nullptr;
}

std::string SessionLocker::UnavailableReason() {
  if(IsAvailable())
    return {};
  return "This macOS build does not expose SACLockScreenImmediate; only display sleep is available.";
}

#include "SessionLocker.h"

#include <Windows.h>
#include <spdlog/spdlog.h>

// Windows session lock.
//
// LockWorkStation() is the documented API and does exactly what the Win+L
// shortcut does. The one constraint that matters here: it locks the session
// of the *calling process*, and it fails outright if called from a service
// running in session 0. That is why the lock listener has to live in the
// user's interactive session rather than in a SYSTEM service - see the
// comment in SessionLocker.h.
bool SessionLocker::LockSession() {
  if(LockWorkStation()) {
    spdlog::info("Session locked.");
    return true;
  }

  auto err = GetLastError();
  // ERROR_ACCESS_DENIED here almost always means "called from session 0",
  // which is a deployment mistake rather than a transient failure, so it is
  // worth calling out specifically.
  if(err == ERROR_ACCESS_DENIED) {
    spdlog::error("LockWorkStation denied. The lock agent must run in the user's "
                  "interactive session, not as a session-0 service.");
  } else {
    spdlog::error("LockWorkStation failed. (Code={})", err);
  }
  return false;
}

bool SessionLocker::IsAvailable() {
  // The API is always present; whether it will succeed depends on the session
  // the process lives in, which cannot be probed without actually locking.
  // Report the obvious disqualifier instead: session 0 is never interactive.
  DWORD sessionId = 0;
  if(ProcessIdToSessionId(GetCurrentProcessId(), &sessionId))
    return sessionId != 0;
  return true;
}

std::string SessionLocker::UnavailableReason() {
  if(IsAvailable())
    return {};
  return "Running in session 0. LockWorkStation only works from an interactive "
         "user session.";
}

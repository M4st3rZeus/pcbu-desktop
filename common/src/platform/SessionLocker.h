#ifndef PCBU_DESKTOP_SESSIONLOCKER_H
#define PCBU_DESKTOP_SESSIONLOCKER_H

#include <string>

// Locks the *currently running* desktop session.
//
// This is the opposite side of unlock and has a different constraint. Unlock
// runs at the login screen, where PAM (or the Windows credential provider)
// invokes us. Lock has no such hook: it can only work from inside a live
// session, because that is where the session bus, the window server, and the
// user's own credentials live. A root daemon cannot lock a session it is not
// part of on any of the three platforms without impersonating the user.
//
// Consequently every backend here is best-effort and reports failure honestly
// rather than pretending. A lock that silently did nothing would be worse
// than one that logs "could not lock" — the user would believe the machine
// was secured when it was not.
class SessionLocker {
public:
  // Locks the session this process belongs to.
  //
  // Returns false when the platform refused or no supported mechanism was
  // found. Never throws: callers are usually on a network thread.
  static bool LockSession();

  // Whether a lock mechanism is available in this context. Lets the agent
  // warn at startup instead of only at the moment the user walks away.
  static bool IsAvailable();

  // Human-readable reason [IsAvailable] returned false, for logs and UI.
  static std::string UnavailableReason();

private:
  SessionLocker() = default;
};

#endif // PCBU_DESKTOP_SESSIONLOCKER_H

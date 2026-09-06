#ifndef PCBU_DESKTOP_ELEVATOR_H
#define PCBU_DESKTOP_ELEVATOR_H

#include <memory>
#include <string>

#include "shell/Shell.h"

// Runs privileged commands without making the whole GUI root.
//
// Why not just relaunch the app elevated: the lock server has to live in the
// user's own interactive session, because every platform's lock API refuses
// to act on a session the caller is not part of. A root GUI sits in a
// different session and would silently break remote lock. Keeping the GUI
// unprivileged also means a bug in the QML layer is not a bug with root.
//
// One helper process is spawned on first use and reused for the rest of the
// session, so the user authenticates once rather than per operation. It dies
// with the GUI: the helper exits as soon as its stdin closes.
class Elevator {
public:
  Elevator();
  ~Elevator();

  Elevator(const Elevator &) = delete;
  Elevator &operator=(const Elevator &) = delete;

  // Whether a privileged helper is currently running.
  [[nodiscard]] bool IsElevated() const;

  // Starts the helper, prompting the user for credentials.
  //
  // Returns false when the prompt was cancelled or elevation failed - both
  // are ordinary outcomes, not errors, and the caller should stay usable in
  // a reduced mode rather than treating this as fatal.
  bool Elevate();

  // Runs one command as root, starting the helper if needed.
  //
  // The command is executed verbatim. Never interpolate untrusted input:
  // there is no sanitising layer, by design (see the helper's own comment).
  ShellCmdResult Run(const std::string &command);

  // Stops the helper. Safe to call when not running.
  void Shutdown();

private:
  struct Impl;
  std::unique_ptr<Impl> m_Impl;
};

// Process-wide instance, so one authentication covers the whole session.
Elevator &GetElevator();

// Scope guard marking a block as user-initiated, and therefore allowed to
// raise an authentication prompt.
//
// Elevation is opt-in because prompting must never be a side effect of
// something the user did not ask for. Startup reads are the motivating case:
// PairedDevicesStorage::GetDevices() rewrites the store when it cannot parse
// it, so without this guard merely launching the app asks for a password
// before any window appears - which reads as "the app is broken", and trains
// users to type credentials at unexplained prompts.
//
// Wrap the handler for an explicit action (Install, Uninstall, Pair, applying
// settings) and everything underneath may elevate. Outside such a scope,
// privileged operations fail quietly and the caller degrades.
class ElevationScope {
public:
  ElevationScope();
  ~ElevationScope();

  ElevationScope(const ElevationScope &) = delete;
  ElevationScope &operator=(const ElevationScope &) = delete;

  // Whether elevation is permitted here: either this thread is inside a
  // scope, or a session-wide window is open.
  static bool IsAllowed();
};

// Opens elevation for every thread until closed.
//
// ElevationScope is thread_local, which is right for a self-contained action
// but wrong when the work crosses threads. Pairing is the case that forced
// this: the user starts it in the UI, and it completes minutes later on the
// PairingServer's client thread when the phone finally connects. A
// thread_local scope opened at the start cannot reach that write.
//
// Prefer ElevationScope. Reach for this only when a user-initiated action
// hands off to another thread, and keep the window as short as the action -
// it is a standing permission to prompt, so leaving one open indefinitely
// would let a prompt appear long after the user forgot what they clicked.
class ElevationSession {
public:
  explicit ElevationSession(std::string reason);
  ~ElevationSession();

  ElevationSession(const ElevationSession &) = delete;
  ElevationSession &operator=(const ElevationSession &) = delete;

  // Ends the window early. Idempotent.
  void Close();

private:
  std::string m_Reason;
  bool m_Open{};
};

#endif // PCBU_DESKTOP_ELEVATOR_H

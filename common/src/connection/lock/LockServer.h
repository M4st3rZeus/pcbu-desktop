#ifndef PCBU_DESKTOP_LOCKSERVER_H
#define PCBU_DESKTOP_LOCKSERVER_H

#include <atomic>
#include <functional>
#include <thread>
#include <vector>

#include "connection/BaseConnection.h"
#include "storage/PairedDevicesStorage.h"

// Default port for the lock listener. Distinct from the unlock ports so the
// two can run simultaneously without contention.
constexpr uint16_t DEFAULT_LOCK_SERVER_PORT = 43294;

// Listens for phone-initiated lock commands and locks the running session.
//
// **Why this exists as its own server.** Unlock is driven by the login screen:
// PAM or the Windows credential provider spawns pcbu_auth, which lives for the
// duration of one attempt. Nothing in that design is running while the user is
// logged in, so there is nobody to receive a lock command. This server is the
// resident half, and it must run *inside the user's interactive session* -
// every platform's lock API refuses to act on a session the caller is not part
// of (see SessionLocker.h).
//
// **Handshake.** Deliberately the mirror of unlock, with the PC still owning
// the nonce:
//
//   phone connects
//   PC   -> PACKET_ID_LOCK_CHALLENGE   fresh lockToken, plaintext
//   phone-> PACKET_ID_LOCK_REQUEST     AES-GCM{lockToken, reason}
//   PC   -> PACKET_ID_LOCK_RESPONSE    result
//
// The challenge is plaintext on purpose: it is a public nonce, not a secret,
// and it is worthless without the paired key needed to echo it back inside an
// authenticated packet. Making the phone speak first would mean a captured
// lock request replays for the whole +/-2min crypto window.
//
// **Threat model.** A spurious lock is a nuisance, not a breach - the worst
// case is the user retyping their password. That asymmetry is why locking is
// allowed to be automatic while unlocking still requires the full
// challenge-response plus a local password check. It is *not* a reason to skip
// authentication here: an unauthenticated lock endpoint would be a trivial
// denial of service against the machine.
class LockServer : public BaseConnection {
public:
  explicit LockServer(uint16_t port = DEFAULT_LOCK_SERVER_PORT);
  ~LockServer() override;

  bool IsServer() override;

  bool Start();
  void Stop();

  [[nodiscard]] bool IsRunning() const { return m_IsRunning; }

  // Invoked after a successful, authenticated lock. Optional; for UI/logging.
  std::function<void(const PairedDevice &, const std::string &reason)> OnLocked{};

private:
  void AcceptThread();
  void ClientThread(SOCKET clientSocket);

  // Runs one full handshake. Returns true when the session was locked.
  bool HandleClient(SOCKET clientSocket);

  uint16_t m_Port;
  SOCKET m_ServerSocket;
  std::atomic<bool> m_IsRunning{};
  std::thread m_AcceptThread{};
  std::atomic<int> m_NumConnections{};
};

#endif // PCBU_DESKTOP_LOCKSERVER_H

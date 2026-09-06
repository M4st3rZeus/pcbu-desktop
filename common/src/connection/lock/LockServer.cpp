#include "LockServer.h"

#include <chrono>
#include <spdlog/spdlog.h>

#include "connection/Packets.h"
#include "connection/SocketDefs.h"
#include "platform/SessionLocker.h"
#include "utils/AppInfo.h"
#include "utils/CryptUtils.h"
#include "utils/StringUtils.h"

#ifdef WINDOWS
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/tcp.h>
#endif

namespace {
constexpr int MAX_CLIENTS = 4;
// A lock exchange is two round trips; anything slower is a stalled peer.
constexpr uint32_t CLIENT_TIMEOUT_SECS = 15;
} // namespace

LockServer::LockServer(uint16_t port) : m_Port(port), m_ServerSocket(SOCKET_INVALID) {}

LockServer::~LockServer() {
  Stop();
}

bool LockServer::IsServer() {
  return true;
}

bool LockServer::Start() {
  if(m_IsRunning)
    return true;

  if(!SessionLocker::IsAvailable()) {
    // Start anyway - the user may install a locker later - but say so now
    // rather than only when they walk away and nothing happens.
    spdlog::warn("Lock server starting, but locking is unavailable: {}", SessionLocker::UnavailableReason());
  }

  WSA_STARTUP
  m_IsRunning = true;
  m_AcceptThread = std::thread(&LockServer::AcceptThread, this);
  return true;
}

void LockServer::Stop() {
  if(!m_IsRunning)
    return;
  m_IsRunning = false;
  SOCKET_CLOSE(m_ServerSocket);
  if(m_AcceptThread.joinable())
    m_AcceptThread.join();
}

void LockServer::AcceptThread() {
  struct sockaddr_in address{};
  socklen_t addrLen = sizeof(address);
  auto clientThreads = std::vector<std::thread>();
  spdlog::info("Starting lock server on port {}...", m_Port);

  if((m_ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_INVALID) {
    spdlog::error("Lock server socket() failed. (Code={})", SOCKET_LAST_ERROR);
    m_IsRunning = false;
    return;
  }

  int opt = 1;
#ifndef WINDOWS
  if(setsockopt(m_ServerSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&opt), sizeof(opt)))
    spdlog::warn("Lock server setsockopt(SO_REUSEADDR) failed. (Code={})", SOCKET_LAST_ERROR);
#endif

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(m_Port);
  if(bind(m_ServerSocket, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) < 0) {
    spdlog::error("Lock server bind() failed. (Port={}, Code={})", m_Port, SOCKET_LAST_ERROR);
    goto threadEnd;
  }
  if(listen(m_ServerSocket, MAX_CLIENTS) < 0) {
    spdlog::error("Lock server listen() failed. (Code={})", SOCKET_LAST_ERROR);
    goto threadEnd;
  }
  if(!SetSocketBlocking(m_ServerSocket, false)) {
    spdlog::error("Lock server failed to set non-blocking mode. (Code={})", SOCKET_LAST_ERROR);
    goto threadEnd;
  }
  spdlog::info("Lock server started.");

  while(m_IsRunning) {
    if(m_NumConnections >= MAX_CLIENTS) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      continue;
    }
    SOCKET clientSocket;
    if((clientSocket = accept(m_ServerSocket, reinterpret_cast<struct sockaddr *>(&address), &addrLen)) == SOCKET_INVALID) {
      auto err = SOCKET_LAST_ERROR;
      if(err == SOCKET_ERROR_TRY_AGAIN || err == SOCKET_ERROR_WOULD_BLOCK) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        continue;
      }
      if(err != SOCKET_ERROR_CONNECT_ABORTED)
        spdlog::error("Lock server accept() failed. (Code={})", err);
      break;
    }
    clientThreads.emplace_back(&LockServer::ClientThread, this, clientSocket);
  }

threadEnd:
  SOCKET_CLOSE(m_ServerSocket);
  for(auto &thread : clientThreads)
    if(thread.joinable())
      thread.join();
  m_IsRunning = false;
  spdlog::info("Lock server stopped.");
}

void LockServer::ClientThread(SOCKET clientSocket) {
  ++m_NumConnections;
  // Blocking with a timeout: the handshake is short and a stalled peer must
  // not hold a slot forever.
  SetSocketBlocking(clientSocket, true);
  SetSocketRWTimeout(clientSocket, CLIENT_TIMEOUT_SECS);

  int opt = 1;
  setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&opt), sizeof(opt));

  HandleClient(clientSocket);

  SOCKET_CLOSE(clientSocket);
  --m_NumConnections;
}

bool LockServer::HandleClient(SOCKET clientSocket) {
  // 1. Issue a fresh nonce. Plaintext by design: it is public, and useless
  //    without the paired key needed to echo it inside an authenticated
  //    packet. Generating it per connection is what stops a captured lock
  //    request from being replayed.
  auto lockToken = StringUtils::RandomString(64);
  auto challenge = PacketLockChallenge();
  challenge.lockToken = lockToken;
  auto challengeStr = challenge.ToJson().dump();
  if(WritePacket(clientSocket, PACKET_ID_LOCK_CHALLENGE, {challengeStr.begin(), challengeStr.end()}) != PacketError::NONE) {
    spdlog::debug("Lock: failed to send challenge.");
    return false;
  }

  // 2. Read the phone's request.
  auto packet = ReadPacket(clientSocket);
  if(packet.error != PacketError::NONE || packet.id != PACKET_ID_LOCK_REQUEST) {
    spdlog::debug("Lock: no valid request. (Error={}, ID={:X})", static_cast<int>(packet.error), packet.id);
    return false;
  }

  auto respond = [&](const std::string &error, bool locked) {
    auto resp = PacketLockResponse();
    resp.error = error;
    resp.locked = locked;
    auto s = resp.ToJson().dump();
    WritePacket(clientSocket, PACKET_ID_LOCK_RESPONSE, {s.begin(), s.end()});
  };

  auto request = PacketLockRequest::FromJson({packet.data.begin(), packet.data.end()});
  if(!request.has_value()) {
    spdlog::error("Lock: malformed request.");
    respond("DATA_ERROR", false);
    return false;
  }
  if(request->protoVersion != AppInfo::GetUnlockProtocolVersion()) {
    spdlog::error("Lock: protocol mismatch. (Got={})", request->protoVersion);
    respond("PROTOCOL_ERROR", false);
    return false;
  }

  // 3. The device must be one we have paired with. An unknown id gets nothing.
  auto device = PairedDevicesStorage::GetDeviceByID(request->deviceId);
  if(!device.has_value()) {
    spdlog::error("Lock: unknown device id.");
    respond("NOT_PAIRED", false);
    return false;
  }

  // 4. Decrypt with that device's key. This is the authentication: only a
  //    holder of the paired key can produce a packet that survives the GCM
  //    tag check.
  auto cryptData = StringUtils::FromHexString(request->encData);
  auto cryptResult = CryptUtils::DecryptAESPacket(cryptData, device->encryptionKey);
  if(cryptResult.result != PacketCryptResult::OK) {
    if(cryptResult.result == PacketCryptResult::INVALID_TIMESTAMP) {
      spdlog::error("Lock: stale packet timestamp.");
      respond("TIME_ERROR", false);
    } else {
      spdlog::error("Lock: could not decrypt request.");
      respond("DATA_ERROR", false);
    }
    return false;
  }

  auto data = PacketLockRequestData::FromJson({cryptResult.data.begin(), cryptResult.data.end()});
  if(!data.has_value()) {
    spdlog::error("Lock: malformed request data.");
    respond("DATA_ERROR", false);
    return false;
  }

  // 5. The echoed nonce must match the one we just issued. Freshness, so a
  //    recorded exchange cannot be replayed within the crypto window.
  if(data->lockToken != lockToken) {
    spdlog::error("Lock: token mismatch; possible replay.");
    respond("DATA_ERROR", false);
    return false;
  }

  spdlog::info("Authenticated lock request from '{}'. (Reason={})", device->deviceName,
               data->reason.empty() ? "unspecified" : data->reason);

  auto locked = SessionLocker::LockSession();
  respond(locked ? "" : "APP_ERROR", locked);
  if(locked && OnLocked)
    OnLocked(device.value(), data->reason);
  return locked;
}

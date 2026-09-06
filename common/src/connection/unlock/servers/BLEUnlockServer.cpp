#include "BLEUnlockServer.h"

#include <cstring>
#include <spdlog/spdlog.h>

#include "utils/AppInfo.h"
#include "utils/CryptUtils.h"
#include "utils/StringUtils.h"

#ifdef WINDOWS
#include <WinSock2.h>
#elif LINUX
#include <arpa/inet.h>
#endif

BLEUnlockServer::BLEUnlockServer(const PairedDevice &device) : BaseUnlockConnection(device) {}

BLEUnlockServer::~BLEUnlockServer() {
  Stop();
}

bool BLEUnlockServer::IsServer() {
  // The PC advertises and waits, exactly like the TCP server case, so the
  // handler prints the "waiting for phone to connect" message.
  return true;
}

bool BLEUnlockServer::Start() {
  if(m_IsRunning)
    return true;

  m_Peripheral = CreateBLEPeripheral();
  if(!m_Peripheral) {
    spdlog::error("BLE is not supported on this platform.");
    return false;
  }

  m_Peripheral->OnChunkReceived = [this](const uint8_t *data, size_t len) { HandleChunk(data, len); };
  m_Peripheral->OnCentralConnected = [this]() {
    spdlog::info("BLE central connected.");
    m_HasConnection = true;
    // A re-subscribe must not start a second exchange: the phone would be
    // asked to approve the same unlock twice, which is the bug the TCP
    // server had.
    if(m_SentRequest) {
      spdlog::info("BLE: request already sent; ignoring re-subscribe.");
      return;
    }
    // The phone cannot announce its device id before we know it is there, so
    // the request goes out as soon as it subscribes.
    if(!SendUnlockRequestBLE())
      spdlog::error("Failed to send BLE unlock request.");
  };
  m_Peripheral->OnCentralDisconnected = [this]() {
    spdlog::info("BLE central disconnected.");
    m_HasConnection = false;
    m_Reassembler.Reset();
    // A drop before any verdict is a connection failure, not a denial.
    if(m_UnlockState == UnlockState::UNKNOWN)
      m_UnlockState = UnlockState::CONNECT_ERROR;
  };

  if(!m_Peripheral->Start()) {
    spdlog::error("Failed to start BLE peripheral.");
    m_Peripheral.reset();
    return false;
  }

  m_IsRunning = true;
  spdlog::info("BLE unlock server started. (Service={})", BLE_SERVICE_UUID);
  return true;
}

void BLEUnlockServer::Stop() {
  if(!m_IsRunning)
    return;

  m_IsRunning = false;
  m_HasConnection = false;
  if(m_Peripheral) {
    m_Peripheral->Stop();
    m_Peripheral.reset();
  }
  m_Reassembler.Reset();
  spdlog::info("BLE unlock server stopped.");
}

void BLEUnlockServer::HandleChunk(const uint8_t *data, size_t length) {
  std::lock_guard lock(m_BLEMutex);
  auto frame = m_Reassembler.Add(data, length);
  if(!frame.has_value()) {
    // A rejected chunk is logged by the reassembler. Keep the link up: the
    // handler's own timeout ends the exchange if nothing valid follows.
    return;
  }
  HandleFrame(frame.value());
}

// Parses one reassembled frame. Mirrors BaseConnection::ReadPacket, but over a
// complete buffer instead of a socket, since BLE hands us whole frames.
void BLEUnlockServer::HandleFrame(const std::vector<uint8_t> &frame) {
  constexpr size_t headerLen = sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint16_t);
  if(frame.size() < headerLen) {
    spdlog::error("BLE frame shorter than its header. (Size={})", frame.size());
    return;
  }

  uint64_t magic{};
  std::memcpy(&magic, frame.data(), sizeof(magic));
  if(magic != htonll(PACKET_HEADER)) {
    spdlog::error("BLE frame has a bad magic header.");
    return;
  }

  uint16_t packetId{};
  std::memcpy(&packetId, frame.data() + sizeof(uint64_t), sizeof(packetId));
  packetId = ntohs(packetId);

  uint16_t packetLen{};
  std::memcpy(&packetLen, frame.data() + sizeof(uint64_t) + sizeof(uint16_t), sizeof(packetLen));
  packetLen = ntohs(packetLen);

  if(frame.size() != headerLen + packetLen) {
    spdlog::error("BLE frame length mismatch. (Declared={}, Actual={})", packetLen, frame.size() - headerLen);
    return;
  }

  std::vector<uint8_t> payload(frame.begin() + static_cast<long>(headerLen), frame.end());
  switch(packetId) {
    case PACKET_ID_DEVICE_ID: {
      // The phone announces itself. This server is already bound to one paired
      // device, so treat a mismatch as someone else's phone and ignore it.
      auto deviceId = std::string(payload.begin(), payload.end());
      if(deviceId != m_PairedDevice.id) {
        spdlog::warn("BLE device ID mismatch; ignoring.");
        return;
      }
      break;
    }
    case PACKET_ID_UNLOCK_RESPONSE: {
      if(!m_SentRequest) {
        spdlog::error("Unexpected BLE unlock response before a request.");
        return;
      }
      OnUnlockResponse(payload);
      break;
    }
    default:
      spdlog::error("Invalid BLE packet. (ID={0:X})", packetId);
      break;
  }
}

bool BLEUnlockServer::WriteFrame(uint16_t packetId, const std::vector<uint8_t> &data) {
  if(!m_Peripheral)
    return false;
  if(data.size() > 0xFFFF) {
    spdlog::error("BLE payload too large. (Size={})", data.size());
    return false;
  }

  // Build the same frame BaseConnection::WritePacket produces, then chunk it.
  std::vector<uint8_t> frame{};
  frame.reserve(sizeof(uint64_t) + 2 * sizeof(uint16_t) + data.size());

  auto magic = htonll(PACKET_HEADER);
  auto idNet = htons(packetId);
  auto lenNet = htons(static_cast<uint16_t>(data.size()));

  auto append = [&frame](const void *src, size_t n) {
    auto p = static_cast<const uint8_t *>(src);
    frame.insert(frame.end(), p, p + n);
  };
  append(&magic, sizeof(magic));
  append(&idNet, sizeof(idNet));
  append(&lenNet, sizeof(lenNet));
  frame.insert(frame.end(), data.begin(), data.end());

  auto budget = m_Peripheral->GetMaxPayloadPerChunk();
  if(budget < 1)
    budget = BLE_DEFAULT_PAYLOAD_PER_CHUNK;

  for(const auto &chunk : BLEChunking::ChunkFrame(frame, budget)) {
    if(!m_Peripheral->SendChunk(chunk)) {
      spdlog::error("Failed to send BLE chunk.");
      return false;
    }
  }
  return true;
}

bool BLEUnlockServer::SendUnlockRequestBLE() {
  auto encData = PacketUnlockRequestData();
  encData.user = m_AuthUser;
  encData.program = m_AuthProgram;
  encData.unlockToken = m_UnlockToken;

  auto encDataStr = encData.ToJson().dump();
  auto cryptResult = CryptUtils::EncryptAESPacket({encDataStr.begin(), encDataStr.end()}, m_PairedDevice.encryptionKey);
  if(cryptResult.result != PacketCryptResult::OK) {
    spdlog::error("Failed to encrypt BLE unlock request packet.");
    m_UnlockState = UnlockState::UNK_ERROR;
    return false;
  }

  auto requestPacket = PacketUnlockRequest();
  requestPacket.protoVersion = AppInfo::GetUnlockProtocolVersion();
  requestPacket.deviceId = m_PairedDevice.id;
  requestPacket.encData = StringUtils::ToHexString(cryptResult.data);

  auto requestStr = requestPacket.ToJson().dump();
  if(!WriteFrame(PACKET_ID_UNLOCK_REQUEST, {requestStr.begin(), requestStr.end()})) {
    m_UnlockState = UnlockState::CONNECT_ERROR;
    return false;
  }
  m_SentRequest = true;
  return true;
}

// Mirrors BaseUnlockConnection::OnResponseReceived. Duplicated rather than
// shared because that method is private and socket-oriented; the logic below
// must stay in step with it.
void BLEUnlockServer::OnUnlockResponse(const std::vector<uint8_t> &payload) {
  auto respStr = std::string(payload.begin(), payload.end());
  auto responsePacket = PacketUnlockResponse::FromJson(respStr);
  if(!responsePacket.has_value()) {
    spdlog::error("Error parsing BLE response packet.");
    m_UnlockState = UnlockState::DATA_ERROR;
    return;
  }

  auto error = responsePacket.value().error;
  if(!error.empty()) {
    spdlog::error("Error in BLE response packet: {}", error);
    if(error == "CANCEL")
      m_UnlockState = UnlockState::CANCELED;
    else if(error == "NOT_PAIRED")
      m_UnlockState = UnlockState::NOT_PAIRED_ERROR;
    else if(error == "APP_ERROR")
      m_UnlockState = UnlockState::APP_ERROR;
    else if(error == "TIME_ERROR")
      m_UnlockState = UnlockState::TIME_ERROR;
    else if(error == "DATA_ERROR")
      m_UnlockState = UnlockState::DATA_ERROR;
    else if(error == "PROTOCOL_ERROR")
      m_UnlockState = UnlockState::PROTOCOL_ERROR;
    else
      m_UnlockState = UnlockState::UNK_ERROR;
    return;
  }

  auto cryptData = StringUtils::FromHexString(responsePacket.value().encData);
  auto cryptResult = CryptUtils::DecryptAESPacket(cryptData, m_PairedDevice.encryptionKey);
  if(cryptResult.result != PacketCryptResult::OK) {
    if(cryptResult.result == PacketCryptResult::INVALID_TIMESTAMP) {
      spdlog::error("Invalid timestamp on BLE AES data.");
      m_UnlockState = UnlockState::TIME_ERROR;
    } else {
      spdlog::error("Invalid BLE data received. (Size={})", payload.size());
      m_UnlockState = UnlockState::DATA_ERROR;
    }
    return;
  }

  auto dataStr = std::string(cryptResult.data.begin(), cryptResult.data.end());
  auto dataPacket = PacketUnlockResponseData::FromJson(dataStr);
  if(!dataPacket.has_value()) {
    spdlog::error("Error parsing BLE response data.");
    m_UnlockState = UnlockState::DATA_ERROR;
    return;
  }
  m_ResponseData = dataPacket.value();

  // The echoed token is what proves freshness; a replayed response carries a
  // token from an earlier exchange and fails here.
  if(m_ResponseData.unlockToken == m_UnlockToken)
    m_UnlockState = UnlockState::SUCCESS;
  else
    m_UnlockState = UnlockState::UNK_ERROR;
}

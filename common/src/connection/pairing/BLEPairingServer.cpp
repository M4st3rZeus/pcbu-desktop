#include "BLEPairingServer.h"

#include <cstring>
#include <spdlog/spdlog.h>

#include "connection/Packets.h"
#include "platform/NetworkHelper.h"
#include "platform/PlatformHelper.h"
#include "storage/AppSettings.h"
#include "storage/PairedDevicesStorage.h"
#include "utils/AppInfo.h"
#include "utils/CryptUtils.h"
#include "utils/I18n.h"
#include "utils/StringUtils.h"

#ifdef WINDOWS
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

BLEPairingServer::BLEPairingServer(const std::function<void(const std::string &)> &errorCallback)
    : m_ErrorCallback(errorCallback) {}

BLEPairingServer::~BLEPairingServer() {
  Stop();
}

bool BLEPairingServer::Start(const PairingUIData &uiData) {
  if(m_IsRunning)
    return true;

  m_UIData = uiData;
  m_Paired = false;
  m_Reassembler.Reset();

  m_Peripheral = CreateBLEPeripheral(BLEServiceIds{BLE_PAIRING_SERVICE_UUID, BLE_PAIRING_RX_CHAR_UUID,
                                                   BLE_PAIRING_TX_CHAR_UUID, "PC Bio Unlock Pairing"});
  if(!m_Peripheral) {
    spdlog::error("BLE pairing is not supported on this platform.");
    m_ErrorCallback(I18n::Get("error_pairing_server_init_unk"));
    return false;
  }

  m_Peripheral->OnChunkReceived = [this](const uint8_t *data, size_t len) { HandleChunk(data, len); };
  m_Peripheral->OnCentralDisconnected = [this]() {
    // Drop any partial frame so a reconnecting phone starts clean rather than
    // splicing its first chunk onto the last attempt's remainder.
    std::lock_guard lock(m_Mutex);
    m_Reassembler.Reset();
  };

  if(!m_Peripheral->Start()) {
    spdlog::error("Failed to start the BLE pairing peripheral.");
    m_ErrorCallback(I18n::Get("error_pairing_server_init_unk"));
    m_Peripheral.reset();
    return false;
  }

  m_IsRunning = true;
  spdlog::info("BLE pairing server started. (Service={})", BLE_PAIRING_SERVICE_UUID);
  return true;
}

void BLEPairingServer::Stop() {
  if(!m_IsRunning)
    return;
  m_IsRunning = false;
  if(m_Peripheral) {
    m_Peripheral->Stop();
    m_Peripheral.reset();
  }
  std::lock_guard lock(m_Mutex);
  m_Reassembler.Reset();
  spdlog::info("BLE pairing server stopped.");
}

void BLEPairingServer::HandleChunk(const uint8_t *data, size_t length) {
  std::lock_guard lock(m_Mutex);
  auto frame = m_Reassembler.Add(data, length);
  if(!frame.has_value())
    return; // More chunks expected, or the reassembler rejected this one.
  HandleFrame(frame.value());
}

// Parses one reassembled frame. Mirrors BaseConnection::ReadPacket, but over a
// complete buffer rather than a socket, since BLE delivers whole frames.
void BLEPairingServer::HandleFrame(const std::vector<uint8_t> &frame) {
  constexpr size_t headerLen = sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint16_t);
  if(frame.size() < headerLen) {
    spdlog::error("BLE pairing frame shorter than its header. (Size={})", frame.size());
    return;
  }

  uint64_t magic{};
  std::memcpy(&magic, frame.data(), sizeof(magic));
  if(magic != htonll(PACKET_HEADER)) {
    spdlog::error("BLE pairing frame has a bad magic header.");
    return;
  }

  uint16_t packetId{};
  std::memcpy(&packetId, frame.data() + sizeof(uint64_t), sizeof(packetId));
  packetId = ntohs(packetId);
  if(packetId != PACKET_ID_PAIR_INIT) {
    spdlog::error("Unexpected BLE pairing packet. (ID={0:X})", packetId);
    return;
  }

  uint16_t packetLen{};
  std::memcpy(&packetLen, frame.data() + sizeof(uint64_t) + sizeof(uint16_t), sizeof(packetLen));
  packetLen = ntohs(packetLen);
  if(frame.size() != headerLen + packetLen) {
    spdlog::error("BLE pairing frame length mismatch. (Declared={}, Actual={})", packetLen,
                  frame.size() - headerLen);
    return;
  }

  // One pairing per session: a re-subscribing phone must not create a second
  // device, and a second phone must not race the first.
  if(m_Paired) {
    spdlog::warn("BLE pairing: already paired this session; ignoring.");
    return;
  }

  std::vector<uint8_t> payload(frame.begin() + static_cast<long>(headerLen), frame.end());
  auto decRes = CryptUtils::DecryptAESPacket(payload, m_UIData.encKey);
  if(decRes.result != PacketCryptResult::OK) {
    if(decRes.result == PacketCryptResult::INVALID_TIMESTAMP) {
      spdlog::error("BLE pairing: stale packet timestamp.");
      m_ErrorCallback(I18n::Get("error_aes_time_mismatch"));
    } else {
      // Wrong key: this phone scanned a different QR, so say nothing to it.
      spdlog::error("BLE pairing: could not decrypt the request.");
    }
    return;
  }

  // From here the logic mirrors PairingServer::ClientThread exactly, so a
  // device paired over BLE is indistinguishable from one paired over TCP.
  try {
    auto initPacket = PacketPairInit::FromJson({decRes.data.begin(), decRes.data.end()});
    if(!initPacket.has_value())
      throw std::runtime_error(I18n::Get("error_pairing_packet_parse"));
    if(AppInfo::CompareVersion(AppInfo::GetPairingProtocolVersion(), initPacket->protoVersion) != 0)
      throw std::runtime_error(I18n::Get("error_protocol_mismatch"));
    if(initPacket->deviceUUID.empty()) {
      spdlog::warn("Device ID is empty. Generating fallback...");
      initPacket->deviceUUID = StringUtils::RandomString(32);
    }

    auto passwordKey = StringUtils::RandomString(64);
    auto pwEnc = CryptUtils::EncryptAES(m_UIData.password, passwordKey);
    if(!pwEnc.has_value())
      throw std::runtime_error(I18n::Get("error_password_encrypt"));

    auto device = PairedDevice();
    device.id = CryptUtils::Sha256(AppSettings::Get().machineID + initPacket->deviceUUID + m_UIData.userName);
    device.pairingMethod = m_UIData.method;
    device.deviceName = initPacket->deviceName;
    device.userName = m_UIData.userName;
    device.passwordEnc = pwEnc.value();
    device.encryptionKey = m_UIData.encKey;

    device.ipAddress = initPacket->ipAddress;
    device.tcpPort = initPacket->tcpPort;
    device.udpPort = initPacket->udpPort;
    device.udpManualPort = initPacket->udpManualPort;
    device.bluetoothAddress = m_UIData.btAddress;
    device.cloudToken = initPacket->cloudToken;

    auto respPacket = PacketPairResponse();
    respPacket.data = PacketPairResponseData();
    respPacket.data.deviceId = device.id;
    respPacket.data.deviceName = NetworkHelper::GetHostName();
    respPacket.data.deviceOS = AppInfo::GetOperatingSystem();
    respPacket.data.unlockServerPort = AppSettings::Get().unlockServerPort;
    respPacket.data.pairingMethod = device.pairingMethod;
    for(const auto &netIf : NetworkHelper::GetWakeOnLanInterfaces())
      respPacket.data.macAddresses.emplace_back(netIf.macAddress);
    respPacket.data.userName = m_UIData.userName;
    respPacket.data.passwordKey = passwordKey;

    auto respStr = respPacket.ToJson().dump();
    auto encRes = CryptUtils::EncryptAESPacket({respStr.begin(), respStr.end()}, m_UIData.encKey);
    if(encRes.result != PacketCryptResult::OK)
      throw std::runtime_error("Failed to encrypt the pairing response.");

    // Store only after the reply is on the wire. If the phone never receives
    // it the device is useless to it, and a stored-but-unknown pairing is
    // worse than none - the user would see a device that cannot unlock.
    if(!WriteFrame(PACKET_ID_PAIR_RESPONSE, encRes.data))
      throw std::runtime_error("Failed to send the pairing response.");

    PairedDevicesStorage::AddDevice(device);
    m_Paired = true;
    spdlog::info("Successfully paired device over BLE. (ID={}, Method={})", device.id,
                 PairingMethodUtils::ToString(device.pairingMethod));
    if(OnPaired)
      OnPaired();
  } catch(const std::exception &ex) {
    spdlog::error("BLE pairing server exception: {}", ex.what());
    auto respPacket = PacketPairResponse();
    respPacket.errMsg = ex.what();
    auto respStr = respPacket.ToJson().dump();
    auto encRes = CryptUtils::EncryptAESPacket({respStr.begin(), respStr.end()}, m_UIData.encKey);
    if(encRes.result != PacketCryptResult::OK || !WriteFrame(PACKET_ID_PAIR_RESPONSE, encRes.data))
      m_ErrorCallback(ex.what());
  }
}

bool BLEPairingServer::WriteFrame(uint16_t packetId, const std::vector<uint8_t> &data) {
  if(!m_Peripheral)
    return false;
  if(data.size() > 0xFFFF) {
    spdlog::error("BLE pairing payload too large. (Size={})", data.size());
    return false;
  }

  // Same frame layout BaseConnection::WritePacket produces, then chunked.
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
      spdlog::error("Failed to send a BLE pairing chunk.");
      return false;
    }
  }
  return true;
}

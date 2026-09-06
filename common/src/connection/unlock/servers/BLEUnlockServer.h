#ifndef PCBU_DESKTOP_BLEUNLOCKSERVER_H
#define PCBU_DESKTOP_BLEUNLOCKSERVER_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "connection/unlock/BaseUnlockConnection.h"
#include "connection/unlock/servers/BLEChunking.h"

// GATT identifiers. These are the shared contract with the phone's
// lib/protocol/ble_ids.dart and must match it exactly. Fixed, randomly
// generated 128-bit UUIDs, not derived from any assigned SIG number.
constexpr auto BLE_SERVICE_UUID = "7F3E2D10-9C41-4B8A-A6D2-1E5F0C8B4A37";
constexpr auto BLE_RX_CHAR_UUID = "7F3E2D11-9C41-4B8A-A6D2-1E5F0C8B4A37"; // phone -> PC (write)
constexpr auto BLE_TX_CHAR_UUID = "7F3E2D12-9C41-4B8A-A6D2-1E5F0C8B4A37"; // PC -> phone (notify)

// Payload budget when the peer has not negotiated a larger MTU. 23 is the
// mandatory BLE floor: 23 - 3 (ATT header) - 2 (our chunk header).
constexpr size_t BLE_DEFAULT_PAYLOAD_PER_CHUNK = 23 - 3 - BLE_CHUNK_HEADER_SIZE;

// Platform-specific GATT peripheral. Implemented per OS; only macOS
// (CoreBluetooth) exists today.
//
// The backend owns advertising and the characteristic plumbing. It knows
// nothing about packets: it moves opaque chunks and reports connect state.
class IBLEPeripheral {
public:
  virtual ~IBLEPeripheral() = default;

  // Begin advertising BLE_SERVICE_UUID. Returns false if the radio is
  // unavailable or powered off.
  virtual bool Start() = 0;
  virtual void Stop() = 0;

  // Notify one chunk on the TX characteristic. Returns false if the peer is
  // gone or the stack refused the write.
  virtual bool SendChunk(const std::vector<uint8_t> &chunk) = 0;

  // Payload bytes per chunk for the current link, from the negotiated MTU.
  [[nodiscard]] virtual size_t GetMaxPayloadPerChunk() const = 0;

  [[nodiscard]] virtual bool IsConnected() const = 0;

  // Invoked from the backend's own thread when a chunk lands on RX.
  std::function<void(const uint8_t *, size_t)> OnChunkReceived{};

  // Invoked when a central subscribes / drops.
  std::function<void()> OnCentralConnected{};
  std::function<void()> OnCentralDisconnected{};
};

// Creates the platform peripheral. Returns nullptr where BLE is unsupported.
// Which GATT service a peripheral should host.
//
// Pairing and unlock use different services so a phone scanning to pair never
// matches a PC merely waiting for an unlock, and both can advertise at once.
struct BLEServiceIds {
  const char *service{};
  const char *rxChar{};
  const char *txChar{};
  const char *localName{};
};

// Creates the platform peripheral for the given service. Returns nullptr
// where BLE is unsupported.
std::unique_ptr<IBLEPeripheral> CreateBLEPeripheral(const BLEServiceIds &ids);

// Convenience for the unlock service, which is the original caller.
inline std::unique_ptr<IBLEPeripheral> CreateBLEPeripheral() {
  return CreateBLEPeripheral(
      BLEServiceIds{BLE_SERVICE_UUID, BLE_RX_CHAR_UUID, BLE_TX_CHAR_UUID, "PC Bio Unlock"});
}

// Unlock over BLE GATT.
//
// The desktop is the peripheral and the phone is the central, matching the
// existing flow where the PC announces it wants an unlock and the phone
// answers. It also suits iOS, where central mode is fully supported.
//
// Everything above the transport is unchanged: the same framed packets, the
// same AES-256-GCM, the same timestamp window and unlockToken echo. Only the
// pipe differs, which is why iPhone can use this while Classic RFCOMM stays
// Android-only.
class BLEUnlockServer : public BaseUnlockConnection {
public:
  explicit BLEUnlockServer(const PairedDevice &device);
  ~BLEUnlockServer() override;

  bool IsServer() override;
  bool Start() override;
  void Stop() override;

private:
  // Chunk arrived on RX; reassemble and parse.
  void HandleChunk(const uint8_t *data, size_t length);
  // A whole frame was reassembled.
  void HandleFrame(const std::vector<uint8_t> &frame);
  // Chunk and notify one framed packet.
  bool WriteFrame(uint16_t packetId, const std::vector<uint8_t> &data);

  bool SendUnlockRequestBLE();
  void OnUnlockResponse(const std::vector<uint8_t> &payload);

  std::unique_ptr<IBLEPeripheral> m_Peripheral{};
  BLEReassembler m_Reassembler{};
  bool m_SentRequest{};
  std::mutex m_BLEMutex{};
};

#endif // PCBU_DESKTOP_BLEUNLOCKSERVER_H

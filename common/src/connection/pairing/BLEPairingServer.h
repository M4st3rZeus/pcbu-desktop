#ifndef PCBU_DESKTOP_BLEPAIRINGSERVER_H
#define PCBU_DESKTOP_BLEPAIRINGSERVER_H

#include <atomic>
#include <functional>
#include <memory>
#include <string>

#include "PairingStructs.h"
#include "connection/unlock/servers/BLEChunking.h"
#include "connection/unlock/servers/BLEUnlockServer.h"

// GATT identifiers for pairing. Distinct from the unlock service so a phone
// scanning to pair never matches a PC that is merely waiting for an unlock,
// and so both can advertise at once without ambiguity.
//
// Shared contract with the phone's lib/protocol/ble_ids.dart.
constexpr auto BLE_PAIRING_SERVICE_UUID = "7F3E2D20-9C41-4B8A-A6D2-1E5F0C8B4A37";
constexpr auto BLE_PAIRING_RX_CHAR_UUID = "7F3E2D21-9C41-4B8A-A6D2-1E5F0C8B4A37"; // phone -> PC
constexpr auto BLE_PAIRING_TX_CHAR_UUID = "7F3E2D22-9C41-4B8A-A6D2-1E5F0C8B4A37"; // PC -> phone

// Pairing over BLE GATT.
//
// The wire exchange is identical to the TCP pairing server - one encrypted
// PacketPairInit in, one encrypted PacketPairResponse out, both AES-256-GCM
// under the QR's encKey - so a device paired this way is indistinguishable
// from any other once stored. Only the transport differs.
//
// **Why this exists.** The TCP pairing server needs Wi-Fi, and the point of
// the BLE method is not needing it. Without this, a BLE device could only be
// created by pairing over Wi-Fi first, which defeats the purpose on a machine
// with no shared network.
//
// **How the phone finds us.** The PC advertises this service while the QR is
// on screen. The QR still carries the encKey and the pairing method, so the
// phone knows to scan for BLE rather than dial an address. Nothing sensitive
// is in the advertisement - possession of the encKey is what authenticates,
// exactly as over TCP.
class BLEPairingServer {
public:
  explicit BLEPairingServer(const std::function<void(const std::string &)> &errorCallback);
  ~BLEPairingServer();

  BLEPairingServer(const BLEPairingServer &) = delete;
  BLEPairingServer &operator=(const BLEPairingServer &) = delete;

  bool Start(const PairingUIData &uiData);
  void Stop();

  [[nodiscard]] bool IsRunning() const { return m_IsRunning; }

  // Invoked once a device has been paired and stored.
  std::function<void()> OnPaired{};

private:
  void HandleChunk(const uint8_t *data, size_t length);
  void HandleFrame(const std::vector<uint8_t> &frame);
  bool WriteFrame(uint16_t packetId, const std::vector<uint8_t> &data);

  std::unique_ptr<IBLEPeripheral> m_Peripheral{};
  BLEReassembler m_Reassembler{};
  std::mutex m_Mutex{};

  // One pairing per session. A phone that re-subscribes must not be able to
  // create a second device, and a second phone must not race the first.
  bool m_Paired{};

  PairingUIData m_UIData{};
  std::atomic<bool> m_IsRunning{};
  std::function<void(const std::string &)> m_ErrorCallback{};
};

#endif // PCBU_DESKTOP_BLEPAIRINGSERVER_H

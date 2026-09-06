#include "BLEUnlockServer.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <spdlog/spdlog.h>

// WinRT GATT peripheral backing BLEUnlockServer on Windows.
//
// C++/WinRT ships with the Windows SDK and is header-only, so this adds no
// external dependency. It does require Windows 10 1703+ for the peripheral
// role; older builds fail at GattServiceProvider::CreateAsync and Start()
// reports the reason rather than half-working.
//
// Threading: WinRT delivers events on a thread-pool thread, so the callbacks
// into BLEUnlockServer arrive off the main thread just as they do on macOS.
// BLEUnlockServer guards its reassembler with a mutex.
#include <winrt/Windows.Devices.Bluetooth.GenericAttributeProfile.h>
#include <winrt/Windows.Devices.Bluetooth.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/base.h>

#include "utils/StringUtils.h"

using namespace winrt;
using namespace winrt::Windows::Devices::Bluetooth;
using namespace winrt::Windows::Devices::Bluetooth::GenericAttributeProfile;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Storage::Streams;

namespace {

// winrt::guid parses a plain 36-char UUID string directly (braces optional)
// and the constructor is constexpr, so no conversion is needed.
constexpr winrt::guid ParseUuid(std::string_view uuid) {
  return winrt::guid(uuid);
}

class WinBLEPeripheral : public IBLEPeripheral {
public:
  WinBLEPeripheral() = default;
  ~WinBLEPeripheral() override { Stop(); }

  bool Start() override;
  void Stop() override;
  bool SendChunk(const std::vector<uint8_t> &chunk) override;
  [[nodiscard]] size_t GetMaxPayloadPerChunk() const override;
  [[nodiscard]] bool IsConnected() const override;

private:
  void OnWriteRequested(const GattLocalCharacteristic &sender, const GattWriteRequestedEventArgs &args);
  void OnSubscribersChanged(const GattLocalCharacteristic &sender, const IInspectable &args);

  GattServiceProvider m_Provider{nullptr};
  GattLocalCharacteristic m_RxChar{nullptr};
  GattLocalCharacteristic m_TxChar{nullptr};

  event_token m_WriteToken{};
  event_token m_SubscribeToken{};

  std::atomic<bool> m_Started{};
  std::atomic<bool> m_HasSubscriber{};
  mutable std::mutex m_Mutex{};
  std::atomic<size_t> m_MaxPayload{BLE_DEFAULT_PAYLOAD_PER_CHUNK};
};

bool WinBLEPeripheral::Start() {
  try {
    // Apartment init is idempotent per thread; the unlock handler may already
    // have initialised COM, so tolerate that rather than failing.
    try {
      init_apartment(apartment_type::multi_threaded);
    } catch(const hresult_error &) {
      // Already initialised on this thread, which is fine.
    }

    auto adapter = BluetoothAdapter::GetDefaultAsync().get();
    if(adapter == nullptr) {
      spdlog::error("BLE: no Bluetooth adapter found.");
      return false;
    }
    if(!adapter.IsLowEnergySupported()) {
      spdlog::error("BLE: adapter does not support Low Energy.");
      return false;
    }
    if(!adapter.IsPeripheralRoleSupported()) {
      // Common on older or cheaper Bluetooth chipsets. Nothing we can do.
      spdlog::error("BLE: this adapter does not support the peripheral role, "
                    "so it cannot host a GATT service.");
      return false;
    }

    auto serviceResult = GattServiceProvider::CreateAsync(ParseUuid(BLE_SERVICE_UUID)).get();
    if(serviceResult.Error() != BluetoothError::Success) {
      spdlog::error("BLE: failed to create GATT service. (Error={})", static_cast<int>(serviceResult.Error()));
      return false;
    }
    m_Provider = serviceResult.ServiceProvider();

    // RX: the phone writes chunks here. Write-with-response gives us
    // backpressure; a dropped chunk would desync reassembly.
    GattLocalCharacteristicParameters rxParams{};
    rxParams.CharacteristicProperties(GattCharacteristicProperties::Write);
    rxParams.WriteProtectionLevel(GattProtectionLevel::Plain);
    auto rxResult = m_Provider.Service().CreateCharacteristicAsync(ParseUuid(BLE_RX_CHAR_UUID), rxParams).get();
    if(rxResult.Error() != BluetoothError::Success) {
      spdlog::error("BLE: failed to create RX characteristic. (Error={})", static_cast<int>(rxResult.Error()));
      Stop();
      return false;
    }
    m_RxChar = rxResult.Characteristic();

    // TX: notifications carry PC -> phone chunks.
    GattLocalCharacteristicParameters txParams{};
    txParams.CharacteristicProperties(GattCharacteristicProperties::Notify);
    txParams.ReadProtectionLevel(GattProtectionLevel::Plain);
    auto txResult = m_Provider.Service().CreateCharacteristicAsync(ParseUuid(BLE_TX_CHAR_UUID), txParams).get();
    if(txResult.Error() != BluetoothError::Success) {
      spdlog::error("BLE: failed to create TX characteristic. (Error={})", static_cast<int>(txResult.Error()));
      Stop();
      return false;
    }
    m_TxChar = txResult.Characteristic();

    m_WriteToken = m_RxChar.WriteRequested({this, &WinBLEPeripheral::OnWriteRequested});
    m_SubscribeToken = m_TxChar.SubscribedClientsChanged({this, &WinBLEPeripheral::OnSubscribersChanged});

    GattServiceProviderAdvertisingParameters advParams{};
    advParams.IsConnectable(true);
    advParams.IsDiscoverable(true);
    m_Provider.StartAdvertising(advParams);

    m_Started = true;
    return true;
  } catch(const hresult_error &ex) {
    spdlog::error("BLE: WinRT error starting peripheral. (HRESULT={:#x}, Msg={})", static_cast<uint32_t>(ex.code()),
                  StringUtils::FromWideString(ex.message().c_str()));
    Stop();
    return false;
  }
}

void WinBLEPeripheral::Stop() {
  std::lock_guard lock(m_Mutex);
  try {
    if(m_RxChar != nullptr && m_WriteToken.value != 0) {
      m_RxChar.WriteRequested(m_WriteToken);
      m_WriteToken = {};
    }
    if(m_TxChar != nullptr && m_SubscribeToken.value != 0) {
      m_TxChar.SubscribedClientsChanged(m_SubscribeToken);
      m_SubscribeToken = {};
    }
    if(m_Provider != nullptr) {
      if(m_Started)
        m_Provider.StopAdvertising();
      m_Provider = nullptr;
    }
  } catch(const hresult_error &ex) {
    spdlog::warn("BLE: error stopping peripheral. (HRESULT={:#x})", static_cast<uint32_t>(ex.code()));
  }
  m_RxChar = nullptr;
  m_TxChar = nullptr;
  m_Started = false;
  m_HasSubscriber = false;
}

void WinBLEPeripheral::OnWriteRequested(const GattLocalCharacteristic &, const GattWriteRequestedEventArgs &args) {
  try {
    // The deferral keeps the request alive while we read it; without it WinRT
    // may recycle the args before the read completes.
    auto deferral = args.GetDeferral();
    auto request = args.GetRequestAsync().get();
    if(request == nullptr) {
      deferral.Complete();
      return;
    }

    auto buffer = request.Value();
    auto reader = DataReader::FromBuffer(buffer);
    std::vector<uint8_t> data(buffer.Length());
    if(!data.empty())
      reader.ReadBytes(data);

    if(request.Option() == GattWriteOption::WriteWithResponse)
      request.Respond();
    deferral.Complete();

    if(!data.empty() && OnChunkReceived)
      OnChunkReceived(data.data(), data.size());
  } catch(const hresult_error &ex) {
    spdlog::error("BLE: error handling write request. (HRESULT={:#x})", static_cast<uint32_t>(ex.code()));
  }
}

void WinBLEPeripheral::OnSubscribersChanged(const GattLocalCharacteristic &sender, const IInspectable &) {
  auto clients = sender.SubscribedClients();
  auto nowSubscribed = clients.Size() > 0;

  if(nowSubscribed && clients.Size() > 0) {
    // MaxNotificationSize already accounts for the ATT header, so only our own
    // chunk header comes off it. With several clients the smallest wins, since
    // one payload goes to all of them.
    size_t maxNotify = SIZE_MAX;
    for(auto const &client : clients) {
      maxNotify = std::min(maxNotify, static_cast<size_t>(client.MaxNotificationSize()));
    }
    m_MaxPayload = maxNotify > BLE_CHUNK_HEADER_SIZE ? maxNotify - BLE_CHUNK_HEADER_SIZE : BLE_DEFAULT_PAYLOAD_PER_CHUNK;
  }

  auto was = m_HasSubscriber.exchange(nowSubscribed);
  if(nowSubscribed && !was) {
    if(OnCentralConnected)
      OnCentralConnected();
  } else if(!nowSubscribed && was) {
    if(OnCentralDisconnected)
      OnCentralDisconnected();
  }
}

bool WinBLEPeripheral::SendChunk(const std::vector<uint8_t> &chunk) {
  if(!m_Started || m_TxChar == nullptr || !m_HasSubscriber)
    return false;
  try {
    DataWriter writer{};
    writer.WriteBytes(array_view<const uint8_t>(chunk.data(), chunk.data() + chunk.size()));

    // Blocking on the notify keeps chunks in order, which the peer's
    // reassembler requires.
    auto results = m_TxChar.NotifyValueAsync(writer.DetachBuffer()).get();
    for(auto const &r : results) {
      if(r.Status() == GattCommunicationStatus::Success)
        return true;
    }
    spdlog::error("BLE: notify failed for every subscribed client.");
    return false;
  } catch(const hresult_error &ex) {
    spdlog::error("BLE: error sending chunk. (HRESULT={:#x})", static_cast<uint32_t>(ex.code()));
    return false;
  }
}

size_t WinBLEPeripheral::GetMaxPayloadPerChunk() const {
  auto v = m_MaxPayload.load();
  return v > 0 ? v : BLE_DEFAULT_PAYLOAD_PER_CHUNK;
}

bool WinBLEPeripheral::IsConnected() const {
  return m_HasSubscriber.load();
}

} // namespace

std::unique_ptr<IBLEPeripheral> CreateBLEPeripheral() {
  return std::make_unique<WinBLEPeripheral>();
}

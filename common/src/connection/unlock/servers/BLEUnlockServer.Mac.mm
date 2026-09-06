#include "BLEUnlockServer.h"

#import <CoreBluetooth/CoreBluetooth.h>
#import <Foundation/Foundation.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <spdlog/spdlog.h>

// This project compiles .mm files without -fobjc-arc, so ownership is manual
// (MRR). PCBU_RELEASE compiles away if ARC is ever switched on, keeping the
// file correct either way rather than leaking under one mode and
// double-releasing under the other.
#if __has_feature(objc_arc)
#define PCBU_RELEASE(obj) ((void)0)
#else
#define PCBU_RELEASE(obj) [(obj) release]
#endif

// CoreBluetooth peripheral backing BLEUnlockServer on macOS.
//
// CBPeripheralManager delivers every callback on a dispatch queue, so the
// C++ side must treat OnChunkReceived / OnCentralConnected as arriving from
// another thread. BLEUnlockServer guards its reassembler with a mutex.

@class PCBUPeripheralDelegate;

namespace {

class MacBLEPeripheral;

// Bridge so the Objective-C delegate can reach the C++ object.
struct DelegateContext {
  MacBLEPeripheral *owner{};
};

class MacBLEPeripheral : public IBLEPeripheral {
public:
  MacBLEPeripheral();
  ~MacBLEPeripheral() override;

  bool Start() override;
  void Stop() override;
  bool SendChunk(const std::vector<uint8_t> &chunk) override;
  [[nodiscard]] size_t GetMaxPayloadPerChunk() const override;
  [[nodiscard]] bool IsConnected() const override;

  // Called from the delegate.
  void SetCentral(CBCentral *central);
  void ClearCentral();
  void DeliverChunk(const uint8_t *data, size_t len);
  void OnPoweredOn();
  void OnPowerFailure(const std::string &reason);

  CBPeripheralManager *m_Manager{};
  CBMutableCharacteristic *m_TxChar{};
  CBMutableCharacteristic *m_RxChar{};
  PCBUPeripheralDelegate *m_Delegate{};
  DelegateContext m_Context{};

  std::atomic<bool> m_PoweredOn{};
  std::atomic<bool> m_PowerFailed{};
  std::mutex m_Mutex{};
  std::condition_variable m_PowerCv{};
  CBCentral *m_Central{};
};

} // namespace

// The delegate owns no C++ memory; it only forwards into MacBLEPeripheral.
@interface PCBUPeripheralDelegate : NSObject <CBPeripheralManagerDelegate>
@property(nonatomic, assign) DelegateContext *ctx;
@end

@implementation PCBUPeripheralDelegate

- (void)peripheralManagerDidUpdateState:(CBPeripheralManager *)peripheral {
  if(!self.ctx || !self.ctx->owner)
    return;
  switch(peripheral.state) {
    case CBManagerStatePoweredOn:
      self.ctx->owner->OnPoweredOn();
      break;
    case CBManagerStateUnauthorized:
      self.ctx->owner->OnPowerFailure("Bluetooth permission denied.");
      break;
    case CBManagerStateUnsupported:
      self.ctx->owner->OnPowerFailure("Bluetooth LE is not supported on this Mac.");
      break;
    case CBManagerStatePoweredOff:
      self.ctx->owner->OnPowerFailure("Bluetooth is turned off.");
      break;
    default:
      break;
  }
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral
                          central:(CBCentral *)central
    didSubscribeToCharacteristic:(CBCharacteristic *)characteristic {
  if(self.ctx && self.ctx->owner)
    self.ctx->owner->SetCentral(central);
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral
                              central:(CBCentral *)central
    didUnsubscribeFromCharacteristic:(CBCharacteristic *)characteristic {
  if(self.ctx && self.ctx->owner)
    self.ctx->owner->ClearCentral();
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral didReceiveWriteRequests:(NSArray<CBATTRequest *> *)requests {
  for(CBATTRequest *request in requests) {
    if(request.value.length > 0 && self.ctx && self.ctx->owner) {
      self.ctx->owner->DeliverChunk(static_cast<const uint8_t *>(request.value.bytes), request.value.length);
    }
  }
  // Only the first request needs a response, per CoreBluetooth's contract.
  if(requests.count > 0)
    [peripheral respondToRequest:requests.firstObject withResult:CBATTErrorSuccess];
}

@end

namespace {

MacBLEPeripheral::MacBLEPeripheral() {
  m_Context.owner = this;
}

MacBLEPeripheral::~MacBLEPeripheral() {
  Stop();
  m_Context.owner = nullptr;
}

void MacBLEPeripheral::OnPoweredOn() {
  {
    std::lock_guard lock(m_Mutex);
    m_PoweredOn = true;
  }
  m_PowerCv.notify_all();
}

void MacBLEPeripheral::OnPowerFailure(const std::string &reason) {
  spdlog::error("BLE: {}", reason);
  {
    std::lock_guard lock(m_Mutex);
    m_PowerFailed = true;
  }
  m_PowerCv.notify_all();
}

void MacBLEPeripheral::SetCentral(CBCentral *central) {
  {
    std::lock_guard lock(m_Mutex);
    m_Central = central;
  }
  if(OnCentralConnected)
    OnCentralConnected();
}

void MacBLEPeripheral::ClearCentral() {
  {
    std::lock_guard lock(m_Mutex);
    m_Central = nil;
  }
  if(OnCentralDisconnected)
    OnCentralDisconnected();
}

void MacBLEPeripheral::DeliverChunk(const uint8_t *data, size_t len) {
  if(OnChunkReceived)
    OnChunkReceived(data, len);
}

bool MacBLEPeripheral::Start() {
  @autoreleasepool {
    m_Delegate = [[PCBUPeripheralDelegate alloc] init];
    m_Delegate.ctx = &m_Context;
    m_Manager = [[CBPeripheralManager alloc] initWithDelegate:m_Delegate queue:nil];

    // The radio reports its state asynchronously; wait briefly for it rather
    // than advertising into a powered-off adapter.
    {
      std::unique_lock lock(m_Mutex);
      m_PowerCv.wait_for(lock, std::chrono::seconds(5),
                         [this] { return m_PoweredOn.load() || m_PowerFailed.load(); });
    }
    if(!m_PoweredOn.load()) {
      spdlog::error("BLE peripheral did not power on.");
      // Release what we already allocated; the caller will not call Stop()
      // after a failed Start().
      Stop();
      return false;
    }

    auto serviceUUID = [CBUUID UUIDWithString:@(BLE_SERVICE_UUID)];
    auto rxUUID = [CBUUID UUIDWithString:@(BLE_RX_CHAR_UUID)];
    auto txUUID = [CBUUID UUIDWithString:@(BLE_TX_CHAR_UUID)];

    // RX: the phone writes chunks here. writeWithoutResponse would be faster
    // but gives no backpressure, and a dropped chunk desyncs reassembly.
    m_RxChar = [[CBMutableCharacteristic alloc] initWithType:rxUUID
                                                  properties:CBCharacteristicPropertyWrite
                                                       value:nil
                                                 permissions:CBAttributePermissionsWriteable];
    // TX: notifications carry PC -> phone chunks.
    m_TxChar = [[CBMutableCharacteristic alloc] initWithType:txUUID
                                                  properties:CBCharacteristicPropertyNotify
                                                       value:nil
                                                 permissions:CBAttributePermissionsReadable];

    auto service = [[CBMutableService alloc] initWithType:serviceUUID primary:YES];
    service.characteristics = @[ m_RxChar, m_TxChar ];
    [m_Manager addService:service];
    // addService: retains it; we own the alloc, so drop our reference.
    PCBU_RELEASE(service);

    [m_Manager startAdvertising:@{
      CBAdvertisementDataServiceUUIDsKey : @[ serviceUUID ],
      CBAdvertisementDataLocalNameKey : @"PC Bio Unlock"
    }];
    return true;
  }
}

void MacBLEPeripheral::Stop() {
  @autoreleasepool {
    if(m_Manager) {
      [m_Manager stopAdvertising];
      [m_Manager removeAllServices];
      PCBU_RELEASE(m_Manager);
      m_Manager = nil;
    }
    if(m_Delegate) {
      // Clear the back-pointer before releasing: a queued callback must not
      // reach a destroyed C++ object.
      m_Delegate.ctx = nullptr;
      PCBU_RELEASE(m_Delegate);
      m_Delegate = nil;
    }
    std::lock_guard lock(m_Mutex);
    // m_Central is owned by CoreBluetooth, never by us.
    m_Central = nil;
    if(m_TxChar) {
      PCBU_RELEASE(m_TxChar);
      m_TxChar = nil;
    }
    if(m_RxChar) {
      PCBU_RELEASE(m_RxChar);
      m_RxChar = nil;
    }
  }
}

bool MacBLEPeripheral::SendChunk(const std::vector<uint8_t> &chunk) {
  @autoreleasepool {
    CBCentral *central{};
    {
      std::lock_guard lock(m_Mutex);
      central = m_Central;
    }
    if(!m_Manager || !m_TxChar || !central)
      return false;

    auto data = [NSData dataWithBytes:chunk.data() length:chunk.size()];
    // updateValue returns NO when the transmit queue is full; retry until it
    // drains rather than dropping a chunk and desyncing the peer.
    for(int attempt = 0; attempt < 100; attempt++) {
      if([m_Manager updateValue:data forCharacteristic:m_TxChar onSubscribedCentrals:@[ central ]])
        return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    spdlog::error("BLE transmit queue stayed full; dropping chunk.");
    return false;
  }
}

size_t MacBLEPeripheral::GetMaxPayloadPerChunk() const {
  CBCentral *central{};
  {
    std::lock_guard lock(const_cast<std::mutex &>(m_Mutex));
    central = m_Central;
  }
  if(!central)
    return BLE_DEFAULT_PAYLOAD_PER_CHUNK;

  // maximumUpdateValueLength is already the usable notification payload, so
  // only our own chunk header comes off it.
  auto maxValue = static_cast<size_t>(central.maximumUpdateValueLength);
  if(maxValue <= BLE_CHUNK_HEADER_SIZE)
    return BLE_DEFAULT_PAYLOAD_PER_CHUNK;
  return maxValue - BLE_CHUNK_HEADER_SIZE;
}

bool MacBLEPeripheral::IsConnected() const {
  std::lock_guard lock(const_cast<std::mutex &>(m_Mutex));
  return m_Central != nil;
}

} // namespace

std::unique_ptr<IBLEPeripheral> CreateBLEPeripheral() {
  return std::make_unique<MacBLEPeripheral>();
}

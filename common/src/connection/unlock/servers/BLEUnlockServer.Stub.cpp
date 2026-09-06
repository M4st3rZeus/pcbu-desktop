#include "BLEUnlockServer.h"

#include <spdlog/spdlog.h>

// Placeholder peripheral for platforms without a GATT server implementation.
//
// Windows would use WinRT GattServiceProvider and Linux the BlueZ D-Bus GATT
// API; neither exists yet. Returning nullptr makes BLEUnlockServer::Start()
// fail cleanly with a logged reason instead of half-working, and pairing
// hides the BLE method on any platform where this is the active backend.
std::unique_ptr<IBLEPeripheral> CreateBLEPeripheral() {
  spdlog::error("BLE unlock is not implemented on this platform yet.");
  return nullptr;
}

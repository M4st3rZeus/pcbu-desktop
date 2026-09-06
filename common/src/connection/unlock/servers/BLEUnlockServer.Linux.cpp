#include "BLEUnlockServer.h"

#include <atomic>
#include <cstring>
#include <map>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>

#include <dbus/dbus.h>

// BlueZ GATT peripheral backing BLEUnlockServer on Linux.
//
// BlueZ exposes no C API for hosting a GATT service; the only supported route
// is the D-Bus interface, where the application registers objects that BlueZ
// then calls back into. That is why this file speaks raw libdbus-1 rather than
// using libbluetooth like the Classic RFCOMM code does.
//
// Object model we export:
//
//   /com/pcbu/ble
//     /service0                  org.bluez.GattService1     (BLE_SERVICE_UUID)
//       /char_rx                 org.bluez.GattCharacteristic1  write
//       /char_tx                 org.bluez.GattCharacteristic1  notify
//
// plus org.freedesktop.DBus.ObjectManager on /com/pcbu/ble, which BlueZ calls
// during RegisterApplication to enumerate the tree.
//
// Requires BlueZ 5.50+ (LEAdvertisingManager1 and GattManager1). Everything
// runs on a private message loop thread so the caller is never blocked.

namespace {

constexpr auto BLUEZ_BUS = "org.bluez";
constexpr auto ROOT_PATH = "/com/pcbu/ble";
constexpr auto SERVICE_PATH = "/com/pcbu/ble/service0";
constexpr auto RX_PATH = "/com/pcbu/ble/service0/char_rx";
constexpr auto TX_PATH = "/com/pcbu/ble/service0/char_tx";
constexpr auto ADV_PATH = "/com/pcbu/ble/advertisement0";

constexpr auto IFACE_OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager";
constexpr auto IFACE_PROPERTIES = "org.freedesktop.DBus.Properties";
constexpr auto IFACE_GATT_SERVICE = "org.bluez.GattService1";
constexpr auto IFACE_GATT_CHAR = "org.bluez.GattCharacteristic1";
constexpr auto IFACE_GATT_MANAGER = "org.bluez.GattManager1";
constexpr auto IFACE_LE_ADV = "org.bluez.LEAdvertisement1";
constexpr auto IFACE_LE_ADV_MANAGER = "org.bluez.LEAdvertisingManager1";

// Appends a {sv} dict entry whose value is a string.
void AppendStringVariant(DBusMessageIter *dict, const char *key, const char *value) {
  DBusMessageIter entry, variant;
  dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
  dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
  dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
  dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &value);
  dbus_message_iter_close_container(&entry, &variant);
  dbus_message_iter_close_container(dict, &entry);
}

void AppendObjectPathVariant(DBusMessageIter *dict, const char *key, const char *value) {
  DBusMessageIter entry, variant;
  dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
  dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
  dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "o", &variant);
  dbus_message_iter_append_basic(&variant, DBUS_TYPE_OBJECT_PATH, &value);
  dbus_message_iter_close_container(&entry, &variant);
  dbus_message_iter_close_container(dict, &entry);
}

void AppendBoolVariant(DBusMessageIter *dict, const char *key, bool value) {
  DBusMessageIter entry, variant;
  dbus_bool_t v = value ? TRUE : FALSE;
  dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
  dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
  dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "b", &variant);
  dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &v);
  dbus_message_iter_close_container(&entry, &variant);
  dbus_message_iter_close_container(dict, &entry);
}

// Appends a {sv} entry whose value is an array of strings.
void AppendStringArrayVariant(DBusMessageIter *dict, const char *key, const std::vector<std::string> &values) {
  DBusMessageIter entry, variant, array;
  dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
  dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
  dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "as", &variant);
  dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "s", &array);
  for(const auto &v : values) {
    auto p = v.c_str();
    dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &p);
  }
  dbus_message_iter_close_container(&variant, &array);
  dbus_message_iter_close_container(&entry, &variant);
  dbus_message_iter_close_container(dict, &entry);
}

class LinuxBLEPeripheral : public IBLEPeripheral {
public:
  LinuxBLEPeripheral() = default;
  ~LinuxBLEPeripheral() override { Stop(); }

  bool Start() override;
  void Stop() override;
  bool SendChunk(const std::vector<uint8_t> &chunk) override;
  [[nodiscard]] size_t GetMaxPayloadPerChunk() const override;
  [[nodiscard]] bool IsConnected() const override;

  // D-Bus vtable entry points.
  DBusHandlerResult HandleMessage(DBusConnection *conn, DBusMessage *msg);

private:
  bool FindAdapter(std::string &adapterPath);
  bool RegisterApplication(const std::string &adapterPath);
  bool RegisterAdvertisement(const std::string &adapterPath);
  void UnregisterAll();
  void MessageLoop();

  // Replies to org.freedesktop.DBus.ObjectManager.GetManagedObjects, which is
  // how BlueZ discovers the service and characteristics we export.
  DBusHandlerResult OnGetManagedObjects(DBusConnection *conn, DBusMessage *msg);
  DBusHandlerResult OnPropertiesGetAll(DBusConnection *conn, DBusMessage *msg, const char *path);
  DBusHandlerResult OnCharacteristicCall(DBusConnection *conn, DBusMessage *msg, const char *path);
  DBusHandlerResult OnAdvertisementCall(DBusConnection *conn, DBusMessage *msg);

  void EmitTxPropertyChanged(const std::vector<uint8_t> &chunk);

  DBusConnection *m_Conn{};
  std::thread m_Thread{};
  std::atomic<bool> m_Running{};
  std::atomic<bool> m_Notifying{};
  std::atomic<size_t> m_MaxPayload{BLE_DEFAULT_PAYLOAD_PER_CHUNK};
  std::string m_AdapterPath{};
  std::mutex m_SendMutex{};
};

// libdbus dispatches through a C callback; forward to the object.
DBusHandlerResult MessageThunk(DBusConnection *conn, DBusMessage *msg, void *user) {
  return static_cast<LinuxBLEPeripheral *>(user)->HandleMessage(conn, msg);
}

bool LinuxBLEPeripheral::Start() {
  DBusError err;
  dbus_error_init(&err);

  m_Conn = dbus_bus_get_private(DBUS_BUS_SYSTEM, &err);
  if(dbus_error_is_set(&err)) {
    spdlog::error("BLE: cannot reach the system bus. ({})", err.message);
    dbus_error_free(&err);
    return false;
  }
  if(m_Conn == nullptr) {
    spdlog::error("BLE: cannot reach the system bus.");
    return false;
  }
  // The unlock helper owns its own loop; do not let libdbus abort the process.
  dbus_connection_set_exit_on_disconnect(m_Conn, FALSE);

  if(!FindAdapter(m_AdapterPath)) {
    spdlog::error("BLE: no Bluetooth adapter exposed by BlueZ.");
    Stop();
    return false;
  }

  // One filter handles every object we export; HandleMessage routes by path.
  if(!dbus_connection_add_filter(m_Conn, MessageThunk, this, nullptr)) {
    spdlog::error("BLE: failed to install the D-Bus message filter.");
    Stop();
    return false;
  }

  m_Running = true;
  m_Thread = std::thread(&LinuxBLEPeripheral::MessageLoop, this);

  if(!RegisterApplication(m_AdapterPath)) {
    Stop();
    return false;
  }
  if(!RegisterAdvertisement(m_AdapterPath)) {
    Stop();
    return false;
  }
  return true;
}

void LinuxBLEPeripheral::Stop() {
  if(m_Running.exchange(false)) {
    UnregisterAll();
  }
  if(m_Thread.joinable()) {
    // Wake the loop so it observes m_Running == false promptly.
    if(m_Conn != nullptr)
      dbus_connection_flush(m_Conn);
    m_Thread.join();
  }
  if(m_Conn != nullptr) {
    dbus_connection_remove_filter(m_Conn, MessageThunk, this);
    dbus_connection_close(m_Conn);
    dbus_connection_unref(m_Conn);
    m_Conn = nullptr;
  }
  m_Notifying = false;
}

void LinuxBLEPeripheral::MessageLoop() {
  while(m_Running.load()) {
    // 100ms keeps shutdown responsive without spinning.
    if(!dbus_connection_read_write_dispatch(m_Conn, 100))
      break;
  }
}

bool LinuxBLEPeripheral::FindAdapter(std::string &adapterPath) {
  // Ask BlueZ's root ObjectManager for an object implementing GattManager1.
  auto msg = dbus_message_new_method_call(BLUEZ_BUS, "/", IFACE_OBJECT_MANAGER, "GetManagedObjects");
  if(msg == nullptr)
    return false;

  DBusError err;
  dbus_error_init(&err);
  auto reply = dbus_connection_send_with_reply_and_block(m_Conn, msg, 5000, &err);
  dbus_message_unref(msg);
  if(dbus_error_is_set(&err)) {
    spdlog::error("BLE: GetManagedObjects failed. ({})", err.message);
    dbus_error_free(&err);
    return false;
  }
  if(reply == nullptr)
    return false;

  DBusMessageIter root, objects;
  dbus_message_iter_init(reply, &root);
  dbus_message_iter_recurse(&root, &objects);

  auto found = false;
  while(dbus_message_iter_get_arg_type(&objects) == DBUS_TYPE_DICT_ENTRY && !found) {
    DBusMessageIter entry;
    dbus_message_iter_recurse(&objects, &entry);

    const char *path{};
    dbus_message_iter_get_basic(&entry, &path);
    dbus_message_iter_next(&entry);

    DBusMessageIter interfaces;
    dbus_message_iter_recurse(&entry, &interfaces);
    while(dbus_message_iter_get_arg_type(&interfaces) == DBUS_TYPE_DICT_ENTRY) {
      DBusMessageIter ifaceEntry;
      dbus_message_iter_recurse(&interfaces, &ifaceEntry);
      const char *ifaceName{};
      dbus_message_iter_get_basic(&ifaceEntry, &ifaceName);
      if(ifaceName != nullptr && std::strcmp(ifaceName, IFACE_GATT_MANAGER) == 0) {
        adapterPath = path;
        found = true;
        break;
      }
      dbus_message_iter_next(&interfaces);
    }
    dbus_message_iter_next(&objects);
  }
  dbus_message_unref(reply);
  return found;
}

bool LinuxBLEPeripheral::RegisterApplication(const std::string &adapterPath) {
  auto msg = dbus_message_new_method_call(BLUEZ_BUS, adapterPath.c_str(), IFACE_GATT_MANAGER, "RegisterApplication");
  if(msg == nullptr)
    return false;

  DBusMessageIter args, options;
  dbus_message_iter_init_append(msg, &args);
  const char *root = ROOT_PATH;
  dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, &root);
  dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &options);
  dbus_message_iter_close_container(&args, &options);

  DBusError err;
  dbus_error_init(&err);
  auto reply = dbus_connection_send_with_reply_and_block(m_Conn, msg, 10000, &err);
  dbus_message_unref(msg);
  if(dbus_error_is_set(&err)) {
    spdlog::error("BLE: RegisterApplication failed. ({})", err.message);
    dbus_error_free(&err);
    return false;
  }
  if(reply != nullptr)
    dbus_message_unref(reply);
  return true;
}

bool LinuxBLEPeripheral::RegisterAdvertisement(const std::string &adapterPath) {
  auto msg = dbus_message_new_method_call(BLUEZ_BUS, adapterPath.c_str(), IFACE_LE_ADV_MANAGER, "RegisterAdvertisement");
  if(msg == nullptr)
    return false;

  DBusMessageIter args, options;
  dbus_message_iter_init_append(msg, &args);
  const char *adv = ADV_PATH;
  dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, &adv);
  dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &options);
  dbus_message_iter_close_container(&args, &options);

  DBusError err;
  dbus_error_init(&err);
  auto reply = dbus_connection_send_with_reply_and_block(m_Conn, msg, 10000, &err);
  dbus_message_unref(msg);
  if(dbus_error_is_set(&err)) {
    spdlog::error("BLE: RegisterAdvertisement failed. ({})", err.message);
    dbus_error_free(&err);
    return false;
  }
  if(reply != nullptr)
    dbus_message_unref(reply);
  return true;
}

void LinuxBLEPeripheral::UnregisterAll() {
  if(m_Conn == nullptr || m_AdapterPath.empty())
    return;

  auto unregister = [this](const char *iface, const char *method, const char *path) {
    auto msg = dbus_message_new_method_call(BLUEZ_BUS, m_AdapterPath.c_str(), iface, method);
    if(msg == nullptr)
      return;
    DBusMessageIter args;
    dbus_message_iter_init_append(msg, &args);
    dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, &path);
    // Fire and forget: on shutdown BlueZ may already have dropped us.
    dbus_connection_send(m_Conn, msg, nullptr);
    dbus_message_unref(msg);
  };
  const char *adv = ADV_PATH;
  const char *root = ROOT_PATH;
  unregister(IFACE_LE_ADV_MANAGER, "UnregisterAdvertisement", adv);
  unregister(IFACE_GATT_MANAGER, "UnregisterApplication", root);
  dbus_connection_flush(m_Conn);
}

DBusHandlerResult LinuxBLEPeripheral::HandleMessage(DBusConnection *conn, DBusMessage *msg) {
  if(dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_METHOD_CALL)
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

  auto path = dbus_message_get_path(msg);
  if(path == nullptr)
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

  if(dbus_message_is_method_call(msg, IFACE_OBJECT_MANAGER, "GetManagedObjects") && std::strcmp(path, ROOT_PATH) == 0)
    return OnGetManagedObjects(conn, msg);

  if(dbus_message_is_method_call(msg, IFACE_PROPERTIES, "GetAll"))
    return OnPropertiesGetAll(conn, msg, path);

  if(std::strcmp(path, RX_PATH) == 0 || std::strcmp(path, TX_PATH) == 0)
    return OnCharacteristicCall(conn, msg, path);

  if(std::strcmp(path, ADV_PATH) == 0)
    return OnAdvertisementCall(conn, msg);

  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

// Builds the a{oa{sa{sv}}} tree BlueZ reads during RegisterApplication.
DBusHandlerResult LinuxBLEPeripheral::OnGetManagedObjects(DBusConnection *conn, DBusMessage *msg) {
  auto reply = dbus_message_new_method_return(msg);
  if(reply == nullptr)
    return DBUS_HANDLER_RESULT_NEED_MEMORY;

  DBusMessageIter args, objects;
  dbus_message_iter_init_append(reply, &args);
  dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{oa{sa{sv}}}", &objects);

  auto addObject = [&objects](const char *path, const char *iface, auto fillProps) {
    DBusMessageIter objEntry, ifaceArray, ifaceEntry, propArray;
    dbus_message_iter_open_container(&objects, DBUS_TYPE_DICT_ENTRY, nullptr, &objEntry);
    dbus_message_iter_append_basic(&objEntry, DBUS_TYPE_OBJECT_PATH, &path);
    dbus_message_iter_open_container(&objEntry, DBUS_TYPE_ARRAY, "{sa{sv}}", &ifaceArray);
    dbus_message_iter_open_container(&ifaceArray, DBUS_TYPE_DICT_ENTRY, nullptr, &ifaceEntry);
    dbus_message_iter_append_basic(&ifaceEntry, DBUS_TYPE_STRING, &iface);
    dbus_message_iter_open_container(&ifaceEntry, DBUS_TYPE_ARRAY, "{sv}", &propArray);
    fillProps(&propArray);
    dbus_message_iter_close_container(&ifaceEntry, &propArray);
    dbus_message_iter_close_container(&ifaceArray, &ifaceEntry);
    dbus_message_iter_close_container(&objEntry, &ifaceArray);
    dbus_message_iter_close_container(&objects, &objEntry);
  };

  addObject(SERVICE_PATH, IFACE_GATT_SERVICE, [](DBusMessageIter *props) {
    AppendStringVariant(props, "UUID", BLE_SERVICE_UUID);
    AppendBoolVariant(props, "Primary", true);
  });
  addObject(RX_PATH, IFACE_GATT_CHAR, [](DBusMessageIter *props) {
    AppendStringVariant(props, "UUID", BLE_RX_CHAR_UUID);
    AppendObjectPathVariant(props, "Service", SERVICE_PATH);
    AppendStringArrayVariant(props, "Flags", {"write"});
  });
  addObject(TX_PATH, IFACE_GATT_CHAR, [](DBusMessageIter *props) {
    AppendStringVariant(props, "UUID", BLE_TX_CHAR_UUID);
    AppendObjectPathVariant(props, "Service", SERVICE_PATH);
    AppendStringArrayVariant(props, "Flags", {"notify"});
  });

  dbus_message_iter_close_container(&args, &objects);
  dbus_connection_send(conn, reply, nullptr);
  dbus_message_unref(reply);
  return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult LinuxBLEPeripheral::OnPropertiesGetAll(DBusConnection *conn, DBusMessage *msg, const char *path) {
  auto reply = dbus_message_new_method_return(msg);
  if(reply == nullptr)
    return DBUS_HANDLER_RESULT_NEED_MEMORY;

  DBusMessageIter args, props;
  dbus_message_iter_init_append(reply, &args);
  dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &props);

  if(std::strcmp(path, SERVICE_PATH) == 0) {
    AppendStringVariant(&props, "UUID", BLE_SERVICE_UUID);
    AppendBoolVariant(&props, "Primary", true);
  } else if(std::strcmp(path, RX_PATH) == 0) {
    AppendStringVariant(&props, "UUID", BLE_RX_CHAR_UUID);
    AppendObjectPathVariant(&props, "Service", SERVICE_PATH);
    AppendStringArrayVariant(&props, "Flags", {"write"});
  } else if(std::strcmp(path, TX_PATH) == 0) {
    AppendStringVariant(&props, "UUID", BLE_TX_CHAR_UUID);
    AppendObjectPathVariant(&props, "Service", SERVICE_PATH);
    AppendStringArrayVariant(&props, "Flags", {"notify"});
  } else if(std::strcmp(path, ADV_PATH) == 0) {
    AppendStringVariant(&props, "Type", "peripheral");
    AppendStringArrayVariant(&props, "ServiceUUIDs", {BLE_SERVICE_UUID});
    AppendStringVariant(&props, "LocalName", "PC Bio Unlock");
  }

  dbus_message_iter_close_container(&args, &props);
  dbus_connection_send(conn, reply, nullptr);
  dbus_message_unref(reply);
  return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult LinuxBLEPeripheral::OnCharacteristicCall(DBusConnection *conn, DBusMessage *msg, const char *path) {
  // WriteValue(ay value, a{sv} options) — the phone sending us a chunk.
  if(dbus_message_is_method_call(msg, IFACE_GATT_CHAR, "WriteValue")) {
    DBusMessageIter args;
    if(dbus_message_iter_init(msg, &args) && dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_ARRAY) {
      DBusMessageIter bytes;
      dbus_message_iter_recurse(&args, &bytes);

      const uint8_t *data{};
      int count = 0;
      dbus_message_iter_get_fixed_array(&bytes, &data, &count);

      // BlueZ reports the negotiated ATT MTU in the options dict; use it when
      // present so we stop assuming the 23-byte floor.
      dbus_message_iter_next(&args);
      if(dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_ARRAY) {
        DBusMessageIter options;
        dbus_message_iter_recurse(&args, &options);
        while(dbus_message_iter_get_arg_type(&options) == DBUS_TYPE_DICT_ENTRY) {
          DBusMessageIter entry;
          dbus_message_iter_recurse(&options, &entry);
          const char *key{};
          dbus_message_iter_get_basic(&entry, &key);
          if(key != nullptr && std::strcmp(key, "mtu") == 0) {
            dbus_message_iter_next(&entry);
            DBusMessageIter variant;
            dbus_message_iter_recurse(&entry, &variant);
            if(dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_UINT16) {
              uint16_t mtu = 0;
              dbus_message_iter_get_basic(&variant, &mtu);
              if(mtu > 3 + BLE_CHUNK_HEADER_SIZE)
                m_MaxPayload = static_cast<size_t>(mtu) - 3 - BLE_CHUNK_HEADER_SIZE;
            }
          }
          dbus_message_iter_next(&options);
        }
      }

      if(data != nullptr && count > 0 && OnChunkReceived)
        OnChunkReceived(data, static_cast<size_t>(count));
    }
    auto reply = dbus_message_new_method_return(msg);
    if(reply != nullptr) {
      dbus_connection_send(conn, reply, nullptr);
      dbus_message_unref(reply);
    }
    return DBUS_HANDLER_RESULT_HANDLED;
  }

  // StartNotify / StopNotify on TX bracket the phone's subscription, which is
  // what we treat as connect / disconnect.
  if(dbus_message_is_method_call(msg, IFACE_GATT_CHAR, "StartNotify")) {
    auto reply = dbus_message_new_method_return(msg);
    if(reply != nullptr) {
      dbus_connection_send(conn, reply, nullptr);
      dbus_message_unref(reply);
    }
    if(std::strcmp(path, TX_PATH) == 0 && !m_Notifying.exchange(true)) {
      if(OnCentralConnected)
        OnCentralConnected();
    }
    return DBUS_HANDLER_RESULT_HANDLED;
  }
  if(dbus_message_is_method_call(msg, IFACE_GATT_CHAR, "StopNotify")) {
    auto reply = dbus_message_new_method_return(msg);
    if(reply != nullptr) {
      dbus_connection_send(conn, reply, nullptr);
      dbus_message_unref(reply);
    }
    if(std::strcmp(path, TX_PATH) == 0 && m_Notifying.exchange(false)) {
      if(OnCentralDisconnected)
        OnCentralDisconnected();
    }
    return DBUS_HANDLER_RESULT_HANDLED;
  }
  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult LinuxBLEPeripheral::OnAdvertisementCall(DBusConnection *conn, DBusMessage *msg) {
  // BlueZ calls Release() when it drops our advertisement.
  if(dbus_message_is_method_call(msg, IFACE_LE_ADV, "Release")) {
    spdlog::info("BLE: BlueZ released the advertisement.");
    auto reply = dbus_message_new_method_return(msg);
    if(reply != nullptr) {
      dbus_connection_send(conn, reply, nullptr);
      dbus_message_unref(reply);
    }
    return DBUS_HANDLER_RESULT_HANDLED;
  }
  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

// A notify on BlueZ is a PropertiesChanged signal carrying the new Value.
void LinuxBLEPeripheral::EmitTxPropertyChanged(const std::vector<uint8_t> &chunk) {
  auto signal = dbus_message_new_signal(TX_PATH, IFACE_PROPERTIES, "PropertiesChanged");
  if(signal == nullptr)
    return;

  DBusMessageIter args, changed, entry, variant, array, invalidated;
  dbus_message_iter_init_append(signal, &args);
  const char *iface = IFACE_GATT_CHAR;
  dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &iface);

  dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &changed);
  dbus_message_iter_open_container(&changed, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
  const char *key = "Value";
  dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
  dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "ay", &variant);
  dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "y", &array);
  for(auto b : chunk) {
    dbus_message_iter_append_basic(&array, DBUS_TYPE_BYTE, &b);
  }
  dbus_message_iter_close_container(&variant, &array);
  dbus_message_iter_close_container(&entry, &variant);
  dbus_message_iter_close_container(&changed, &entry);
  dbus_message_iter_close_container(&args, &changed);

  dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "s", &invalidated);
  dbus_message_iter_close_container(&args, &invalidated);

  dbus_connection_send(m_Conn, signal, nullptr);
  dbus_message_unref(signal);
}

bool LinuxBLEPeripheral::SendChunk(const std::vector<uint8_t> &chunk) {
  if(!m_Running.load() || m_Conn == nullptr || !m_Notifying.load())
    return false;

  // Serialised so chunks reach the peer in order; the reassembler rejects
  // anything else.
  std::lock_guard lock(m_SendMutex);
  EmitTxPropertyChanged(chunk);
  dbus_connection_flush(m_Conn);
  return true;
}

size_t LinuxBLEPeripheral::GetMaxPayloadPerChunk() const {
  auto v = m_MaxPayload.load();
  return v > 0 ? v : BLE_DEFAULT_PAYLOAD_PER_CHUNK;
}

bool LinuxBLEPeripheral::IsConnected() const {
  return m_Notifying.load();
}

} // namespace

std::unique_ptr<IBLEPeripheral> CreateBLEPeripheral() {
  return std::make_unique<LinuxBLEPeripheral>();
}

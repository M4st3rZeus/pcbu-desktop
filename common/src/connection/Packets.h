#ifndef PCBU_DESKTOP_PACKETS_H
#define PCBU_DESKTOP_PACKETS_H

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "storage/PairingMethod.h"

constexpr uint64_t PACKET_HEADER = 0xDB065AC7AFDFA4CC;

constexpr uint16_t PACKET_ID_PAIR_INIT = 0x50;
constexpr uint16_t PACKET_ID_PAIR_RESPONSE = 0x51;

constexpr uint16_t PACKET_ID_DEVICE_ID = 0xB0;
constexpr uint16_t PACKET_ID_UNLOCK_REQUEST = 0xB1;
constexpr uint16_t PACKET_ID_UNLOCK_RESPONSE = 0xB2;

// Lock is phone-initiated, the mirror image of unlock. The phone asks, the PC
// replies once it has acted. Appended, never inserted, so existing IDs keep
// their meaning on already-paired devices.
constexpr uint16_t PACKET_ID_LOCK_CHALLENGE = 0xB3;
constexpr uint16_t PACKET_ID_LOCK_REQUEST = 0xB4;
constexpr uint16_t PACKET_ID_LOCK_RESPONSE = 0xB5;

struct PacketPairInit { // From phone
  std::string protoVersion{};
  std::string deviceUUID{};
  std::string deviceName{};
  std::string ipAddress{};
  uint16_t tcpPort{};
  uint16_t udpPort{};
  uint16_t udpManualPort{};
  std::string cloudToken{};

  static std::optional<PacketPairInit> FromJson(const std::string &jsonStr) {
    try {
      auto json = nlohmann::json::parse(jsonStr);
      auto packet = PacketPairInit();
      packet.protoVersion = json["protoVersion"];
      try {
        packet.deviceUUID = json["deviceUUID"];
        packet.deviceName = json["deviceName"];
        packet.ipAddress = json["ipAddress"];
        packet.tcpPort = json["tcpPort"];
        packet.udpPort = json["udpPort"];
        packet.udpManualPort = json["udpManualPort"];
        packet.cloudToken = json["cloudToken"];
      } catch(...) {
      }
      return packet;
    } catch(...) {
    }
    return {};
  }
};

struct PacketPairResponseData { // From PC
  PairingMethod pairingMethod{};
  std::string deviceId{};
  std::string deviceName{};
  std::string deviceOS{};
  uint16_t unlockServerPort{};
  std::vector<std::string> macAddresses{};
  std::string userName{};
  std::string passwordKey{};

  nlohmann::json ToJson() {
    return {{"pairingMethod", PairingMethodUtils::ToString(pairingMethod)},
            {"deviceId", deviceId},
            {"deviceName", deviceName},
            {"deviceOS", deviceOS},
            {"unlockServerPort", unlockServerPort},
            {"macAddresses", macAddresses},
            {"userName", userName},
            {"passwordKey", passwordKey}};
  }
};

struct PacketPairResponse { // From PC
  std::string errMsg{};
  PacketPairResponseData data{};

  nlohmann::json ToJson() {
    return {{"errMsg", errMsg}, {"data", data.ToJson()}};
  }
};

struct PacketUnlockRequest {
  std::string protoVersion;
  std::string deviceId;
  std::string encData;

  nlohmann::json ToJson() {
    return {{"protoVersion", protoVersion}, {"deviceId", deviceId}, {"encData", encData}};
  }
};

struct PacketUnlockRequestData {
  std::string user;
  std::string program;
  std::string unlockToken;

  nlohmann::json ToJson() {
    return {{"user", user}, {"program", program}, {"unlockToken", unlockToken}};
  }
};

struct PacketUnlockResponse {
  std::string error;
  std::string encData;

  static std::optional<PacketUnlockResponse> FromJson(const std::string &jsonStr) {
    try {
      auto json = nlohmann::json::parse(jsonStr);
      auto packet = PacketUnlockResponse();
      packet.error = json["error"];
      packet.encData = json["encData"];
      return packet;
    } catch(...) {
    }
    return {};
  }
};

struct PacketUnlockResponseData {
  std::string unlockToken;
  std::string passwordKey;

  static std::optional<PacketUnlockResponseData> FromJson(const std::string &jsonStr) {
    try {
      auto json = nlohmann::json::parse(jsonStr);
      auto packet = PacketUnlockResponseData();
      packet.unlockToken = json["unlockToken"];
      packet.passwordKey = json["passwordKey"];
      return packet;
    } catch(...) {
    }
    return {};
  }
};

// PC -> phone. A fresh nonce the phone must echo inside its lock request.
//
// Unlock has the PC speak first, so its token rides along with the request.
// Lock is phone-initiated, which would leave nothing to bind the request to a
// single exchange - a captured packet would replay for the whole +/-2min
// crypto window. So the PC issues a challenge first and the direction of the
// handshake stays the same as unlock: the PC always owns the nonce.
struct PacketLockChallenge {
  std::string lockToken;

  nlohmann::json ToJson() {
    return {{"lockToken", lockToken}};
  }
};

// Phone -> PC, encrypted with the paired device key.
struct PacketLockRequest {
  std::string protoVersion;
  std::string deviceId;
  std::string encData;

  static std::optional<PacketLockRequest> FromJson(const std::string &jsonStr) {
    try {
      auto json = nlohmann::json::parse(jsonStr);
      auto packet = PacketLockRequest();
      packet.protoVersion = json["protoVersion"];
      packet.deviceId = json["deviceId"];
      packet.encData = json["encData"];
      return packet;
    } catch(...) {
    }
    return {};
  }
};

// The encrypted half. `lockToken` must match the challenge we just issued.
struct PacketLockRequestData {
  std::string lockToken;
  std::string reason;

  static std::optional<PacketLockRequestData> FromJson(const std::string &jsonStr) {
    try {
      auto json = nlohmann::json::parse(jsonStr);
      auto packet = PacketLockRequestData();
      packet.lockToken = json["lockToken"];
      try {
        packet.reason = json["reason"];
      } catch(...) {
      }
      return packet;
    } catch(...) {
    }
    return {};
  }
};

// PC -> phone, once the lock has been attempted.
struct PacketLockResponse {
  std::string error;
  bool locked{};

  nlohmann::json ToJson() {
    return {{"error", error}, {"locked", locked}};
  }
};

struct PacketUDPBroadcast {
  std::string deviceId;
  std::string pcbuIP;
  uint16_t pcbuPort;
  bool isManual;

  nlohmann::json ToJson() {
    return {{"deviceId", deviceId}, {"pcbuIP", pcbuIP}, {"pcbuPort", pcbuPort}, {"isManual", isManual}};
  }
};

struct PacketUDPPairBeacon {
  std::string serverId;
  std::string ip;
  uint16_t port;

  nlohmann::json ToJson() {
    return {{"serverId", serverId}, {"ip", ip}, {"port", port}};
  }
};

#endif // PCBU_DESKTOP_PACKETS_H

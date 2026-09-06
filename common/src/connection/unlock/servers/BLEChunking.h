#ifndef PCBU_DESKTOP_BLECHUNKING_H
#define PCBU_DESKTOP_BLECHUNKING_H

#include <cstdint>
#include <optional>
#include <vector>

// BLE chunking, the layer that lets the existing frame format survive a
// transport with a small MTU.
//
// A BLE ATT payload is (MTU - 3) bytes; a negotiated MTU is typically ~185 and
// 23 is the mandatory floor. One unlock frame runs 300-500 bytes once the JSON
// is hex-encoded, so frames must be split and reassembled.
//
// This MUST stay byte-identical to the phone's lib/protocol/ble_chunking.dart.
//
// Chunk layout:
//   byte 0   : sequence number, uint8, wraps at 256
//   byte 1   : flags, bit0 set means "last chunk of this frame"
//   byte 2.. : payload slice
constexpr size_t BLE_CHUNK_HEADER_SIZE = 2;
constexpr uint8_t BLE_CHUNK_FLAG_LAST = 0x01;

// Upper bound on a reassembled frame. The protocol caps packets at
// CRYPT_BUFFER_SIZE (2048); this leaves headroom while still refusing a peer
// that streams forever without terminating.
constexpr size_t BLE_MAX_FRAME_SIZE = 8192;

class BLEChunking {
public:
  // Splits one framed packet into chunks of at most maxPayloadPerChunk bytes
  // of payload each. An empty frame still yields one terminating chunk.
  static std::vector<std::vector<uint8_t>> ChunkFrame(const std::vector<uint8_t> &frame, size_t maxPayloadPerChunk);

private:
  BLEChunking() = default;
};

// Reassembles chunks back into whole frames.
//
// A sequence gap discards the partial frame rather than emitting a spliced
// one. A corrupted frame would fail the GCM tag anyway, but dropping it early
// gives a clearer failure.
class BLEReassembler {
public:
  // Returns the completed frame once the last chunk arrives, otherwise
  // std::nullopt. Returns std::nullopt and resets on a malformed or
  // out-of-order chunk; check HasError() to distinguish.
  std::optional<std::vector<uint8_t>> Add(const uint8_t *chunk, size_t length);

  // True when the last Add() rejected its input.
  [[nodiscard]] bool HasError() const { return m_HasError; }
  [[nodiscard]] const std::string &GetError() const { return m_Error; }

  // Drop any partial frame; call on disconnect.
  void Reset();

  [[nodiscard]] size_t BufferedBytes() const { return m_Buffer.size(); }

private:
  void Fail(const std::string &reason);

  std::vector<uint8_t> m_Buffer{};
  bool m_HasExpectedSeq{};
  uint8_t m_ExpectedSeq{};
  bool m_HasError{};
  std::string m_Error{};
};

#endif // PCBU_DESKTOP_BLECHUNKING_H

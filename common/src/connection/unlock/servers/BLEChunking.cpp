#include "BLEChunking.h"

#include <algorithm>
#include <cstring>
#include <spdlog/spdlog.h>

std::vector<std::vector<uint8_t>> BLEChunking::ChunkFrame(const std::vector<uint8_t> &frame, size_t maxPayloadPerChunk) {
  std::vector<std::vector<uint8_t>> result{};
  if(maxPayloadPerChunk < 1) {
    spdlog::error("BLEChunking: maxPayloadPerChunk must be >= 1.");
    return result;
  }

  // An empty frame still needs one chunk, or the peer never sees a terminator.
  if(frame.empty()) {
    result.push_back({0, BLE_CHUNK_FLAG_LAST});
    return result;
  }

  size_t offset = 0;
  uint32_t seq = 0;
  while(offset < frame.size()) {
    auto take = std::min(maxPayloadPerChunk, frame.size() - offset);
    auto isLast = (offset + take) >= frame.size();

    std::vector<uint8_t> chunk(BLE_CHUNK_HEADER_SIZE + take);
    chunk[0] = static_cast<uint8_t>(seq & 0xFF);
    chunk[1] = isLast ? BLE_CHUNK_FLAG_LAST : 0x00;
    std::memcpy(chunk.data() + BLE_CHUNK_HEADER_SIZE, frame.data() + offset, take);

    result.emplace_back(std::move(chunk));
    offset += take;
    seq++;
  }
  return result;
}

std::optional<std::vector<uint8_t>> BLEReassembler::Add(const uint8_t *chunk, size_t length) {
  m_HasError = false;
  m_Error.clear();

  if(chunk == nullptr || length < BLE_CHUNK_HEADER_SIZE) {
    Fail("chunk shorter than its header");
    return std::nullopt;
  }

  auto seq = chunk[0];
  auto isLast = (chunk[1] & BLE_CHUNK_FLAG_LAST) != 0;
  uint8_t want = m_HasExpectedSeq ? m_ExpectedSeq : 0;
  if(seq != want) {
    Fail(fmt::format("out-of-order chunk: expected seq {}, got {}", want, seq));
    return std::nullopt;
  }

  auto payloadLen = length - BLE_CHUNK_HEADER_SIZE;
  m_Buffer.insert(m_Buffer.end(), chunk + BLE_CHUNK_HEADER_SIZE, chunk + BLE_CHUNK_HEADER_SIZE + payloadLen);
  if(m_Buffer.size() > BLE_MAX_FRAME_SIZE) {
    Fail(fmt::format("frame exceeded {} bytes", BLE_MAX_FRAME_SIZE));
    return std::nullopt;
  }

  if(!isLast) {
    // uint8_t arithmetic wraps naturally at 256, matching the phone.
    m_ExpectedSeq = static_cast<uint8_t>(seq + 1);
    m_HasExpectedSeq = true;
    return std::nullopt;
  }

  auto frame = std::move(m_Buffer);
  Reset();
  return frame;
}

void BLEReassembler::Reset() {
  m_Buffer.clear();
  m_HasExpectedSeq = false;
  m_ExpectedSeq = 0;
}

void BLEReassembler::Fail(const std::string &reason) {
  spdlog::warn("BLEReassembler: {}", reason);
  m_HasError = true;
  m_Error = reason;
  Reset();
}

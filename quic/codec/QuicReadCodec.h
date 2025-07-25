/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Decode.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/Types.h>
#include <quic/common/BufUtil.h>
#include <quic/common/Optional.h>
#include <quic/handshake/Aead.h>
#include <quic/state/AckStates.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

/**
 * Structure which describes data which could not be processed by
 * the read codec due to the required cipher being unavailable. The caller might
 * use this to retry later once the cipher is available.
 */
struct CipherUnavailable {
  BufPtr packet;
  ProtectionType protectionType;

  CipherUnavailable(BufPtr packetIn, ProtectionType protectionTypeIn)
      : packet(std::move(packetIn)), protectionType(protectionTypeIn) {}
};

/**
 * A type which represents no data.
 */
struct Nothing {
  PacketDropReason reason;

  Nothing() : reason(PacketDropReason::UNEXPECTED_NOTHING) {}

  explicit Nothing(PacketDropReason reasonIn) : reason(reasonIn) {}
};

struct CodecError {
  QuicError error;

  explicit CodecError(QuicError errorIn) : error(std::move(errorIn)) {}
};

struct CodecResult {
  enum class Type {
    REGULAR_PACKET,
    RETRY,
    CIPHER_UNAVAILABLE,
    STATELESS_RESET,
    NOTHING,
    CODEC_ERROR
  };

  ~CodecResult();

  CodecResult(CodecResult&& other) noexcept;
  CodecResult& operator=(CodecResult&& other) noexcept;

  /* implicit */ CodecResult(RegularQuicPacket&& regularPacketIn);
  /* implicit */ CodecResult(CipherUnavailable&& cipherUnavailableIn);
  /* implicit */ CodecResult(StatelessReset&& statelessReset);
  /* implicit */ CodecResult(RetryPacket&& retryPacket);
  /* implicit */ CodecResult(Nothing&& nothing);
  /* implicit */ CodecResult(CodecError&& codecErrorIn);

  Type type();
  RegularQuicPacket* regularPacket();
  CipherUnavailable* cipherUnavailable();
  StatelessReset* statelessReset();
  RetryPacket* retryPacket();
  Nothing* nothing();
  CodecError* codecError();

 private:
  void destroyCodecResult();

  union {
    RegularQuicPacket packet;
    RetryPacket retry;
    CipherUnavailable cipher;
    StatelessReset reset;
    Nothing none;
    CodecError error;
  };

  Type type_;
};

/**
 * Reads given data and returns parsed long header.
 * Returns an error if parsing is unsuccessful.
 */
quic::Expected<ParsedLongHeader, TransportErrorCode> tryParseLongHeader(
    Cursor& cursor,
    QuicNodeType nodeType);

class QuicReadCodec {
 public:
  virtual ~QuicReadCodec() = default;

  explicit QuicReadCodec(QuicNodeType nodeType);

  /**
   * Tries to parse a packet from the buffer data.
   * If it is able to parse the packet, then it returns
   * a valid QUIC packet. If it is not able to parse a packet it might return a
   * cipher unavailable structure. The caller can then retry when the cipher is
   * available. A client should call tryParsingVersionNegotiation
   * before the version is negotiated to detect VN.
   */
  virtual CodecResult parsePacket(
      BufQueue& queue,
      const AckStates& ackStates,
      size_t dstConnIdSize = kDefaultConnectionIdSize);

  /**
   * Tries to parse the packet and returns whether or not
   * it is a version negotiation packet.
   * This returns std::nullopt if the packet is either not
   * a VN packet or is invalid.
   */
  Optional<VersionNegotiationPacket> tryParsingVersionNegotiation(
      BufQueue& queue);

  const Aead* getOneRttReadCipher() const;
  const Aead* getZeroRttReadCipher() const;
  const Aead* getHandshakeReadCipher() const;

  const Aead* getInitialCipher() const;

  const PacketNumberCipher* getInitialHeaderCipher() const;
  const PacketNumberCipher* getOneRttHeaderCipher() const;
  const PacketNumberCipher* getHandshakeHeaderCipher() const;
  const PacketNumberCipher* getZeroRttHeaderCipher() const;

  const Optional<StatelessResetToken>& getStatelessResetToken() const;

  [[nodiscard]] ProtectionType getCurrentOneRttReadPhase() const;

  CodecParameters getCodecParameters() const;

  void setInitialReadCipher(std::unique_ptr<Aead> initialReadCipher);
  void setOneRttReadCipher(std::unique_ptr<Aead> oneRttReadCipher);
  void setNextOneRttReadCipher(std::unique_ptr<Aead> oneRttReadCipher);
  void setZeroRttReadCipher(std::unique_ptr<Aead> zeroRttReadCipher);
  void setHandshakeReadCipher(std::unique_ptr<Aead> handshakeReadCipher);

  void setInitialHeaderCipher(
      std::unique_ptr<PacketNumberCipher> initialHeaderCipher);
  void setOneRttHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttHeaderCipher);
  void setZeroRttHeaderCipher(
      std::unique_ptr<PacketNumberCipher> zeroRttHeaderCipher);
  void setHandshakeHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeHeaderCipher);

  void setCodecParameters(CodecParameters params);
  void setClientConnectionId(ConnectionId connId);
  void setServerConnectionId(ConnectionId connId);
  void setStatelessResetToken(StatelessResetToken statelessResetToken);
  void setCryptoEqual(std::function<bool(ByteRange, ByteRange)> cryptoEqual);
  const ConnectionId& getClientConnectionId() const;
  const ConnectionId& getServerConnectionId() const;

  void setConnectionStatsCallback(QuicTransportStatsCallback* callback);

  /**
   * Returns true if the (local) transport can initiate a key update. This is
   * true if:
   *    - the nextOneRttReadCipher is available, and
   *    - we have received enough packets in the current one rtt phase.
   */
  [[nodiscard]] bool canInitiateKeyUpdate() const;

  /*
   * Advance the current one rtt read cipher to the next one.
   * This discards the previous one rtt read cipher and leaves the next one rtt
   * read cipher unset.
   *
   * Returns true if the cipher was successfully advanced.
   */
  bool advanceOneRttReadPhase();

  /**
   * Should be invoked when the state machine believes that the handshake is
   * complete.
   */
  void onHandshakeDone(TimePoint handshakeDoneTime);

  Optional<TimePoint> getHandshakeDoneTime();

 private:
  quic::Expected<CodecResult, QuicError> tryParseShortHeaderPacket(
      BufPtr data,
      const AckStates& ackStates,
      size_t dstConnIdSize,
      Cursor& cursor);
  quic::Expected<CodecResult, QuicError> parseLongHeaderPacket(
      BufQueue& queue,
      const AckStates& ackStates);

  [[nodiscard]] std::string connIdToHex() const;

  QuicNodeType nodeType_;

  CodecParameters params_;
  Optional<ConnectionId> clientConnectionId_;
  Optional<ConnectionId> serverConnectionId_;

  // Cipher used to decrypt handshake packets.
  std::unique_ptr<Aead> initialReadCipher_;

  std::unique_ptr<Aead> zeroRttReadCipher_;
  std::unique_ptr<Aead> handshakeReadCipher_;

  std::unique_ptr<Aead> previousOneRttReadCipher_;
  std::unique_ptr<Aead> currentOneRttReadCipher_;
  std::unique_ptr<Aead> nextOneRttReadCipher_;
  ProtectionType currentOneRttReadPhase_{ProtectionType::KeyPhaseZero};
  // The packet number of the first packet in the current 1-RTT phase
  // It's not set when a key update is ongoing (i.e. the write key has been
  // updated but no packets have been received with the corresponding read key)
  Optional<PacketNum> currentOneRttReadPhaseStartPacketNum_{0};

  std::unique_ptr<PacketNumberCipher> initialHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> oneRttHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> zeroRttHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> handshakeHeaderCipher_;

  Optional<StatelessResetToken> statelessResetToken_;
  std::function<bool(ByteRange, ByteRange)> cryptoEqual_;
  Optional<TimePoint> handshakeDoneTime_;

  QuicTransportStatsCallback* statsCallback_{nullptr};
};

} // namespace quic

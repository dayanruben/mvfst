/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicReadCodec.h>

#include <folly/io/Cursor.h>
#include <quic/codec/Decode.h>
#include <quic/codec/PacketNumber.h>

namespace quic {

QuicReadCodec::QuicReadCodec(QuicNodeType nodeType) : nodeType_(nodeType) {}

Optional<VersionNegotiationPacket> QuicReadCodec::tryParsingVersionNegotiation(
    BufQueue& queue) {
  Cursor cursor(queue.front());
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    return std::nullopt;
  }
  uint8_t initialByte = cursor.readBE<uint8_t>();
  auto headerForm = getHeaderForm(initialByte);
  if (headerForm != HeaderForm::Long) {
    return std::nullopt;
  }
  auto longHeaderInvariant = parseLongHeaderInvariant(initialByte, cursor);
  if (!longHeaderInvariant) {
    // if it is an invalid packet, it's definitely not a VN packet, so ignore
    // it.
    return std::nullopt;
  }
  if (longHeaderInvariant->invariant.version !=
      QuicVersion::VERSION_NEGOTIATION) {
    return std::nullopt;
  }
  return decodeVersionNegotiation(*longHeaderInvariant, cursor);
}

quic::Expected<ParsedLongHeader, TransportErrorCode> tryParseLongHeader(
    Cursor& cursor,
    QuicNodeType nodeType) {
  if (cursor.isAtEnd() || !cursor.canAdvance(sizeof(uint8_t))) {
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto initialByte = cursor.readBE<uint8_t>();
  auto longHeaderInvariant = parseLongHeaderInvariant(initialByte, cursor);
  if (!longHeaderInvariant) {
    VLOG(4) << "Dropping packet, failed to parse invariant";
    // We've failed to parse the long header, so we have no idea where this
    // packet ends. Clear the queue since no other data in this packet is
    // parse-able.
    return quic::make_unexpected(longHeaderInvariant.error());
  }
  if (longHeaderInvariant->invariant.version ==
      QuicVersion::VERSION_NEGOTIATION) {
    // We shouldn't handle VN packets while parsing the long header.
    // We assume here that they have been handled before calling this
    // function.
    // Since VN is not allowed to be coalesced with another packet
    // type, we clear out the buffer to avoid anyone else parsing it.
    return quic::make_unexpected(TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto type = parseLongHeaderType(initialByte);

  auto parsedLongHeader =
      parseLongHeaderVariants(type, *longHeaderInvariant, cursor, nodeType);
  if (!parsedLongHeader) {
    VLOG(4) << "Dropping due to failed to parse header";
    // We've failed to parse the long header, so we have no idea where this
    // packet ends. Clear the queue since no other data in this packet is
    // parse-able.
    return quic::make_unexpected(parsedLongHeader.error());
  }

  return std::move(parsedLongHeader.value());
}

static PacketDropReason getDecryptErrorReason(ProtectionType protectionType) {
  switch (protectionType) {
    case ProtectionType::Initial:
      return PacketDropReason::DECRYPTION_ERROR_INITIAL;
    case ProtectionType::Handshake:
      return PacketDropReason::DECRYPTION_ERROR_HANDSHAKE;
    case ProtectionType::ZeroRtt:
      return PacketDropReason::DECRYPTION_ERROR_0RTT;
    default:
      return PacketDropReason::DECRYPTION_ERROR;
  }
}

quic::Expected<CodecResult, QuicError> QuicReadCodec::parseLongHeaderPacket(
    BufQueue& queue,
    const AckStates& ackStates) {
  Cursor cursor(queue.front());
  const uint8_t initialByte = *cursor.peekBytes().data();

  auto res = tryParseLongHeader(cursor, nodeType_);
  if (res.hasError()) {
    VLOG(4) << "Failed to parse long header " << connIdToHex();
    queue.move();
    return CodecResult(Nothing());
  }
  auto parsedLongHeader = std::move(res.value());
  auto type = parsedLongHeader.header.getHeaderType();

  // As soon as we have parsed out the long header we can split off any
  // coalesced packets. We do this early since the spec mandates that decryption
  // failure must not stop the processing of subsequent coalesced packets.
  auto longHeader = std::move(parsedLongHeader.header);

  if (type == LongHeader::Types::Retry) {
    auto integrityTag = cursor.read<RetryPacket::IntegrityTagType>();
    queue.move();
    return RetryPacket(std::move(longHeader), integrityTag, initialByte);
  }

  uint64_t packetNumberOffset = cursor.getCurrentPosition();
  size_t currentPacketLen =
      packetNumberOffset + parsedLongHeader.packetLength.packetLength;
  if (queue.chainLength() < currentPacketLen) {
    // Packet appears truncated, there's no parse-able data left.
    queue.move();
    return CodecResult(Nothing());
  }
  auto currentPacketData = queue.splitAtMost(currentPacketLen);
  cursor.reset(currentPacketData.get());
  cursor.skip(packetNumberOffset);
  // Sample starts after the max packet number size. This ensures that we
  // have enough bytes to skip before we can start reading the sample.
  if (!cursor.canAdvance(kMaxPacketNumEncodingSize)) {
    VLOG(4) << "Dropping packet, not enough for packet number "
            << connIdToHex();
    // Packet appears truncated, there's no parse-able data left.
    queue.move();
    return CodecResult(Nothing());
  }
  cursor.skip(kMaxPacketNumEncodingSize);
  Sample sample;
  if (!cursor.canAdvance(sample.size())) {
    VLOG(4) << "Dropping packet, sample too small " << connIdToHex();
    // Packet appears truncated, there's no parse-able data left.
    queue.move();
    return CodecResult(Nothing());
  }
  cursor.pull(sample.data(), sample.size());
  const PacketNumberCipher* headerCipher{nullptr};
  const Aead* cipher{nullptr};
  auto protectionType = longHeader.getProtectionType();
  switch (protectionType) {
    case ProtectionType::Initial:
      if (!initialHeaderCipher_) {
        VLOG(4) << nodeToString(nodeType_)
                << " dropping initial packet after initial keys dropped"
                << connIdToHex();
        return CodecResult(Nothing());
      }
      headerCipher = initialHeaderCipher_.get();
      cipher = initialReadCipher_.get();
      break;
    case ProtectionType::Handshake:
      headerCipher = handshakeHeaderCipher_.get();
      cipher = handshakeReadCipher_.get();
      break;
    case ProtectionType::ZeroRtt:
      if (handshakeDoneTime_) {
        // TODO actually drop the 0-rtt keys in addition to dropping packets.
        auto timeBetween = Clock::now() - *handshakeDoneTime_;
        if (timeBetween > kTimeToRetainZeroRttKeys) {
          VLOG(4) << nodeToString(nodeType_)
                  << " dropping zero rtt packet for exceeding key timeout"
                  << connIdToHex();
          return CodecResult(Nothing());
        }
      }
      headerCipher = zeroRttHeaderCipher_.get();
      cipher = zeroRttReadCipher_.get();
      break;
    case ProtectionType::KeyPhaseZero:
    case ProtectionType::KeyPhaseOne:
      CHECK(false) << "one rtt protection type in long header";
  }
  if (!headerCipher || !cipher) {
    return CodecResult(
        CipherUnavailable(std::move(currentPacketData), protectionType));
  }

  PacketNum expectedNextPacketNum = 0;
  Optional<PacketNum> largestRecvdPacketNum;
  switch (longHeaderTypeToProtectionType(type)) {
    case ProtectionType::Initial:
      largestRecvdPacketNum = ackStates.initialAckState->largestRecvdPacketNum;

      break;
    case ProtectionType::Handshake:
      largestRecvdPacketNum =
          ackStates.handshakeAckState->largestRecvdPacketNum;

      break;
    case ProtectionType::ZeroRtt:
      largestRecvdPacketNum = ackStates.appDataAckState.largestRecvdPacketNum;

      break;
    default:
      folly::assume_unreachable();
  }
  if (largestRecvdPacketNum) {
    expectedNextPacketNum = 1 + *largestRecvdPacketNum;
  }
  MutableByteRange initialByteRange(currentPacketData->writableData(), 1);
  MutableByteRange packetNumberByteRange(
      currentPacketData->writableData() + packetNumberOffset,
      kMaxPacketNumEncodingSize);
  auto decryptResult = headerCipher->decryptLongHeader(
      folly::range(sample), initialByteRange, packetNumberByteRange);
  if (decryptResult.hasError()) {
    VLOG(4) << "Failed to decrypt long header " << connIdToHex();
    return quic::make_unexpected(decryptResult.error());
  }
  std::pair<PacketNum, size_t> packetNum = parsePacketNumber(
      initialByteRange.data()[0], packetNumberByteRange, expectedNextPacketNum);

  longHeader.setPacketNumber(packetNum.first);
  BufQueue decryptQueue;
  decryptQueue.append(std::move(currentPacketData));
  size_t aadLen = packetNumberOffset + packetNum.second;
  auto headerData = decryptQueue.splitAtMost(aadLen);
  // parsing verifies that packetLength >= packet number length.
  auto encryptedData = decryptQueue.splitAtMost(
      parsedLongHeader.packetLength.packetLength - packetNum.second);
  if (!encryptedData) {
    // There should normally be some integrity tag at least in the data,
    // however allowing the aead to process the data even if the tag is not
    // present helps with writing tests.
    encryptedData = BufHelpers::create(0);
  }

  BufPtr decrypted;
  auto decryptAttempt = cipher->tryDecrypt(
      std::move(encryptedData), headerData.get(), packetNum.first);
  if (!decryptAttempt) {
    VLOG(4) << "Unable to decrypt packet=" << packetNum.first
            << " packetNumLen=" << parsePacketNumberLength(initialByte)
            << " protectionType=" << toString(protectionType) << " "
            << connIdToHex();
    return CodecResult(Nothing(getDecryptErrorReason(protectionType)));
  }
  decrypted = std::move(*decryptAttempt);

  if (!decrypted) {
    // TODO better way of handling this (tests break without this)
    decrypted = BufHelpers::create(0);
  }

  auto packetRes =
      decodeRegularPacket(std::move(longHeader), params_, std::move(decrypted));

  if (!packetRes.has_value()) {
    return CodecResult(CodecError(std::move(packetRes.error())));
  }

  return CodecResult(std::move(*packetRes));
}

quic::Expected<CodecResult, QuicError> QuicReadCodec::tryParseShortHeaderPacket(
    BufPtr data,
    const AckStates& ackStates,
    size_t dstConnIdSize,
    Cursor& cursor) {
  // TODO: allow other connid lengths from the state.
  size_t packetNumberOffset = 1 + dstConnIdSize;
  PacketNum expectedNextPacketNum =
      ackStates.appDataAckState.largestRecvdPacketNum
      ? (1 + *ackStates.appDataAckState.largestRecvdPacketNum)
      : 0;
  size_t sampleOffset = packetNumberOffset + kMaxPacketNumEncodingSize;
  Sample sample;
  if (data->computeChainDataLength() < sampleOffset + sample.size()) {
    VLOG(10) << "Dropping packet, too small for sample " << connIdToHex();
    // There's not enough space for the short header packet
    return CodecResult(Nothing());
  }

  MutableByteRange initialByteRange(data->writableData(), 1);
  MutableByteRange packetNumberByteRange(
      data->writableData() + packetNumberOffset, kMaxPacketNumEncodingSize);
  ByteRange sampleByteRange(data->writableData() + sampleOffset, sample.size());

  auto decryptResult = oneRttHeaderCipher_->decryptShortHeader(
      sampleByteRange, initialByteRange, packetNumberByteRange);
  if (decryptResult.hasError()) {
    VLOG(4) << "Failed to decrypt short header " << connIdToHex();
    return quic::make_unexpected(decryptResult.error());
  }
  std::pair<PacketNum, size_t> packetNum = parsePacketNumber(
      initialByteRange.data()[0], packetNumberByteRange, expectedNextPacketNum);
  auto shortHeader =
      parseShortHeader(initialByteRange.data()[0], cursor, dstConnIdSize);
  if (!shortHeader) {
    VLOG(10) << "Dropping packet, cannot parse " << connIdToHex();
    return CodecResult(Nothing());
  }
  shortHeader->setPacketNumber(packetNum.first);
  bool peerKeyUpdateAttempt = false;
  auto oneRttReadCipherToUse = [&]() -> Aead* {
    if (shortHeader->getProtectionType() == currentOneRttReadPhase_) {
      return currentOneRttReadCipher_.get();
    } else {
      // This is a packet from a different phase. It may be encrypted using the
      // next key (new peer-initiated key update) or the previous key (out of
      // order packet or pending locally-initiated key update).

      if (!currentOneRttReadPhaseStartPacketNum_ ||
          shortHeader->getPacketSequenceNum() <
              currentOneRttReadPhaseStartPacketNum_.value()) {
        // There is either a pending key update or this an out-of-order packet,
        // attempt to use the previous cipher
        if (previousOneRttReadCipher_) {
          return previousOneRttReadCipher_.get();
        } else {
          // There is no previous packet. We can't decrypt this packet
          VLOG(4)
              << nodeToString(nodeType_)
              << " cannot read packet using previous cipher. Cipher is not available";
          return nullptr;
        }
      } else {
        // This is a key update attempt
        if (nextOneRttReadCipher_) {
          peerKeyUpdateAttempt = true;
          QUIC_STATS(statsCallback_, onKeyUpdateAttemptReceived);
          return nextOneRttReadCipher_.get();
        } else {
          // The next cipher is not yet available. We can't decrypt this packet
          VLOG(4)
              << nodeToString(nodeType_)
              << " unable to process key update. Next cipher is not yet available";
          return nullptr;
        }
      }
    }
  }();

  if (oneRttReadCipherToUse == nullptr) {
    return CodecResult(
        CipherUnavailable(std::move(data), shortHeader->getProtectionType()));
  }

  // We know that the iobuf is not chained. This means that we can safely have
  // a non-owning reference to the header without cloning the buffer. If we
  // don't clone the buffer, the buffer will not show up as shared and we can
  // decrypt in-place.
  size_t aadLen = packetNumberOffset + packetNum.second;
  Buf headerData = BufHelpers::wrapBufferAsValue(data->data(), aadLen);
  data->trimStart(aadLen);

  BufPtr decrypted;
  auto decryptAttempt = oneRttReadCipherToUse->tryDecrypt(
      std::move(data), &headerData, packetNum.first);
  if (!decryptAttempt) {
    auto protectionType = shortHeader->getProtectionType();
    VLOG(10) << "Unable to decrypt packet=" << packetNum.first
             << " protectionType=" << (int)protectionType << " "
             << connIdToHex();
    return CodecResult(Nothing(PacketDropReason::DECRYPTION_ERROR));
  }
  decrypted = std::move(*decryptAttempt);
  if (!decrypted) {
    // TODO better way of handling this (tests break without this)
    decrypted = BufHelpers::create(0);
  }

  if (peerKeyUpdateAttempt) {
    // Peer initiated a key update and we've successfully decrypted a packet
    // from the next phase. We should advance our oneRttCipher state.
    currentOneRttReadPhase_ = shortHeader->getProtectionType();
    currentOneRttReadPhaseStartPacketNum_.reset();
    previousOneRttReadCipher_.reset(currentOneRttReadCipher_.release());
    currentOneRttReadCipher_.reset(nextOneRttReadCipher_.release());
    // nextOneRttReadCipher_ will be populated by the transport
  }

  if (!currentOneRttReadPhaseStartPacketNum_.has_value() &&
      oneRttReadCipherToUse == currentOneRttReadCipher_.get()) {
    // This is the first packet in the current phase. Record the packet
    // number. This applies for both peer-initiated and self-initiated key
    // updates.
    currentOneRttReadPhaseStartPacketNum_ = shortHeader->getPacketSequenceNum();
    QUIC_STATS(statsCallback_, onKeyUpdateAttemptSucceeded);
  }

  // TODO: Should we discard the previous cipher at some point? Keeping it
  // around avoids the timing signals mentioned in the spec, but we could also
  // drop it after 3 * PTO.

  auto packetRes = decodeRegularPacket(
      std::move(*shortHeader), params_, std::move(decrypted));

  if (!packetRes.has_value()) {
    return CodecResult(CodecError(std::move(packetRes.error())));
  }
  return CodecResult(std::move(*packetRes));
}

CodecResult QuicReadCodec::parsePacket(
    BufQueue& queue,
    const AckStates& ackStates,
    size_t dstConnIdSize) {
  if (queue.empty()) {
    return CodecResult(Nothing());
  }
  DCHECK(!queue.front()->isChained());
  Cursor cursor(queue.front());
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    return CodecResult(Nothing());
  }
  uint8_t initialByte = cursor.readBE<uint8_t>();
  auto headerForm = getHeaderForm(initialByte);
  if (headerForm == HeaderForm::Long) {
    auto result = parseLongHeaderPacket(queue, ackStates);
    if (result.hasError()) {
      return CodecResult(CodecError(std::move(result.error())));
    }
    return std::move(result.value());
  }
  // Missing 1-rtt header cipher is the only case we wouldn't consider reset
  if (!currentOneRttReadCipher_ || !oneRttHeaderCipher_) {
    VLOG(4) << nodeToString(nodeType_) << " cannot read key phase zero packet";
    VLOG(20) << "cannot read data="
             << folly::hexlify(queue.front()->clone()->moveToFbString()) << " "
             << connIdToHex();
    return CodecResult(
        CipherUnavailable(queue.move(), ProtectionType::KeyPhaseZero));
  }

  auto data = queue.move();
  Optional<StatelessResetToken> token;
  if (nodeType_ == QuicNodeType::Client &&
      initialByte & ShortHeader::kFixedBitMask) {
    auto dataLength = data->length();
    if (statelessResetToken_ && dataLength > sizeof(StatelessResetToken)) {
      const uint8_t* tokenSource =
          data->data() + (dataLength - sizeof(StatelessResetToken));
      if (!cryptoEqual_) {
        return CodecResult(CodecError(QuicError(
            QuicErrorCode(LocalErrorCode::INTERNAL_ERROR),
            "crypto constant time comparison function is not set.")));
      }
      // Only allocate & copy the token if it matches the token we have
      if (cryptoEqual_(
              ByteRange(tokenSource, sizeof(StatelessResetToken)),
              ByteRange(
                  statelessResetToken_->data(), sizeof(StatelessResetToken)))) {
        token = StatelessResetToken();
        memcpy(token->data(), tokenSource, token->size());
        return StatelessReset(*token);
      }
    }
  }
  auto result = tryParseShortHeaderPacket(
      std::move(data), ackStates, dstConnIdSize, cursor);
  if (result.hasError()) {
    return CodecResult(CodecError(std::move(result.error())));
  }
  return std::move(result.value());
}

bool QuicReadCodec::canInitiateKeyUpdate() const {
  if (!nextOneRttReadCipher_ || !currentOneRttReadPhaseStartPacketNum_) {
    // We haven't received any packets in the current oneRtt phase yet.
    return false;
  }
  return true;
}

bool QuicReadCodec::advanceOneRttReadPhase() {
  if (!canInitiateKeyUpdate()) {
    LOG(WARNING) << "Key update requested before the read codec can allow it";
    return false;
  }
  previousOneRttReadCipher_.reset(currentOneRttReadCipher_.release());
  currentOneRttReadCipher_.reset(nextOneRttReadCipher_.release());
  currentOneRttReadPhase_ =
      (currentOneRttReadPhase_ == ProtectionType::KeyPhaseZero)
      ? ProtectionType::KeyPhaseOne
      : ProtectionType::KeyPhaseZero;
  currentOneRttReadPhaseStartPacketNum_.reset();
  return true;
}

const Aead* QuicReadCodec::getOneRttReadCipher() const {
  return currentOneRttReadCipher_.get();
}

const Aead* QuicReadCodec::getZeroRttReadCipher() const {
  return zeroRttReadCipher_.get();
}

const Aead* QuicReadCodec::getHandshakeReadCipher() const {
  return handshakeReadCipher_.get();
}

const Optional<StatelessResetToken>& QuicReadCodec::getStatelessResetToken()
    const {
  return statelessResetToken_;
}

CodecParameters QuicReadCodec::getCodecParameters() const {
  return params_;
}

void QuicReadCodec::setInitialReadCipher(
    std::unique_ptr<Aead> initialReadCipher) {
  initialReadCipher_ = std::move(initialReadCipher);
}

void QuicReadCodec::setOneRttReadCipher(
    std::unique_ptr<Aead> oneRttReadCipher) {
  currentOneRttReadCipher_ = std::move(oneRttReadCipher);
}

void QuicReadCodec::setNextOneRttReadCipher(
    std::unique_ptr<Aead> oneRttReadCipher) {
  nextOneRttReadCipher_ = std::move(oneRttReadCipher);
}

void QuicReadCodec::setZeroRttReadCipher(
    std::unique_ptr<Aead> zeroRttReadCipher) {
  CHECK(nodeType_ == QuicNodeType::Server)
      << "Setting zero rtt read cipher on client.";
  zeroRttReadCipher_ = std::move(zeroRttReadCipher);
}

void QuicReadCodec::setHandshakeReadCipher(
    std::unique_ptr<Aead> handshakeReadCipher) {
  handshakeReadCipher_ = std::move(handshakeReadCipher);
}

void QuicReadCodec::setInitialHeaderCipher(
    std::unique_ptr<PacketNumberCipher> initialHeaderCipher) {
  initialHeaderCipher_ = std::move(initialHeaderCipher);
}

void QuicReadCodec::setOneRttHeaderCipher(
    std::unique_ptr<PacketNumberCipher> oneRttHeaderCipher) {
  oneRttHeaderCipher_ = std::move(oneRttHeaderCipher);
}

void QuicReadCodec::setZeroRttHeaderCipher(
    std::unique_ptr<PacketNumberCipher> zeroRttHeaderCipher) {
  zeroRttHeaderCipher_ = std::move(zeroRttHeaderCipher);
}

void QuicReadCodec::setHandshakeHeaderCipher(
    std::unique_ptr<PacketNumberCipher> handshakeHeaderCipher) {
  handshakeHeaderCipher_ = std::move(handshakeHeaderCipher);
}

void QuicReadCodec::setCodecParameters(CodecParameters params) {
  params_ = std::move(params);
}

void QuicReadCodec::setClientConnectionId(ConnectionId connId) {
  clientConnectionId_ = connId;
}

void QuicReadCodec::setServerConnectionId(ConnectionId connId) {
  serverConnectionId_ = connId;
}

void QuicReadCodec::setStatelessResetToken(
    StatelessResetToken statelessResetToken) {
  statelessResetToken_ = std::move(statelessResetToken);
}

void QuicReadCodec::setCryptoEqual(
    std::function<bool(ByteRange, ByteRange)> cryptoEqual) {
  cryptoEqual_ = std::move(cryptoEqual);
}

void QuicReadCodec::setConnectionStatsCallback(
    QuicTransportStatsCallback* callback) {
  statsCallback_ = callback;
}

const ConnectionId& QuicReadCodec::getClientConnectionId() const {
  return clientConnectionId_.value();
}

const ConnectionId& QuicReadCodec::getServerConnectionId() const {
  return serverConnectionId_.value();
}

const Aead* QuicReadCodec::getInitialCipher() const {
  return initialReadCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getInitialHeaderCipher() const {
  return initialHeaderCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getOneRttHeaderCipher() const {
  return oneRttHeaderCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getHandshakeHeaderCipher() const {
  return handshakeHeaderCipher_.get();
}

const PacketNumberCipher* QuicReadCodec::getZeroRttHeaderCipher() const {
  return zeroRttHeaderCipher_.get();
}

void QuicReadCodec::onHandshakeDone(TimePoint handshakeDoneTime) {
  if (!handshakeDoneTime_) {
    handshakeDoneTime_ = handshakeDoneTime;
  }
}

Optional<TimePoint> QuicReadCodec::getHandshakeDoneTime() {
  return handshakeDoneTime_;
}

ProtectionType QuicReadCodec::getCurrentOneRttReadPhase() const {
  return currentOneRttReadPhase_;
}

std::string QuicReadCodec::connIdToHex() const {
  static ConnectionId zeroConn = ConnectionId::createZeroLength();
  const auto& serverId = serverConnectionId_.value_or(zeroConn);
  const auto& clientId = clientConnectionId_.value_or(zeroConn);
  return fmt::format(
      "server={} client={}", serverId.hex(), "client=", clientId.hex());
}

CodecResult::CodecResult(RegularQuicPacket&& regularPacketIn)
    : type_(CodecResult::Type::REGULAR_PACKET) {
  new (&packet) RegularQuicPacket(std::move(regularPacketIn));
}

CodecResult::CodecResult(CipherUnavailable&& cipherUnavailableIn)
    : type_(CodecResult::Type::CIPHER_UNAVAILABLE) {
  new (&cipher) CipherUnavailable(std::move(cipherUnavailableIn));
}

CodecResult::CodecResult(StatelessReset&& statelessResetIn)
    : type_(CodecResult::Type::STATELESS_RESET) {
  new (&reset) StatelessReset(std::move(statelessResetIn));
}

CodecResult::CodecResult(RetryPacket&& retryPacketIn)
    : type_(CodecResult::Type::RETRY) {
  new (&retry) RetryPacket(std::move(retryPacketIn));
}

CodecResult::CodecResult(Nothing&& nothing)
    : type_(CodecResult::Type::NOTHING) {
  new (&none) Nothing(std::move(nothing));
}

CodecResult::CodecResult(CodecError&& codecErrorIn)
    : type_(CodecResult::Type::CODEC_ERROR) {
  new (&error) CodecError(std::move(codecErrorIn));
}

CodecError* CodecResult::codecError() {
  if (type_ == CodecResult::Type::CODEC_ERROR) {
    return &error;
  }
  return nullptr;
}

void CodecResult::destroyCodecResult() {
  switch (type_) {
    case CodecResult::Type::REGULAR_PACKET:
      packet.~RegularQuicPacket();
      break;
    case CodecResult::Type::RETRY:
      retry.~RetryPacket();
      break;
    case CodecResult::Type::CIPHER_UNAVAILABLE:
      cipher.~CipherUnavailable();
      break;
    case CodecResult::Type::STATELESS_RESET:
      reset.~StatelessReset();
      break;
    case CodecResult::Type::NOTHING:
      none.~Nothing();
      break;
    case CodecResult::Type::CODEC_ERROR:
      error.~CodecError();
      break;
  }
}

CodecResult::~CodecResult() {
  destroyCodecResult();
}

CodecResult::CodecResult(CodecResult&& other) noexcept {
  switch (other.type_) {
    case CodecResult::Type::REGULAR_PACKET:
      new (&packet) RegularQuicPacket(std::move(other.packet));
      break;
    case CodecResult::Type::RETRY:
      new (&retry) RetryPacket(std::move(other.retry));
      break;
    case CodecResult::Type::CIPHER_UNAVAILABLE:
      new (&cipher) CipherUnavailable(std::move(other.cipher));
      break;
    case CodecResult::Type::STATELESS_RESET:
      new (&reset) StatelessReset(std::move(other.reset));
      break;
    case CodecResult::Type::NOTHING:
      new (&none) Nothing(std::move(other.none));
      break;
    case CodecResult::Type::CODEC_ERROR:
      new (&error) CodecError(std::move(other.error));
      break;
  }
  type_ = other.type_;
}

CodecResult& CodecResult::operator=(CodecResult&& other) noexcept {
  destroyCodecResult();
  switch (other.type_) {
    case CodecResult::Type::REGULAR_PACKET:
      new (&packet) RegularQuicPacket(std::move(other.packet));
      break;
    case CodecResult::Type::RETRY:
      new (&retry) RetryPacket(std::move(other.retry));
      break;
    case CodecResult::Type::CIPHER_UNAVAILABLE:
      new (&cipher) CipherUnavailable(std::move(other.cipher));
      break;
    case CodecResult::Type::STATELESS_RESET:
      new (&reset) StatelessReset(std::move(other.reset));
      break;
    case CodecResult::Type::NOTHING:
      new (&none) Nothing(std::move(other.none));
      break;
    case CodecResult::Type::CODEC_ERROR:
      new (&error) CodecError(std::move(other.error));
      break;
  }
  type_ = other.type_;
  return *this;
}

CodecResult::Type CodecResult::type() {
  return type_;
}

RegularQuicPacket* CodecResult::regularPacket() {
  if (type_ == CodecResult::Type::REGULAR_PACKET) {
    return &packet;
  }
  return nullptr;
}

CipherUnavailable* CodecResult::cipherUnavailable() {
  if (type_ == CodecResult::Type::CIPHER_UNAVAILABLE) {
    return &cipher;
  }
  return nullptr;
}

StatelessReset* CodecResult::statelessReset() {
  if (type_ == CodecResult::Type::STATELESS_RESET) {
    return &reset;
  }
  return nullptr;
}

RetryPacket* CodecResult::retryPacket() {
  if (type_ == CodecResult::Type::RETRY) {
    return &retry;
  }
  return nullptr;
}

Nothing* CodecResult::nothing() {
  if (type_ == CodecResult::Type::NOTHING) {
    return &none;
  }
  return nullptr;
}
} // namespace quic

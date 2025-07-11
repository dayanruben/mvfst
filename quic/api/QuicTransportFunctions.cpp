/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/tracing/StaticTracepoint.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/common/BufAccessor.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>

#include <quic/state/AckHandlers.h>
#include <quic/state/QuicAckFrequencyFunctions.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>

namespace {

/*
 *  Check whether crypto has pending data.
 */
bool cryptoHasWritableData(const quic::QuicConnectionStateBase& conn) {
  return (conn.initialWriteCipher &&
          (!conn.cryptoState->initialStream.pendingWrites.empty() ||
           !conn.cryptoState->initialStream.lossBuffer.empty())) ||
      (conn.handshakeWriteCipher &&
       (!conn.cryptoState->handshakeStream.pendingWrites.empty() ||
        !conn.cryptoState->handshakeStream.lossBuffer.empty())) ||
      (conn.oneRttWriteCipher &&
       (!conn.cryptoState->oneRttStream.pendingWrites.empty() ||
        !conn.cryptoState->oneRttStream.lossBuffer.empty()));
}

std::string optionalToString(const quic::Optional<quic::PacketNum>& packetNum) {
  if (!packetNum) {
    return "-";
  }
  return fmt::format("{}", *packetNum);
}

std::string largestAckScheduledToString(
    const quic::QuicConnectionStateBase& conn) noexcept {
  return fmt::format(
      "[{},{},{}]",
      optionalToString(
          conn.ackStates.initialAckState
              ? conn.ackStates.initialAckState->largestAckScheduled
              : std::nullopt),
      optionalToString(
          conn.ackStates.handshakeAckState
              ? conn.ackStates.handshakeAckState->largestAckScheduled
              : std::nullopt),
      optionalToString(conn.ackStates.appDataAckState.largestAckScheduled));
}

std::string largestAckToSendToString(
    const quic::QuicConnectionStateBase& conn) noexcept {
  return fmt::format(
      "[{},{},{}]",
      optionalToString(
          conn.ackStates.initialAckState
              ? largestAckToSend(*conn.ackStates.initialAckState)
              : std::nullopt),
      optionalToString(
          conn.ackStates.handshakeAckState
              ? largestAckToSend(*conn.ackStates.handshakeAckState)
              : std::nullopt),
      optionalToString(largestAckToSend(conn.ackStates.appDataAckState)));
}

using namespace quic;

/**
 * This function returns the number of write bytes that are available until we
 * reach the writableBytesLimit. It may or may not be the limiting factor on the
 * number of bytes we can write on the wire.
 *
 * If the client's address has not been verified, this will return the number of
 * write bytes available until writableBytesLimit is reached.
 *
 * Otherwise if the client's address is validated, it will return unlimited
 * number of bytes to write.
 */
uint64_t maybeUnvalidatedClientWritableBytes(
    quic::QuicConnectionStateBase& conn) {
  if (!conn.writableBytesLimit) {
    return unlimitedWritableBytes(conn);
  }

  if (*conn.writableBytesLimit <= conn.lossState.totalBytesSent) {
    QUIC_STATS(conn.statsCallback, onConnectionWritableBytesLimited);
    return 0;
  }

  uint64_t writableBytes =
      *conn.writableBytesLimit - conn.lossState.totalBytesSent;

  // round the result up to the nearest multiple of udpSendPacketLen.
  return (writableBytes + conn.udpSendPacketLen - 1) / conn.udpSendPacketLen *
      conn.udpSendPacketLen;
}

quic::Expected<WriteQuicDataResult, QuicError> writeQuicDataToSocketImpl(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    bool exceptCryptoStream,
    TimePoint writeLoopBeginTime) {
  auto builder = ShortHeaderBuilder(connection.oneRttWritePhase);
  WriteQuicDataResult result;
  auto& packetsWritten = result.packetsWritten;
  auto& probesWritten = result.probesWritten;
  auto& bytesWritten = result.bytesWritten;
  auto& numProbePackets =
      connection.pendingEvents.numProbePackets[PacketNumberSpace::AppData];
  if (numProbePackets) {
    auto probeSchedulerBuilder =
        FrameScheduler::Builder(
            connection,
            EncryptionLevel::AppData,
            PacketNumberSpace::AppData,
            exceptCryptoStream ? "ProbeWithoutCrypto" : "ProbeScheduler")
            .blockedFrames()
            .windowUpdateFrames()
            .simpleFrames()
            .resetFrames()
            .streamFrames()
            .pingFrames()
            .immediateAckFrames();
    if (!exceptCryptoStream) {
      probeSchedulerBuilder.cryptoFrames();
    }
    auto probeScheduler = std::move(probeSchedulerBuilder).build();
    auto probeResult = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        EncryptionLevel::AppData,
        PacketNumberSpace::AppData,
        probeScheduler,
        numProbePackets, // This possibly bypasses the packetLimit.
        aead,
        headerCipher,
        version);
    if (!probeResult.has_value()) {
      return quic::make_unexpected(probeResult.error());
    }
    probesWritten = probeResult->probesWritten;
    bytesWritten += probeResult->bytesWritten;
    // We only get one chance to write out the probes.
    numProbePackets = 0;
    packetLimit =
        probesWritten > packetLimit ? 0 : (packetLimit - probesWritten);
  }
  auto schedulerBuilder =
      FrameScheduler::Builder(
          connection,
          EncryptionLevel::AppData,
          PacketNumberSpace::AppData,
          exceptCryptoStream ? "FrameSchedulerWithoutCrypto" : "FrameScheduler")
          .streamFrames()
          .resetFrames()
          .windowUpdateFrames()
          .blockedFrames()
          .simpleFrames()
          .pingFrames()
          .datagramFrames()
          .immediateAckFrames();
  // Only add ACK frames if we need to send an ACK.
  if (connection.transportSettings.opportunisticAcking ||
      toWriteAppDataAcks(connection)) {
    schedulerBuilder.ackFrames();
  }
  if (!exceptCryptoStream) {
    schedulerBuilder.cryptoFrames();
  }
  FrameScheduler scheduler = std::move(schedulerBuilder).build();
  auto connectionDataResult = writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      std::move(builder),
      PacketNumberSpace::AppData,
      scheduler,
      congestionControlWritableBytes,
      packetLimit,
      aead,
      headerCipher,
      version,
      writeLoopBeginTime);
  if (!connectionDataResult.has_value()) {
    return quic::make_unexpected(connectionDataResult.error());
  }
  packetsWritten += connectionDataResult->packetsWritten;
  bytesWritten += connectionDataResult->bytesWritten;
  VLOG_IF(10, packetsWritten || probesWritten)
      << nodeToString(connection.nodeType) << " written data "
      << (exceptCryptoStream ? "without crypto data " : "")
      << "to socket packets=" << packetsWritten << " probes=" << probesWritten
      << " " << connection;
  return result;
}

void updateErrnoCount(
    QuicConnectionStateBase& connection,
    IOBufQuicBatch& ioBufBatch) {
  int lastErrno = ioBufBatch.getLastRetryableErrno();
  if (lastErrno == EAGAIN || lastErrno == EWOULDBLOCK) {
    connection.eagainOrEwouldblockCount++;
  } else if (lastErrno == ENOBUFS) {
    connection.enobufsCount++;
  }
}

[[nodiscard]] quic::Expected<DataPathResult, QuicError>
continuousMemoryBuildScheduleEncrypt(
    QuicConnectionStateBase& connection,
    PacketHeader header,
    PacketNumberSpace pnSpace,
    PacketNum packetNum,
    uint64_t cipherOverhead,
    QuicPacketScheduler& scheduler,
    uint64_t writableBytes,
    IOBufQuicBatch& ioBufBatch,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  auto prevSize = connection.bufAccessor->length();

  auto rollbackBuf = [&]() {
    connection.bufAccessor->trimEnd(
        connection.bufAccessor->length() - prevSize);
  };

  // It's the scheduler's job to invoke encode header
  InplaceQuicPacketBuilder pktBuilder(
      *connection.bufAccessor,
      connection.udpSendPacketLen,
      std::move(header),
      getAckState(connection, pnSpace).largestAckedByPeer.value_or(0));
  pktBuilder.accountForCipherOverhead(cipherOverhead);
  CHECK(scheduler.hasData());
  auto result =
      scheduler.scheduleFramesForPacket(std::move(pktBuilder), writableBytes);
  if (!result.has_value()) {
    return quic::make_unexpected(result.error());
  }
  CHECK(connection.bufAccessor->ownsBuffer());
  auto& packet = result->packet;
  if (!packet || packet->packet.frames.empty()) {
    rollbackBuf();
    auto flushResult = ioBufBatch.flush();
    if (!flushResult.has_value()) {
      return quic::make_unexpected(flushResult.error());
    }
    updateErrnoCount(connection, ioBufBatch);
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_FRAME;
    }
    return DataPathResult::makeBuildFailure();
  }
  if (packet->body.empty()) {
    // No more space remaining.
    rollbackBuf();
    auto flushResult = ioBufBatch.flush();
    if (!flushResult.has_value()) {
      return quic::make_unexpected(flushResult.error());
    }
    updateErrnoCount(connection, ioBufBatch);
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_BODY;
    }
    return DataPathResult::makeBuildFailure();
  }
  CHECK(!packet->header.isChained());
  auto headerLen = packet->header.length();
  CHECK(
      packet->body.data() > connection.bufAccessor->data() &&
      packet->body.tail() <= connection.bufAccessor->tail());
  CHECK(
      packet->header.data() >= connection.bufAccessor->data() &&
      packet->header.tail() < connection.bufAccessor->tail());
  // Trim off everything before the current packet, and the header length, so
  // buf's data starts from the body part of buf.
  connection.bufAccessor->trimStart(prevSize + headerLen);
  // buf and packetBuf is actually the same.
  auto buf = connection.bufAccessor->obtain();
  auto encryptResult =
      aead.inplaceEncrypt(std::move(buf), &packet->header, packetNum);
  if (!encryptResult.has_value()) {
    return quic::make_unexpected(encryptResult.error());
  }
  auto packetBuf = std::move(encryptResult.value());
  CHECK(packetBuf->headroom() == headerLen + prevSize);
  // Include header back.
  packetBuf->prepend(headerLen);

  HeaderForm headerForm = packet->packet.header.getHeaderForm();
  auto headerEncryptResult = encryptPacketHeader(
      headerForm,
      packetBuf->writableData(),
      headerLen,
      packetBuf->data() + headerLen,
      packetBuf->length() - headerLen,
      headerCipher);
  if (!headerEncryptResult.has_value()) {
    return quic::make_unexpected(headerEncryptResult.error());
  }
  if (!headerEncryptResult.has_value()) {
    return quic::make_unexpected(headerEncryptResult.error());
  }
  CHECK(!packetBuf->isChained());
  auto encodedSize = packetBuf->length();
  auto encodedBodySize = encodedSize - headerLen;
  // Include previous packets back.
  packetBuf->prepend(prevSize);
  if (connection.transportSettings.isPriming && packetBuf) {
    packetBuf->coalesce();
    connection.bufAccessor->release(BufHelpers::create(packetBuf->capacity()));
    connection.primingData.emplace_back(std::move(packetBuf));
    return DataPathResult::makeWriteResult(
        true, std::move(result.value()), encodedSize, encodedBodySize);
  }
  connection.bufAccessor->release(std::move(packetBuf));
  if (encodedSize > connection.udpSendPacketLen) {
    VLOG(3) << "Quic sending pkt larger than limit, encodedSize="
            << encodedSize;
  }
  // TODO: I think we should add an API that doesn't need a buffer.
  auto writeResult =
      ioBufBatch.write(nullptr /* no need to pass buf */, encodedSize);
  if (!writeResult.has_value()) {
    return quic::make_unexpected(writeResult.error());
  }
  updateErrnoCount(connection, ioBufBatch);
  return DataPathResult::makeWriteResult(
      writeResult.value(),
      std::move(result.value()),
      encodedSize,
      encodedBodySize);
}

[[nodiscard]] quic::Expected<DataPathResult, QuicError>
iobufChainBasedBuildScheduleEncrypt(
    QuicConnectionStateBase& connection,
    PacketHeader header,
    PacketNumberSpace pnSpace,
    PacketNum packetNum,
    uint64_t cipherOverhead,
    QuicPacketScheduler& scheduler,
    uint64_t writableBytes,
    IOBufQuicBatch& ioBufBatch,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  RegularQuicPacketBuilder pktBuilder(
      connection.udpSendPacketLen,
      std::move(header),
      getAckState(connection, pnSpace).largestAckedByPeer.value_or(0));
  // It's the scheduler's job to invoke encode header
  pktBuilder.accountForCipherOverhead(cipherOverhead);
  auto result =
      scheduler.scheduleFramesForPacket(std::move(pktBuilder), writableBytes);
  if (!result.has_value()) {
    return quic::make_unexpected(result.error());
  }
  auto& packet = result->packet;
  if (!packet || packet->packet.frames.empty()) {
    auto flushResult = ioBufBatch.flush();
    if (!flushResult.has_value()) {
      return quic::make_unexpected(flushResult.error());
    }
    updateErrnoCount(connection, ioBufBatch);
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_FRAME;
    }
    return DataPathResult::makeBuildFailure();
  }
  if (packet->body.empty()) {
    // No more space remaining.
    auto flushResult = ioBufBatch.flush();
    if (!flushResult.has_value()) {
      return quic::make_unexpected(flushResult.error());
    }
    updateErrnoCount(connection, ioBufBatch);
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_BODY;
    }
    return DataPathResult::makeBuildFailure();
  }
  packet->header.coalesce();
  auto headerLen = packet->header.length();
  auto bodyLen = packet->body.computeChainDataLength();
  auto unencrypted = BufHelpers::createCombined(
      headerLen + bodyLen + aead.getCipherOverhead());
  auto bodyCursor = Cursor(&packet->body);
  bodyCursor.pull(unencrypted->writableData() + headerLen, bodyLen);
  unencrypted->advance(headerLen);
  unencrypted->append(bodyLen);
  auto encryptResult =
      aead.inplaceEncrypt(std::move(unencrypted), &packet->header, packetNum);
  if (!encryptResult.has_value()) {
    return quic::make_unexpected(encryptResult.error());
  }
  auto packetBuf = std::move(encryptResult.value());
  DCHECK(packetBuf->headroom() == headerLen);
  packetBuf->clear();
  auto headerCursor = Cursor(&packet->header);
  headerCursor.pull(packetBuf->writableData(), headerLen);
  packetBuf->append(headerLen + bodyLen + aead.getCipherOverhead());

  HeaderForm headerForm = packet->packet.header.getHeaderForm();
  auto headerEncryptResult = encryptPacketHeader(
      headerForm,
      packetBuf->writableData(),
      headerLen,
      packetBuf->data() + headerLen,
      packetBuf->length() - headerLen,
      headerCipher);
  if (!headerEncryptResult.has_value()) {
    return quic::make_unexpected(headerEncryptResult.error());
  }
  auto encodedSize = packetBuf->computeChainDataLength();
  auto encodedBodySize = encodedSize - headerLen;
  if (encodedSize > connection.udpSendPacketLen) {
    VLOG(3) << "Quic sending pkt larger than limit, encodedSize=" << encodedSize
            << " encodedBodySize=" << encodedBodySize;
  }
  if (connection.transportSettings.isPriming && packetBuf) {
    packetBuf->coalesce();
    connection.primingData.emplace_back(std::move(packetBuf));
    return DataPathResult::makeWriteResult(
        true, std::move(result.value()), encodedSize, encodedBodySize);
  }
  auto writeResult = ioBufBatch.write(std::move(packetBuf), encodedSize);
  if (!writeResult.has_value()) {
    return quic::make_unexpected(writeResult.error());
  }
  updateErrnoCount(connection, ioBufBatch);
  return DataPathResult::makeWriteResult(
      writeResult.value(),
      std::move(result.value()),
      encodedSize,
      encodedBodySize);
}

} // namespace

namespace quic {

void handleNewStreamBufMetaWritten(
    QuicStreamState& stream,
    uint64_t frameLen,
    bool frameFin);

void handleRetransmissionBufMetaWritten(
    QuicStreamState& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    const decltype(stream.lossBufMetas)::iterator lossBufMetaIter);

bool writeLoopTimeLimit(
    TimePoint loopBeginTime,
    const QuicConnectionStateBase& connection) {
  return connection.lossState.srtt == 0us ||
      connection.transportSettings.writeLimitRttFraction == 0 ||
      Clock::now() - loopBeginTime < connection.lossState.srtt /
          connection.transportSettings.writeLimitRttFraction;
}

void handleNewStreamDataWritten(
    QuicStreamLike& stream,
    uint64_t frameLen,
    bool frameFin) {
  auto originalOffset = stream.currentWriteOffset;
  // Idealy we should also check this data doesn't exist in either retx buffer
  // or loss buffer, but that's an expensive search.
  stream.currentWriteOffset += frameLen;
  ChainedByteRangeHead bufWritten(
      stream.pendingWrites.splitAtMost(static_cast<size_t>(frameLen)));
  DCHECK_EQ(bufWritten.chainLength(), frameLen);
  // TODO: If we want to be able to write FIN out of order for DSR-ed streams,
  // this needs to be fixed:
  stream.currentWriteOffset += frameFin ? 1 : 0;
  CHECK(stream.retransmissionBuffer
            .emplace(
                std::piecewise_construct,
                std::forward_as_tuple(originalOffset),
                std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
                    std::move(bufWritten), originalOffset, frameFin)))
            .second);
}

void handleNewStreamBufMetaWritten(
    QuicStreamState& stream,
    uint64_t frameLen,
    bool frameFin) {
  CHECK_GT(stream.writeBufMeta.offset, 0);
  auto originalOffset = stream.writeBufMeta.offset;
  auto bufMetaSplit = stream.writeBufMeta.split(frameLen);
  CHECK_EQ(bufMetaSplit.offset, originalOffset);
  if (frameFin) {
    // If FIN is written, nothing should be left in the writeBufMeta.
    CHECK_EQ(0, stream.writeBufMeta.length);
    ++stream.writeBufMeta.offset;
    CHECK_GT(stream.writeBufMeta.offset, *stream.finalWriteOffset);
  }
  CHECK(stream.retransmissionBufMetas
            .emplace(
                std::piecewise_construct,
                std::forward_as_tuple(originalOffset),
                std::forward_as_tuple(bufMetaSplit))
            .second);
}

void handleRetransmissionWritten(
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    CircularDeque<WriteStreamBuffer>::iterator lossBufferIter) {
  auto bufferLen = lossBufferIter->data.chainLength();
  if (frameLen == bufferLen && frameFin == lossBufferIter->eof) {
    // The buffer is entirely retransmitted
    ChainedByteRangeHead bufWritten(std::move(lossBufferIter->data));
    stream.lossBuffer.erase(lossBufferIter);
    CHECK(stream.retransmissionBuffer
              .emplace(
                  std::piecewise_construct,
                  std::forward_as_tuple(frameOffset),
                  std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
                      std::move(bufWritten), frameOffset, frameFin)))
              .second);
  } else {
    lossBufferIter->offset += frameLen;
    ChainedByteRangeHead bufWritten(lossBufferIter->data.splitAtMost(frameLen));
    CHECK(stream.retransmissionBuffer
              .emplace(
                  std::piecewise_construct,
                  std::forward_as_tuple(frameOffset),
                  std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
                      std::move(bufWritten), frameOffset, frameFin)))
              .second);
  }
}

void handleRetransmissionBufMetaWritten(
    QuicStreamState& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    const decltype(stream.lossBufMetas)::iterator lossBufMetaIter) {
  if (frameLen == lossBufMetaIter->length && frameFin == lossBufMetaIter->eof) {
    stream.lossBufMetas.erase(lossBufMetaIter);
  } else {
    CHECK_GT(lossBufMetaIter->length, frameLen);
    lossBufMetaIter->length -= frameLen;
    lossBufMetaIter->offset += frameLen;
  }
  CHECK(stream.retransmissionBufMetas
            .emplace(
                std::piecewise_construct,
                std::forward_as_tuple(frameOffset),
                std::forward_as_tuple(WriteBufferMeta::Builder()
                                          .setOffset(frameOffset)
                                          .setLength(frameLen)
                                          .setEOF(frameFin)
                                          .build()))
            .second);
}

/**
 * Update the connection and stream state after stream data is written and deal
 * with new data, as well as retranmissions. Returns true if the data sent is
 * new data.
 */
quic::Expected<bool, QuicError> handleStreamWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace) {
  auto writtenNewData = false;
  // Handle new data first
  if (frameOffset == stream.currentWriteOffset) {
    handleNewStreamDataWritten(stream, frameLen, frameFin);
    writtenNewData = true;
  } else if (frameOffset > stream.currentWriteOffset) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        fmt::format(
            "Byte offset of first byte in written stream frame ({}) is "
            "greater than stream's current write offset ({})",
            frameOffset,
            stream.currentWriteOffset)));
  }

  if (writtenNewData) {
    // Count packet. It's based on the assumption that schedluing scheme will
    // only writes one STREAM frame for a stream in a packet. If that doesn't
    // hold, we need to avoid double-counting.
    ++stream.numPacketsTxWithNewData;
    VLOG(10) << nodeToString(conn.nodeType) << " sent"
             << " packetNum=" << packetNum << " space=" << packetNumberSpace
             << " " << conn;
    return true;
  }

  bool writtenRetx = false;
  // If the data is in the loss buffer, it is a retransmission.
  auto lossBufferIter = std::lower_bound(
      stream.lossBuffer.begin(),
      stream.lossBuffer.end(),
      frameOffset,
      [](const auto& buf, auto off) { return buf.offset < off; });
  if (lossBufferIter != stream.lossBuffer.end() &&
      lossBufferIter->offset == frameOffset) {
    handleRetransmissionWritten(
        stream, frameOffset, frameLen, frameFin, lossBufferIter);
    writtenRetx = true;
  }

  if (writtenRetx) {
    conn.lossState.totalBytesRetransmitted += frameLen;
    VLOG(10) << nodeToString(conn.nodeType) << " sent retransmission"
             << " packetNum=" << packetNum << " " << conn;
    QUIC_STATS(conn.statsCallback, onPacketRetransmission);
    return false;
  }

  // Otherwise it must be a clone write.
  conn.lossState.totalStreamBytesCloned += frameLen;
  return false;
}

bool handleStreamBufMetaWritten(
    QuicConnectionStateBase& conn,
    QuicStreamState& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace) {
  auto writtenNewData = false;
  // Handle new data first
  if (stream.writeBufMeta.offset > 0 &&
      frameOffset == stream.writeBufMeta.offset) {
    handleNewStreamBufMetaWritten(stream, frameLen, frameFin);
    writtenNewData = true;
  }

  if (writtenNewData) {
    // Count packet. It's based on the assumption that schedluing scheme will
    // only writes one STREAM frame for a stream in a packet. If that doesn't
    // hold, we need to avoid double-counting.
    ++stream.numPacketsTxWithNewData;
    VLOG(10) << nodeToString(conn.nodeType) << " sent"
             << " packetNum=" << packetNum << " space=" << packetNumberSpace
             << " " << conn;
    return true;
  }

  auto lossBufMetaIter = std::lower_bound(
      stream.lossBufMetas.begin(),
      stream.lossBufMetas.end(),
      frameOffset,
      [](const auto& bufMeta, auto offset) { return bufMeta.offset < offset; });
  // We do not clone BufMeta right now. So the data has to be in lossBufMetas.
  CHECK(lossBufMetaIter != stream.lossBufMetas.end());
  CHECK_EQ(lossBufMetaIter->offset, frameOffset);
  handleRetransmissionBufMetaWritten(
      stream, frameOffset, frameLen, frameFin, lossBufMetaIter);
  conn.lossState.totalBytesRetransmitted += frameLen;
  VLOG(10) << nodeToString(conn.nodeType) << " sent retransmission"
           << " packetNum=" << packetNum << " " << conn;
  QUIC_STATS(conn.statsCallback, onPacketRetransmission);
  return false;
}

quic::Expected<void, QuicError> updateConnection(
    QuicConnectionStateBase& conn,
    Optional<ClonedPacketIdentifier> clonedPacketIdentifier,
    RegularQuicWritePacket packet,
    TimePoint sentTime,
    uint32_t encodedSize,
    uint32_t encodedBodySize,
    bool isDSRPacket) {
  auto packetNum = packet.header.getPacketSequenceNum();
  // AckFrame, PaddingFrame and Datagrams are not retx-able.
  bool retransmittable = false;
  bool isPing = false;
  uint32_t connWindowUpdateSent = 0;
  uint32_t ackFrameCounter = 0;
  uint32_t streamBytesSent = 0;
  uint32_t newStreamBytesSent = 0;
  OutstandingPacketWrapper::Metadata::DetailsPerStream detailsPerStream;
  auto packetNumberSpace = packet.header.getPacketNumberSpace();
  VLOG(10) << nodeToString(conn.nodeType) << " sent packetNum=" << packetNum
           << " in space=" << packetNumberSpace << " size=" << encodedSize
           << " bodySize: " << encodedBodySize << " isDSR=" << isDSRPacket
           << " " << conn;
  if (conn.qLogger) {
    conn.qLogger->addPacket(packet, encodedSize);
  }
  FOLLY_SDT(quic, update_connection_num_frames, packet.frames.size());
  for (const auto& frame : packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteStreamFrame: {
        const WriteStreamFrame& writeStreamFrame = *frame.asWriteStreamFrame();
        retransmittable = true;
        auto streamResult =
            conn.streamManager->getStream(writeStreamFrame.streamId);
        if (!streamResult) {
          return quic::make_unexpected(streamResult.error());
        }
        auto stream = streamResult.value();
        bool newStreamDataWritten = false;
        if (writeStreamFrame.fromBufMeta) {
          newStreamDataWritten = handleStreamBufMetaWritten(
              conn,
              *stream,
              writeStreamFrame.offset,
              writeStreamFrame.len,
              writeStreamFrame.fin,
              packetNum,
              packetNumberSpace);
        } else {
          auto streamWrittenResult = handleStreamWritten(
              conn,
              *stream,
              writeStreamFrame.offset,
              writeStreamFrame.len,
              writeStreamFrame.fin,
              packetNum,
              packetNumberSpace);
          if (!streamWrittenResult.has_value()) {
            return quic::make_unexpected(streamWrittenResult.error());
          }
          newStreamDataWritten = streamWrittenResult.value();
        }
        if (newStreamDataWritten) {
          auto flowControlResult =
              updateFlowControlOnWriteToSocket(*stream, writeStreamFrame.len);
          if (!flowControlResult.has_value()) {
            return quic::make_unexpected(flowControlResult.error());
          }
          maybeWriteBlockAfterSocketWrite(*stream);
          maybeWriteDataBlockedAfterSocketWrite(conn);
          conn.streamManager->addTx(writeStreamFrame.streamId);
          newStreamBytesSent += writeStreamFrame.len;
        }
        // This call could take an argument whether the packet scheduler already
        // removed stream from writeQueue
        conn.streamManager->updateWritableStreams(
            *stream, getSendConnFlowControlBytesWire(conn) > 0);
        streamBytesSent += writeStreamFrame.len;
        detailsPerStream.addFrame(writeStreamFrame, newStreamDataWritten);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
        const WriteCryptoFrame& writeCryptoFrame = *frame.asWriteCryptoFrame();
        retransmittable = true;
        auto protectionType = packet.header.getProtectionType();
        // NewSessionTicket is sent in crypto frame encrypted with 1-rtt key,
        // however, it is not part of handshake
        auto encryptionLevel = protectionTypeToEncryptionLevel(protectionType);
        auto cryptoWritten = handleStreamWritten(
            conn,
            *getCryptoStream(*conn.cryptoState, encryptionLevel),
            writeCryptoFrame.offset,
            writeCryptoFrame.len,
            false /* fin */,
            packetNum,
            packetNumberSpace);
        if (!cryptoWritten.has_value()) {
          return quic::make_unexpected(cryptoWritten.error());
        }
        break;
      }
      case QuicWriteFrame::Type::WriteAckFrame: {
        const WriteAckFrame& writeAckFrame = *frame.asWriteAckFrame();
        DCHECK(!ackFrameCounter++)
            << "Send more than one WriteAckFrame " << conn;
        auto largestAckedPacketWritten = writeAckFrame.ackBlocks.front().end;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent packet with largestAcked="
                 << largestAckedPacketWritten << " packetNum=" << packetNum
                 << " " << conn;
        ++conn.numAckFramesSent;
        updateAckSendStateOnSentPacketWithAcks(
            conn,
            getAckState(conn, packetNumberSpace),
            largestAckedPacketWritten);
        break;
      }
      case QuicWriteFrame::Type::RstStreamFrame: {
        const RstStreamFrame& rstStreamFrame = *frame.asRstStreamFrame();
        retransmittable = true;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent reset streams in packetNum=" << packetNum << " "
                 << conn;
        auto resetIter =
            conn.pendingEvents.resets.find(rstStreamFrame.streamId);
        // TODO: this can happen because we clone RST_STREAM frames. Should we
        // start to treat RST_STREAM in the same way we treat window update?
        if (resetIter != conn.pendingEvents.resets.end()) {
          conn.pendingEvents.resets.erase(resetIter);
        } else {
          DCHECK(clonedPacketIdentifier.has_value())
              << " reset missing from pendingEvents for non-clone packet";
        }
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        const MaxDataFrame& maxDataFrame = *frame.asMaxDataFrame();
        CHECK(!connWindowUpdateSent++)
            << "Send more than one connection window update " << conn;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent conn window update packetNum=" << packetNum << " "
                 << conn;
        retransmittable = true;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent conn window update in packetNum=" << packetNum << " "
                 << conn;
        ++conn.numWindowUpdateFramesSent;
        onConnWindowUpdateSent(conn, maxDataFrame.maximumData, sentTime);
        break;
      }
      case QuicWriteFrame::Type::DataBlockedFrame: {
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent conn data blocked frame=" << packetNum << " "
                 << conn;
        retransmittable = true;
        conn.pendingEvents.sendDataBlocked = false;
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        auto streamResult =
            conn.streamManager->getStream(maxStreamDataFrame.streamId);
        if (!streamResult.has_value()) {
          return quic::make_unexpected(streamResult.error());
        }
        auto stream = streamResult.value();
        retransmittable = true;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent packet with window update packetNum=" << packetNum
                 << " stream=" << maxStreamDataFrame.streamId << " " << conn;
        ++conn.numWindowUpdateFramesSent;
        onStreamWindowUpdateSent(
            *stream, maxStreamDataFrame.maximumData, sentTime);
        break;
      }
      case QuicWriteFrame::Type::StreamDataBlockedFrame: {
        const StreamDataBlockedFrame& streamBlockedFrame =
            *frame.asStreamDataBlockedFrame();
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent blocked stream frame packetNum=" << packetNum << " "
                 << conn;
        retransmittable = true;
        conn.streamManager->removeBlocked(streamBlockedFrame.streamId);
        break;
      }
      case QuicWriteFrame::Type::PingFrame:
        conn.pendingEvents.sendPing = false;
        isPing = true;
        retransmittable = true;
        conn.numPingFramesSent++;
        break;
      case QuicWriteFrame::Type::QuicSimpleFrame: {
        const QuicSimpleFrame& simpleFrame = *frame.asQuicSimpleFrame();
        retransmittable = true;
        // We don't want this triggered for cloned frames.
        if (!clonedPacketIdentifier.has_value()) {
          updateSimpleFrameOnPacketSent(conn, simpleFrame);
        }
        break;
      }
      case QuicWriteFrame::Type::PaddingFrame: {
        // do not mark padding as retransmittable. There are several reasons
        // for this:
        // 1. We might need to pad ACK packets to make it so that we can
        //    sample them correctly for header encryption. ACK packets may not
        //    count towards congestion window, so the padding frames in those
        //    ack packets should not count towards the window either
        // 2. Of course we do not want to retransmit the ACK frames.
        break;
      }
      case QuicWriteFrame::Type::DatagramFrame: {
        // do not mark Datagram frames as retransmittable
        break;
      }
      case QuicWriteFrame::Type::ImmediateAckFrame: {
        // turn off the immediate ack pending event.
        conn.pendingEvents.requestImmediateAck = false;
        retransmittable = true;
        break;
      }
      default:
        retransmittable = true;
    }
  }

  // This increments the next packet number and (potentially) the next non-DSR
  // packet sequence number. Capture the non DSR sequence number before
  // increment.
  auto& ackState = getAckState(conn, packetNumberSpace);
  auto nonDsrPacketSequenceNumber = ackState.nonDsrPacketSequenceNumber;
  increaseNextPacketNum(conn, packetNumberSpace, isDSRPacket);
  if (!ackState.skippedPacketNum.has_value() &&
      folly::Random::oneIn(
          conn.transportSettings.skipOneInNPacketSequenceNumber)) {
    ackState.skippedPacketNum = ackState.nextPacketNum;
    increaseNextPacketNum(conn, packetNumberSpace, isDSRPacket);
  }
  conn.lossState.largestSent =
      std::max(conn.lossState.largestSent.value_or(packetNum), packetNum);
  // updateConnection may be called multiple times during write. If before or
  // during any updateConnection, setLossDetectionAlarm is already set, we
  // shouldn't clear it:
  if (!conn.pendingEvents.setLossDetectionAlarm) {
    conn.pendingEvents.setLossDetectionAlarm = retransmittable;
  }
  conn.lossState.maybeLastPacketSentTime = sentTime;
  conn.lossState.totalBytesSent += encodedSize;
  conn.lossState.totalBodyBytesSent += encodedBodySize;
  conn.lossState.totalPacketsSent++;
  conn.lossState.totalStreamBytesSent += streamBytesSent;
  conn.lossState.totalNewStreamBytesSent += newStreamBytesSent;

  // Count the number of packets sent in the current phase.
  // This is used to initiate key updates if enabled.
  if (packet.header.getProtectionType() == conn.oneRttWritePhase) {
    if (conn.oneRttWritePendingVerification &&
        conn.oneRttWritePacketsSentInCurrentPhase == 0) {
      // This is the first packet in the new phase after we have initiated a key
      // update. We need to keep track of it to confirm the peer acks it in the
      // same phase.
      conn.oneRttWritePendingVerificationPacketNumber =
          packet.header.getPacketSequenceNum();
    }
    conn.oneRttWritePacketsSentInCurrentPhase++;
  }

  if (!retransmittable && !isPing) {
    DCHECK(!clonedPacketIdentifier);
    return {};
  }
  conn.lossState.totalAckElicitingPacketsSent++;

  auto packetIt =
      std::find_if(
          conn.outstandings.packets.rbegin(),
          conn.outstandings.packets.rend(),
          [packetNum](const auto& packetWithTime) {
            return packetWithTime.packet.header.getPacketSequenceNum() <
                packetNum;
          })
          .base();

  std::function<void(const quic::OutstandingPacketWrapper&)> packetDestroyFn =
      [&conn](const quic::OutstandingPacketWrapper& pkt) {
        for (auto& packetProcessor : conn.packetProcessors) {
          packetProcessor->onPacketDestroyed(pkt);
        }
      };

  auto& pkt = *conn.outstandings.packets.emplace(
      packetIt,
      std::move(packet),
      sentTime,
      encodedSize,
      encodedBodySize,
      // these numbers should all _include_ the current packet
      // conn.lossState.inflightBytes isn't updated until below
      // conn.outstandings.numOutstanding() + 1 since we're emplacing here
      conn.lossState.totalBytesSent,
      conn.lossState.inflightBytes + encodedSize,
      conn.lossState,
      conn.writeCount,
      std::move(detailsPerStream),
      conn.appLimitedTracker.getTotalAppLimitedTime(),
      std::move(packetDestroyFn));

  maybeAddPacketMark(conn, pkt);

  pkt.isAppLimited = conn.congestionController
      ? conn.congestionController->isAppLimited()
      : false;
  if (conn.lossState.lastAckedTime.has_value() &&
      conn.lossState.lastAckedPacketSentTime.has_value()) {
    pkt.lastAckedPacketInfo.emplace(
        *conn.lossState.lastAckedPacketSentTime,
        *conn.lossState.lastAckedTime,
        *conn.lossState.adjustedLastAckedTime,
        conn.lossState.totalBytesSentAtLastAck,
        conn.lossState.totalBytesAckedAtLastAck);
  }
  if (clonedPacketIdentifier) {
    DCHECK(conn.outstandings.clonedPacketIdentifiers.count(
        *clonedPacketIdentifier));
    pkt.maybeClonedPacketIdentifier = std::move(clonedPacketIdentifier);
    conn.lossState.totalBytesCloned += encodedSize;
  }
  pkt.isDSRPacket = isDSRPacket;
  if (isDSRPacket) {
    ++conn.outstandings.dsrCount;
    QUIC_STATS(conn.statsCallback, onDSRPacketSent, encodedSize);
  } else {
    // If it's not a DSR packet, set the sequence number to the previous one,
    // as the state currently is the _next_ one after this packet.
    pkt.nonDsrPacketSequenceNumber = nonDsrPacketSequenceNumber;
  }

  if (conn.congestionController) {
    conn.congestionController->onPacketSent(pkt);
  }
  if (conn.pacer) {
    conn.pacer->onPacketSent();
  }
  for (auto& packetProcessor : conn.packetProcessors) {
    packetProcessor->onPacketSent(pkt);
  }

  if (conn.pathValidationLimiter &&
      (conn.pendingEvents.pathChallenge || conn.outstandingPathValidation)) {
    conn.pathValidationLimiter->onPacketSent(pkt.metadata.encodedSize);
  }
  conn.lossState.lastRetransmittablePacketSentTime = pkt.metadata.time;
  if (pkt.maybeClonedPacketIdentifier) {
    ++conn.outstandings.clonedPacketCount[packetNumberSpace];
    ++conn.lossState.timeoutBasedRtxCount;
  } else {
    ++conn.outstandings.packetCount[packetNumberSpace];
  }
  return {};
}

uint64_t probePacketWritableBytes(QuicConnectionStateBase& conn) {
  uint64_t probeWritableBytes = maybeUnvalidatedClientWritableBytes(conn);
  if (!probeWritableBytes) {
    conn.numProbesWritableBytesLimited++;
  }
  return probeWritableBytes;
}

uint64_t congestionControlWritableBytes(QuicConnectionStateBase& conn) {
  uint64_t writableBytes = std::numeric_limits<uint64_t>::max();

  if (conn.pendingEvents.pathChallenge || conn.outstandingPathValidation) {
    CHECK(conn.pathValidationLimiter);
    // 0-RTT and path validation  rate limiting should be mutually exclusive.
    CHECK(!conn.writableBytesLimit);

    // Use the default RTT measurement when starting a new path challenge (CC is
    // reset). This shouldn't be an RTT sample, so we do not update the CC with
    // this value.
    writableBytes = conn.pathValidationLimiter->currentCredit(
        std::chrono::steady_clock::now(),
        conn.lossState.srtt == 0us ? kDefaultInitialRtt : conn.lossState.srtt);
  } else if (conn.writableBytesLimit) {
    writableBytes = maybeUnvalidatedClientWritableBytes(conn);
  }

  if (conn.congestionController) {
    writableBytes = std::min<uint64_t>(
        writableBytes, conn.congestionController->getWritableBytes());

    if (conn.throttlingSignalProvider &&
        conn.throttlingSignalProvider->getCurrentThrottlingSignal()
            .has_value()) {
      const auto& throttlingSignal =
          conn.throttlingSignalProvider->getCurrentThrottlingSignal();
      if (throttlingSignal.value().maybeBytesToSend.has_value()) {
        // Cap the writable bytes by the amount of tokens available in the
        // throttler's bucket if one found to be throttling the connection.
        writableBytes = std::min(
            throttlingSignal.value().maybeBytesToSend.value(), writableBytes);
      }
    }
  }

  if (writableBytes == std::numeric_limits<uint64_t>::max()) {
    return writableBytes;
  }

  // For real-CC/PathChallenge cases, round the result up to the nearest
  // multiple of udpSendPacketLen.
  return (writableBytes + conn.udpSendPacketLen - 1) / conn.udpSendPacketLen *
      conn.udpSendPacketLen;
}

uint64_t unlimitedWritableBytes(QuicConnectionStateBase&) {
  return std::numeric_limits<uint64_t>::max();
}

HeaderBuilder LongHeaderBuilder(LongHeader::Types packetType) {
  return [packetType](
             const ConnectionId& srcConnId,
             const ConnectionId& dstConnId,
             PacketNum packetNum,
             QuicVersion version,
             const std::string& token) {
    return LongHeader(
        packetType, srcConnId, dstConnId, packetNum, version, token);
  };
}

HeaderBuilder ShortHeaderBuilder(ProtectionType keyPhase) {
  return [keyPhase](
             const ConnectionId& /* srcConnId */,
             const ConnectionId& dstConnId,
             PacketNum packetNum,
             QuicVersion,
             const std::string&) {
    return ShortHeader(keyPhase, dstConnId, packetNum);
  };
}

quic::Expected<WriteQuicDataResult, QuicError> writeCryptoAndAckDataToSocket(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types packetType,
    Aead& cleartextCipher,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    const std::string& token) {
  auto encryptionLevel = protectionTypeToEncryptionLevel(
      longHeaderTypeToProtectionType(packetType));
  FrameScheduler scheduler =
      std::move(FrameScheduler::Builder(
                    connection,
                    encryptionLevel,
                    LongHeader::typeToPacketNumberSpace(packetType),
                    "CryptoAndAcksScheduler")
                    .ackFrames()
                    .cryptoFrames())
          .build();
  auto builder = LongHeaderBuilder(packetType);
  WriteQuicDataResult result;
  auto& packetsWritten = result.packetsWritten;
  auto& bytesWritten = result.bytesWritten;
  auto& probesWritten = result.probesWritten;
  auto& cryptoStream =
      *getCryptoStream(*connection.cryptoState, encryptionLevel);
  auto& numProbePackets =
      connection.pendingEvents
          .numProbePackets[LongHeader::typeToPacketNumberSpace(packetType)];
  if (numProbePackets &&
      (cryptoStream.retransmissionBuffer.size() || scheduler.hasData())) {
    auto probeResult = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        encryptionLevel,
        LongHeader::typeToPacketNumberSpace(packetType),
        scheduler,
        numProbePackets, // This possibly bypasses the packetLimit.
        cleartextCipher,
        headerCipher,
        version,
        token);
    if (!probeResult.has_value()) {
      return quic::make_unexpected(probeResult.error());
    }
    probesWritten += probeResult->probesWritten;
    bytesWritten += probeResult->bytesWritten;
  }
  packetLimit = probesWritten > packetLimit ? 0 : (packetLimit - probesWritten);
  // Only get one chance to write probes.
  numProbePackets = 0;
  // Crypto data is written without aead protection.
  auto writeResult = writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      builder,
      LongHeader::typeToPacketNumberSpace(packetType),
      scheduler,
      congestionControlWritableBytes,
      packetLimit - packetsWritten,
      cleartextCipher,
      headerCipher,
      version,
      Clock::now(),
      token);

  if (!writeResult.has_value()) {
    return quic::make_unexpected(writeResult.error());
  }

  packetsWritten += writeResult->packetsWritten;
  bytesWritten += writeResult->bytesWritten;

  if (connection.transportSettings.immediatelyRetransmitInitialPackets &&
      packetsWritten > 0 && packetsWritten < packetLimit) {
    auto remainingLimit = packetLimit - packetsWritten;
    auto cloneResult = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        encryptionLevel,
        LongHeader::typeToPacketNumberSpace(packetType),
        scheduler,
        packetsWritten < remainingLimit ? packetsWritten : remainingLimit,
        cleartextCipher,
        headerCipher,
        version,
        token);
    if (!cloneResult.has_value()) {
      return quic::make_unexpected(cloneResult.error());
    }
    probesWritten += cloneResult->probesWritten;
    bytesWritten += cloneResult->bytesWritten;
  }

  VLOG_IF(10, packetsWritten || probesWritten)
      << nodeToString(connection.nodeType)
      << " written crypto and acks data type=" << packetType
      << " packetsWritten=" << packetsWritten
      << " probesWritten=" << probesWritten << connection;
  CHECK_GE(packetLimit, packetsWritten);
  return result;
}

quic::Expected<WriteQuicDataResult, QuicError> writeQuicDataToSocket(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    TimePoint writeLoopBeginTime) {
  return writeQuicDataToSocketImpl(
      sock,
      connection,
      srcConnId,
      dstConnId,
      aead,
      headerCipher,
      version,
      packetLimit,
      /*exceptCryptoStream=*/false,
      writeLoopBeginTime);
}

quic::Expected<WriteQuicDataResult, QuicError>
writeQuicDataExceptCryptoStreamToSocket(
    QuicAsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit) {
  return writeQuicDataToSocketImpl(
      socket,
      connection,
      srcConnId,
      dstConnId,
      aead,
      headerCipher,
      version,
      packetLimit,
      /*exceptCryptoStream=*/true,
      Clock::now());
}

quic::Expected<uint64_t, QuicError> writeZeroRttDataToSocket(
    QuicAsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit) {
  auto type = LongHeader::Types::ZeroRtt;
  auto encryptionLevel =
      protectionTypeToEncryptionLevel(longHeaderTypeToProtectionType(type));
  auto builder = LongHeaderBuilder(type);
  // Probe is not useful for zero rtt because we will always have handshake
  // packets outstanding when sending zero rtt data.
  FrameScheduler scheduler =
      std::move(FrameScheduler::Builder(
                    connection,
                    encryptionLevel,
                    LongHeader::typeToPacketNumberSpace(type),
                    "ZeroRttScheduler")
                    .streamFrames()
                    .resetFrames()
                    .windowUpdateFrames()
                    .blockedFrames()
                    .simpleFrames())
          .build();
  auto writeResult = writeConnectionDataToSocket(
      socket,
      connection,
      srcConnId,
      dstConnId,
      std::move(builder),
      LongHeader::typeToPacketNumberSpace(type),
      scheduler,
      congestionControlWritableBytes,
      packetLimit,
      aead,
      headerCipher,
      version,
      Clock::now());

  if (!writeResult.has_value()) {
    return quic::make_unexpected(writeResult.error());
  }

  auto written = writeResult->packetsWritten;
  VLOG_IF(10, written > 0) << nodeToString(connection.nodeType)
                           << " written zero rtt data, packets=" << written
                           << " " << connection;
  DCHECK_GE(packetLimit, written);
  return written;
}

void writeCloseCommon(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    PacketHeader&& header,
    Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  // close is special, we're going to bypass all the packet sent logic for all
  // packets we send with a connection close frame.
  PacketNumberSpace pnSpace = header.getPacketNumberSpace();
  HeaderForm headerForm = header.getHeaderForm();
  PacketNum packetNum = header.getPacketSequenceNum();

  // Create a buffer onto which we write the connection close.
  BufAccessor bufAccessor(connection.udpSendPacketLen);
  InplaceQuicPacketBuilder packetBuilder(
      bufAccessor,
      connection.udpSendPacketLen,
      header,
      getAckState(connection, pnSpace).largestAckedByPeer.value_or(0));
  auto encodeResult = packetBuilder.encodePacketHeader();
  if (!encodeResult.has_value()) {
    LOG(ERROR) << "Error encoding packet header: "
               << encodeResult.error().message;
    return;
  }
  packetBuilder.accountForCipherOverhead(aead.getCipherOverhead());
  size_t written = 0;
  if (!closeDetails) {
    auto writeResult = writeFrame(
        ConnectionCloseFrame(
            QuicErrorCode(TransportErrorCode::NO_ERROR),
            std::string("No error")),
        packetBuilder);
    if (!writeResult.has_value()) {
      LOG(ERROR) << "Error writing frame: " << writeResult.error().message;
      return;
    }
    written = *writeResult;
  } else {
    switch (closeDetails->code.type()) {
      case QuicErrorCode::Type::ApplicationErrorCode: {
        auto writeResult = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(*closeDetails->code.asApplicationErrorCode()),
                closeDetails->message,
                quic::FrameType::CONNECTION_CLOSE_APP_ERR),
            packetBuilder);
        if (!writeResult.has_value()) {
          LOG(ERROR) << "Error writing frame: " << writeResult.error().message;
          return;
        }
        written = *writeResult;
        break;
      }
      case QuicErrorCode::Type::TransportErrorCode: {
        auto writeResult = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(*closeDetails->code.asTransportErrorCode()),
                closeDetails->message,
                quic::FrameType::CONNECTION_CLOSE),
            packetBuilder);
        if (!writeResult.has_value()) {
          LOG(ERROR) << "Error writing frame: " << writeResult.error().message;
          return;
        }
        written = *writeResult;
        break;
      }
      case QuicErrorCode::Type::LocalErrorCode: {
        auto writeResult = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
                std::string("Internal error"),
                quic::FrameType::CONNECTION_CLOSE),
            packetBuilder);
        if (!writeResult.has_value()) {
          LOG(ERROR) << "Error writing frame: " << writeResult.error().message;
          return;
        }
        written = *writeResult;
        break;
      }
    }
  }
  if (pnSpace == PacketNumberSpace::Initial &&
      connection.nodeType == QuicNodeType::Client) {
    while (packetBuilder.remainingSpaceInPkt() > 0) {
      auto paddingResult = writeFrame(PaddingFrame(), packetBuilder);
      if (!paddingResult.has_value()) {
        LOG(ERROR) << "Error writing padding frame: "
                   << paddingResult.error().message;
        return;
      }
    }
  }
  if (written == 0) {
    LOG(ERROR) << "Close frame too large " << connection;
    return;
  }
  auto packet = std::move(packetBuilder).buildPacket();
  CHECK_GE(packet.body.tailroom(), aead.getCipherOverhead());
  auto bufUniquePtr = packet.body.clone();
  auto encryptResult =
      aead.inplaceEncrypt(std::move(bufUniquePtr), &packet.header, packetNum);
  if (!encryptResult.has_value()) {
    LOG(ERROR) << "Error encrypting packet: " << encryptResult.error().message;
    return;
  }
  bufUniquePtr = std::move(encryptResult.value());
  bufUniquePtr->coalesce();
  auto headerEncryptResult = encryptPacketHeader(
      headerForm,
      packet.header.writableData(),
      packet.header.length(),
      bufUniquePtr->data(),
      bufUniquePtr->length(),
      headerCipher);
  if (!headerEncryptResult.has_value()) {
    LOG(ERROR) << "Failed to encrypt packet header: "
               << headerEncryptResult.error().message;
    return;
  }
  Buf packetBuf(std::move(packet.header));
  packetBuf.appendToChain(std::move(bufUniquePtr));
  auto packetSize = packetBuf.computeChainDataLength();
  if (connection.qLogger) {
    connection.qLogger->addPacket(packet.packet, packetSize);
  }
  VLOG(10) << nodeToString(connection.nodeType)
           << " sent close packetNum=" << packetNum << " in space=" << pnSpace
           << " " << connection;
  // Increment the sequence number.
  increaseNextPacketNum(connection, pnSpace);
  // best effort writing to the socket, ignore any errors.

  BufPtr packetBufPtr = packetBuf.clone();
  iovec vec[kNumIovecBufferChains];
  size_t iovec_len = fillIovec(packetBufPtr, vec);
  auto ret = sock.write(connection.peerAddress, vec, iovec_len);
  connection.lossState.totalBytesSent += packetSize;
  if (ret < 0) {
    VLOG(4) << "Error writing connection close " << folly::errnoStr(errno)
            << " " << connection;
  } else {
    QUIC_STATS(connection.statsCallback, onWrite, ret);
  }
}

void writeLongClose(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types headerType,
    Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version) {
  if (!connection.serverConnectionId) {
    // It's possible that servers encountered an error before binding to a
    // connection id.
    return;
  }
  LongHeader header(
      headerType,
      srcConnId,
      dstConnId,
      getNextPacketNum(
          connection, LongHeader::typeToPacketNumberSpace(headerType)),
      version);
  writeCloseCommon(
      sock,
      connection,
      std::move(header),
      std::move(closeDetails),
      aead,
      headerCipher);
}

void writeShortClose(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& connId,
    Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  auto header = ShortHeader(
      connection.oneRttWritePhase,
      connId,
      getNextPacketNum(connection, PacketNumberSpace::AppData));
  writeCloseCommon(
      sock,
      connection,
      std::move(header),
      std::move(closeDetails),
      aead,
      headerCipher);
}

quic::Expected<void, QuicError> encryptPacketHeader(
    HeaderForm headerForm,
    uint8_t* header,
    size_t headerLen,
    const uint8_t* encryptedBody,
    size_t bodyLen,
    const PacketNumberCipher& headerCipher) {
  // Header encryption.
  auto packetNumberLength = parsePacketNumberLength(*header);
  Sample sample;
  size_t sampleBytesToUse = kMaxPacketNumEncodingSize - packetNumberLength;
  // If there were less than 4 bytes in the packet number, some of the payload
  // bytes will also be skipped during sampling.
  CHECK_GE(bodyLen, sampleBytesToUse + sample.size());
  encryptedBody += sampleBytesToUse;
  memcpy(sample.data(), encryptedBody, sample.size());

  MutableByteRange initialByteRange(header, 1);
  MutableByteRange packetNumByteRange(
      header + headerLen - packetNumberLength, packetNumberLength);
  if (headerForm == HeaderForm::Short) {
    auto result = headerCipher.encryptShortHeader(
        sample, initialByteRange, packetNumByteRange);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  } else {
    auto result = headerCipher.encryptLongHeader(
        sample, initialByteRange, packetNumByteRange);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  }
  return {};
}

/**
 * Writes packets to the socket. The is the function that is called by all
 * the other write*ToSocket() functions.
 *
 * The number of packets written is limited by:
 *   - the maximum batch size supported by the underlying writer
 *     (`maxBatchSize`)
 *   - the `packetLimit` input parameter
 *   - the value returned by the `writableBytesFunc` which usually is either the
 *     congestion control writable bytes or unlimited writable bytes (if the
 *     output of the given scheduler should not be subject to congestion
 *     control)
 *   - the maximum time to spend in a write loop as specified by
 *     `transportSettings.writeLimitRttFraction`
 *   - the amount of data available in the provided scheduler.
 *
 * Writing the packets involves:
 *   1. The scheduler which decides the data to write in each packet
 *   2. The IOBufQuicBatch which holds the data output by the scheduler
 *   3. The BatchWriter which writes the data from the IOBufQuicBatch to
 *      the socket
 *
 * The IOBufQuicBatch can hold packets either as a chain of IOBufs or as a
 * single contiguous buffer (continuous vs. chained memory datapaths). This also
 * affects the type of BatchWriter used to read the IOBufQuicBatch and write it
 * to the socket.
 *
 * A rough outline of this function is as follows:
 * 1. Make a BatchWriter for the requested batching mode and datapath type.
 * 2. Make an IOBufQuicBatch to hold the data. This owns the BatchWriter created
 *    above which it will use to write its data to the socket later.
 * 3. Based upon the selected datapathType, the dataplaneFunc is chosen.
 * 4. The dataplaneFunc is responsible for writing the scheduler's data into the
 *    IOBufQuicBatch in the desired format, and calling the IOBufQuicBatch's
 *    write() function which wraps around the BatchWriter it owns.
 * 5. Each dataplaneFunc call writes one packet to the IOBufQuicBatch. It is
 *    called repeatedly until one of the limits described above is hit.
 * 6. After each packet is written, the connection state is updated to reflect a
 *    packet being sent.
 * 7. Once the limit is hit, the IOBufQuicBatch is flushed to give it another
 *    chance to write any remaining data to the socket that hasn't already been
 *    written in the loop.
 *
 * Note that:
 * - This function does not guarantee that the data is written to the underlying
 *   UDP socket buffer.
 * - It only guarantees that packets will be scheduled and written to a
 *   IOBufQuicBatch and that the IOBufQuicBatch will get a chance to write to
 *   the socket.
 * - Step 6 above updates the connection state when the packet is written to the
 *   buffer, but not necessarily when it is written to the socket. This decision
 *   is made by the IOBufQuicBatch and its BatchWriter.
 * - This function attempts to flush the IOBufQuicBatch before returning
 *   to try to ensure that all scheduled data is written into the socket.
 * - If that flush still fails, the packets are considered written to the
 *   network, since currently there is no way to rewind scheduler and connection
 *   state after the packets have been written to a batch.
 */
quic::Expected<WriteQuicDataResult, QuicError> writeConnectionDataToSocket(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    HeaderBuilder builder,
    PacketNumberSpace pnSpace,
    QuicPacketScheduler& scheduler,
    const WritableBytesFunc& writableBytesFunc,
    uint64_t packetLimit,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    TimePoint writeLoopBeginTime,
    const std::string& token) {
  if (connection.loopDetectorCallback) {
    connection.writeDebugState.schedulerName = scheduler.name().str();
    connection.writeDebugState.noWriteReason = NoWriteReason::WRITE_OK;
  }

  // Note: if a write is pending, it will be taken over by the batch writer when
  // it's created. So this check has to be done before creating the batch
  // writer.
  bool pendingBufferedWrite = hasBufferedDataToWrite(connection);

  if (!scheduler.hasData() && !pendingBufferedWrite) {
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::EMPTY_SCHEDULER;
    }
    return WriteQuicDataResult{0, 0, 0};
  }

  VLOG(10) << nodeToString(connection.nodeType)
           << " writing data using scheduler=" << scheduler.name() << " "
           << connection;

  if (!connection.gsoSupported.has_value()) {
    auto gsoResult = sock.getGSO();
    if (!gsoResult.has_value()) {
      LOG(ERROR) << "Failed to get GSO: " << gsoResult.error().message;
      return quic::make_unexpected(gsoResult.error());
    }
    connection.gsoSupported = sock.getGSO().value() >= 0;
  }

  auto batchWriter = BatchWriterFactory::makeBatchWriter(
      connection.transportSettings.batchingMode,
      connection.transportSettings.maxBatchSize,
      connection.transportSettings.enableWriterBackpressure,
      connection.transportSettings.dataPathType,
      connection,
      *connection.gsoSupported);

  auto happyEyeballsState = connection.nodeType == QuicNodeType::Server
      ? nullptr
      : &static_cast<QuicClientConnectionState&>(connection).happyEyeballsState;
  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      sock,
      connection.peerAddress,
      connection.statsCallback,
      happyEyeballsState);

  // If we have a pending write to retry. Flush that first and make sure it
  // succeeds before scheduling any new data.
  if (pendingBufferedWrite) {
    auto flushResult = ioBufBatch.flush();
    if (!flushResult.has_value()) {
      return quic::make_unexpected(flushResult.error());
    }
    auto flushSuccess = flushResult.value();
    updateErrnoCount(connection, ioBufBatch);
    if (!flushSuccess) {
      // Could not flush retried data. Return empty write result and wait for
      // next retry.
      return WriteQuicDataResult{0, 0, 0};
    }
  }

  auto batchSize = connection.transportSettings.batchingMode ==
          QuicBatchingMode::BATCHING_MODE_NONE
      ? connection.transportSettings.writeConnectionDataPacketsLimit
      : connection.transportSettings.maxBatchSize;

  uint64_t bytesWritten = 0;
  uint64_t shortHeaderPadding = 0;
  uint64_t shortHeaderPaddingCount = 0;
  SCOPE_EXIT {
    auto nSent = ioBufBatch.getPktSent();
    if (nSent > 0) {
      QUIC_STATS(connection.statsCallback, onPacketsSent, nSent);
      QUIC_STATS(connection.statsCallback, onWrite, bytesWritten);
      if (shortHeaderPadding > 0) {
        QUIC_STATS(
            connection.statsCallback,
            onShortHeaderPaddingBatch,
            shortHeaderPaddingCount,
            shortHeaderPadding);
      }
    }
  };

  quic::TimePoint sentTime = Clock::now();

  while (scheduler.hasData() && ioBufBatch.getPktSent() < packetLimit &&
         ((ioBufBatch.getPktSent() < batchSize) ||
          writeLoopTimeLimit(writeLoopBeginTime, connection))) {
    auto packetNum = getNextPacketNum(connection, pnSpace);
    auto header = builder(srcConnId, dstConnId, packetNum, version, token);
    uint32_t writableBytes = std::min<uint64_t>(
        connection.udpSendPacketLen, writableBytesFunc(connection));
    uint64_t cipherOverhead = aead.getCipherOverhead();
    if (writableBytes < cipherOverhead) {
      writableBytes = 0;
    } else {
      writableBytes -= cipherOverhead;
    }

    auto writeQueueTransaction =
        connection.streamManager->writeQueue().beginTransaction();
    auto guard = folly::makeGuard([&] {
      connection.streamManager->writeQueue().rollbackTransaction(
          std::move(writeQueueTransaction));
    });
    const auto& dataPlaneFunc =
        connection.transportSettings.dataPathType == DataPathType::ChainedMemory
        ? iobufChainBasedBuildScheduleEncrypt
        : continuousMemoryBuildScheduleEncrypt;
    auto ret = dataPlaneFunc(
        connection,
        std::move(header),
        pnSpace,
        packetNum,
        cipherOverhead,
        scheduler,
        writableBytes,
        ioBufBatch,
        aead,
        headerCipher);

    // This is a fatal error vs. a build error.
    if (!ret.has_value()) {
      return quic::make_unexpected(ret.error());
    }
    if (!ret->buildSuccess) {
      // If we're returning because we couldn't schedule more packets,
      // make sure we flush the buffer in this function.
      auto flushResult = ioBufBatch.flush();
      if (!flushResult.has_value()) {
        return quic::make_unexpected(flushResult.error());
      }
      updateErrnoCount(connection, ioBufBatch);
      return WriteQuicDataResult{ioBufBatch.getPktSent(), 0, bytesWritten};
    }
    // If we build a packet, we updateConnection(), even if write might have
    // been failed. Because if it builds, a lot of states need to be updated no
    // matter the write result. We are basically treating this case as if we
    // pretend write was also successful but packet is lost somewhere in the
    // network.
    bytesWritten += ret->encodedSize;
    if (ret->result && ret->result->shortHeaderPadding > 0) {
      shortHeaderPaddingCount++;
      shortHeaderPadding += ret->result->shortHeaderPadding;
    }

    auto& result = ret->result;
    // This call to updateConnection will attempt to erase streams from the
    // write queue that have already been removed in QuicPacketScheduler.
    // Removing non-existent streams can be O(N), consider passing the
    // transaction set to skip this step
    auto updateConnResult = updateConnection(
        connection,
        std::move(result->clonedPacketIdentifier),
        std::move(result->packet->packet),
        sentTime,
        static_cast<uint32_t>(ret->encodedSize),
        static_cast<uint32_t>(ret->encodedBodySize),
        false /* isDSRPacket */);
    if (!updateConnResult.has_value()) {
      return quic::make_unexpected(updateConnResult.error());
    }
    guard.dismiss();
    connection.streamManager->writeQueue().commitTransaction(
        std::move(writeQueueTransaction));

    // if ioBufBatch.write returns false
    // it is because a flush() call failed
    if (!ret->writeSuccess) {
      if (connection.loopDetectorCallback) {
        connection.writeDebugState.noWriteReason =
            NoWriteReason::SOCKET_FAILURE;
      }
      return WriteQuicDataResult{ioBufBatch.getPktSent(), 0, bytesWritten};
    }

    if ((connection.transportSettings.batchingMode ==
         QuicBatchingMode::BATCHING_MODE_NONE) &&
        useSinglePacketInplaceBatchWriter(
            connection.transportSettings.maxBatchSize,
            connection.transportSettings.dataPathType)) {
      // With SinglePacketInplaceBatchWriter we always write one packet, and so
      // ioBufBatch needs a flush.
      auto flushResult = ioBufBatch.flush();
      if (!flushResult.has_value()) {
        return quic::make_unexpected(flushResult.error());
      }
      updateErrnoCount(connection, ioBufBatch);
    }
  }

  // Ensure that the buffer is flushed before returning
  auto flushResult = ioBufBatch.flush();
  if (!flushResult.has_value()) {
    return quic::make_unexpected(flushResult.error());
  }
  updateErrnoCount(connection, ioBufBatch);

  if (connection.transportSettings.dataPathType ==
      DataPathType::ContinuousMemory) {
    CHECK(connection.bufAccessor->ownsBuffer());
    CHECK(
        connection.bufAccessor->length() == 0 &&
        connection.bufAccessor->headroom() == 0);
  }
  return WriteQuicDataResult{ioBufBatch.getPktSent(), 0, bytesWritten};
}

quic::Expected<WriteQuicDataResult, QuicError> writeProbingDataToSocket(
    QuicAsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const HeaderBuilder& builder,
    EncryptionLevel encryptionLevel,
    PacketNumberSpace pnSpace,
    FrameScheduler scheduler,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    const std::string& token) {
  // Skip a packet number for probing packets to elicit acks
  increaseNextPacketNum(connection, pnSpace);
  CloningScheduler cloningScheduler(
      scheduler, connection, "CloningScheduler", aead.getCipherOverhead());
  auto writeLoopBeginTime = Clock::now();

  // If we have the ability to draw an ACK for AppData, let's send a probe that
  // is just an IMMEDIATE_ACK. Increase the number of probes to do so.
  uint8_t dataProbesToSend = probesToSend;
  if (probesToSend && canSendAckControlFrames(connection) &&
      encryptionLevel == EncryptionLevel::AppData) {
    probesToSend = std::max<uint8_t>(probesToSend, kPacketToSendForPTO);
    dataProbesToSend = probesToSend - 1;
  }
  auto cloningResult = writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      builder,
      pnSpace,
      cloningScheduler,
      connection.transportSettings.enableWritableBytesLimit
          ? probePacketWritableBytes
          : unlimitedWritableBytes,
      dataProbesToSend,
      aead,
      headerCipher,
      version,
      writeLoopBeginTime,
      token);
  if (!cloningResult.has_value()) {
    return quic::make_unexpected(cloningResult.error());
  }
  auto probesWritten = cloningResult->packetsWritten;
  auto bytesWritten = cloningResult->bytesWritten;
  if (probesWritten < probesToSend) {
    // If we can use an IMMEDIATE_ACK, that's better than a PING.
    auto probeSchedulerBuilder = FrameScheduler::Builder(
        connection, encryptionLevel, pnSpace, "ProbeScheduler");
    // Might as well include some ACKs.
    probeSchedulerBuilder.ackFrames();
    if (canSendAckControlFrames(connection) &&
        encryptionLevel == EncryptionLevel::AppData) {
      requestPeerImmediateAck(connection);
      probeSchedulerBuilder.immediateAckFrames();
    } else {
      connection.pendingEvents.sendPing = true;
      probeSchedulerBuilder.pingFrames();
    }
    auto probeScheduler = std::move(probeSchedulerBuilder).build();
    auto probingResult = writeConnectionDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        pnSpace,
        probeScheduler,
        connection.transportSettings.enableWritableBytesLimit
            ? probePacketWritableBytes
            : unlimitedWritableBytes,
        probesToSend - probesWritten,
        aead,
        headerCipher,
        version,
        writeLoopBeginTime);
    if (!probingResult.has_value()) {
      return quic::make_unexpected(probingResult.error());
    }
    probesWritten += probingResult->packetsWritten;
    bytesWritten += probingResult->bytesWritten;
  }
  VLOG_IF(10, probesWritten > 0)
      << nodeToString(connection.nodeType)
      << " writing probes using scheduler=CloningScheduler " << connection;
  return WriteQuicDataResult{0, probesWritten, bytesWritten};
}

WriteDataReason shouldWriteData(/*const*/ QuicConnectionStateBase& conn) {
  auto& numProbePackets = conn.pendingEvents.numProbePackets;
  bool shouldWriteInitialProbes =
      numProbePackets[PacketNumberSpace::Initial] && conn.initialWriteCipher;
  bool shouldWriteHandshakeProbes =
      numProbePackets[PacketNumberSpace::Handshake] &&
      conn.handshakeWriteCipher;
  bool shouldWriteAppDataProbes =
      numProbePackets[PacketNumberSpace::AppData] && conn.oneRttWriteCipher;
  if (shouldWriteInitialProbes || shouldWriteHandshakeProbes ||
      shouldWriteAppDataProbes) {
    VLOG(10) << nodeToString(conn.nodeType) << " needs write because of PTO"
             << conn;
    return WriteDataReason::PROBES;
  }
  if (hasAckDataToWrite(conn)) {
    VLOG(10) << nodeToString(conn.nodeType) << " needs write because of ACKs "
             << conn;
    return WriteDataReason::ACK;
  }

  if (!congestionControlWritableBytes(conn)) {
    QUIC_STATS(conn.statsCallback, onCwndBlocked);
    return WriteDataReason::NO_WRITE;
  }

  if (hasBufferedDataToWrite(conn)) {
    return WriteDataReason::BUFFERED_WRITE;
  }

  return hasNonAckDataToWrite(conn);
}

bool hasAckDataToWrite(const QuicConnectionStateBase& conn) {
  // hasAcksToSchedule tells us whether we have acks.
  // needsToSendAckImmediately tells us when to schedule the acks. If we don't
  // have an immediate need to schedule the acks then we need to wait till we
  // satisfy a condition where there is immediate need, so we shouldn't
  // consider the acks to be writable.
  bool writeAcks =
      (toWriteInitialAcks(conn) || toWriteHandshakeAcks(conn) ||
       toWriteAppDataAcks(conn));
  VLOG_IF(10, writeAcks) << nodeToString(conn.nodeType)
                         << " needs write because of acks largestAck="
                         << largestAckToSendToString(conn) << " largestSentAck="
                         << largestAckScheduledToString(conn)
                         << " ackTimeoutSet="
                         << conn.pendingEvents.scheduleAckTimeout << " "
                         << conn;
  return writeAcks;
}

bool hasBufferedDataToWrite(const QuicConnectionStateBase& conn) {
  return (bool)conn.pendingWriteBatch_.buf;
}

WriteDataReason hasNonAckDataToWrite(const QuicConnectionStateBase& conn) {
  if (cryptoHasWritableData(conn)) {
    VLOG(10) << nodeToString(conn.nodeType)
             << " needs write because of crypto stream" << " " << conn;
    return WriteDataReason::CRYPTO_STREAM;
  }
  if (!conn.oneRttWriteCipher &&
      !(conn.nodeType == QuicNodeType::Client &&
        static_cast<const QuicClientConnectionState&>(conn)
            .zeroRttWriteCipher)) {
    // All the rest of the types of data need either a 1-rtt or 0-rtt cipher to
    // be written.
    return WriteDataReason::NO_WRITE;
  }
  if (!conn.pendingEvents.resets.empty()) {
    return WriteDataReason::RESET;
  }
  if (conn.streamManager->hasWindowUpdates()) {
    return WriteDataReason::STREAM_WINDOW_UPDATE;
  }
  if (conn.pendingEvents.connWindowUpdate) {
    return WriteDataReason::CONN_WINDOW_UPDATE;
  }
  if (conn.streamManager->hasBlocked()) {
    return WriteDataReason::BLOCKED;
  }
  // If we have lost data or flow control + stream data.
  if (conn.streamManager->hasLoss() ||
      (getSendConnFlowControlBytesWire(conn) != 0 &&
       conn.streamManager->hasWritable())) {
    return WriteDataReason::STREAM;
  }
  if (!conn.pendingEvents.frames.empty()) {
    return WriteDataReason::SIMPLE;
  }
  if ((conn.pendingEvents.pathChallenge.has_value())) {
    return WriteDataReason::PATHCHALLENGE;
  }
  if (conn.pendingEvents.sendPing) {
    return WriteDataReason::PING;
  }
  if (!conn.datagramState.writeBuffer.empty()) {
    return WriteDataReason::DATAGRAM;
  }
  return WriteDataReason::NO_WRITE;
}

void maybeSendStreamLimitUpdates(QuicConnectionStateBase& conn) {
  auto update = conn.streamManager->remoteBidirectionalStreamLimitUpdate();
  if (update) {
    sendSimpleFrame(conn, (MaxStreamsFrame(*update, true)));
  }
  update = conn.streamManager->remoteUnidirectionalStreamLimitUpdate();
  if (update) {
    sendSimpleFrame(conn, (MaxStreamsFrame(*update, false)));
  }
}

void implicitAckCryptoStream(
    QuicConnectionStateBase& conn,
    EncryptionLevel encryptionLevel) {
  auto implicitAckTime = Clock::now();
  auto packetNumSpace = encryptionLevel == EncryptionLevel::Handshake
      ? PacketNumberSpace::Handshake
      : PacketNumberSpace::Initial;
  auto& ackState = getAckState(conn, packetNumSpace);
  AckBlocks ackBlocks;
  ReadAckFrame implicitAck;
  implicitAck.ackDelay = 0ms;
  implicitAck.implicit = true;
  for (const auto& op : conn.outstandings.packets) {
    if (op.packet.header.getPacketNumberSpace() == packetNumSpace) {
      ackBlocks.insert(op.packet.header.getPacketSequenceNum());
    }
  }
  if (ackBlocks.empty()) {
    return;
  }
  // Construct an implicit ack covering the entire range of packets.
  // If some of these have already been ACK'd then processAckFrame
  // should simply ignore them.
  implicitAck.largestAcked = ackBlocks.back().end;
  if (ackState.skippedPacketNum &&
      *ackState.skippedPacketNum > ackBlocks.front().start &&
      *ackState.skippedPacketNum < implicitAck.largestAcked) {
    implicitAck.ackBlocks.emplace_back(
        *ackState.skippedPacketNum + 1, implicitAck.largestAcked);
    implicitAck.ackBlocks.emplace_back(
        ackBlocks.front().start, *ackState.skippedPacketNum - 1);
  } else {
    implicitAck.ackBlocks.emplace_back(
        ackBlocks.front().start, implicitAck.largestAcked);
  }
  auto result = processAckFrame(
      conn,
      packetNumSpace,
      implicitAck,
      [](const auto&) -> quic::Expected<void, QuicError> {
        // ackedPacketVisitor. No action needed.
        return {};
      },
      [&](auto&, auto& packetFrame) -> quic::Expected<void, QuicError> {
        switch (packetFrame.type()) {
          case QuicWriteFrame::Type::WriteCryptoFrame: {
            const WriteCryptoFrame& frame = *packetFrame.asWriteCryptoFrame();
            auto cryptoStream =
                getCryptoStream(*conn.cryptoState, encryptionLevel);
            processCryptoStreamAck(*cryptoStream, frame.offset, frame.len);
            break;
          }
          case QuicWriteFrame::Type::WriteAckFrame: {
            const WriteAckFrame& frame = *packetFrame.asWriteAckFrame();
            commonAckVisitorForAckFrame(ackState, frame);
            break;
          }
          default: {
            // We don't bother checking for valid packets, since these are
            // our outstanding packets.
          }
        }
        return {};
      },
      // We shouldn't mark anything as lost from the implicit ACK, as it should
      // be ACKing the entire rangee.
      [](auto&, auto&, auto) -> quic::Expected<void, QuicError> {
        LOG(FATAL) << "Got loss from implicit crypto ACK.";
        return {};
      },
      implicitAckTime);
  // TODO handle error
  CHECK(result.has_value()) << result.error().message;
  // Clear our the loss buffer explicitly. The implicit ACK itself will not
  // remove data already in the loss buffer.
  auto cryptoStream = getCryptoStream(*conn.cryptoState, encryptionLevel);
  cryptoStream->lossBuffer.clear();
  CHECK(cryptoStream->retransmissionBuffer.empty());
  // The write buffer should be empty, there's no optional crypto data.
  CHECK(cryptoStream->pendingWrites.empty());
}

void handshakeConfirmed(QuicConnectionStateBase& conn) {
  // If we've supposedly confirmed the handshake and don't have the 1RTT
  // ciphers installed, we are going to have problems.
  CHECK(conn.oneRttWriteCipher);
  CHECK(conn.oneRttWriteHeaderCipher);
  CHECK(conn.readCodec->getOneRttReadCipher());
  CHECK(conn.readCodec->getOneRttHeaderCipher());
  conn.readCodec->onHandshakeDone(Clock::now());
  conn.initialWriteCipher.reset();
  conn.initialHeaderCipher.reset();
  conn.readCodec->setInitialReadCipher(nullptr);
  conn.readCodec->setInitialHeaderCipher(nullptr);
  implicitAckCryptoStream(conn, EncryptionLevel::Initial);
  conn.ackStates.initialAckState.reset();
  conn.handshakeWriteCipher.reset();
  conn.handshakeWriteHeaderCipher.reset();
  conn.readCodec->setHandshakeReadCipher(nullptr);
  conn.readCodec->setHandshakeHeaderCipher(nullptr);
  implicitAckCryptoStream(conn, EncryptionLevel::Handshake);
  conn.ackStates.handshakeAckState.reset();
}

bool hasInitialOrHandshakeCiphers(QuicConnectionStateBase& conn) {
  return conn.initialWriteCipher || conn.handshakeWriteCipher ||
      conn.readCodec->getInitialCipher() ||
      conn.readCodec->getHandshakeReadCipher();
}

bool toWriteInitialAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.initialWriteCipher && conn.ackStates.initialAckState &&
      hasAcksToSchedule(*conn.ackStates.initialAckState) &&
      conn.ackStates.initialAckState->needsToSendAckImmediately);
}

bool toWriteHandshakeAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.handshakeWriteCipher && conn.ackStates.handshakeAckState &&
      hasAcksToSchedule(*conn.ackStates.handshakeAckState) &&
      conn.ackStates.handshakeAckState->needsToSendAckImmediately);
}

bool toWriteAppDataAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.oneRttWriteCipher &&
      hasAcksToSchedule(conn.ackStates.appDataAckState) &&
      conn.ackStates.appDataAckState.needsToSendAckImmediately);
}

void updateOneRttWriteCipher(
    quic::QuicConnectionStateBase& conn,
    std::unique_ptr<Aead> aead,
    ProtectionType oneRttPhase) {
  CHECK(
      oneRttPhase == ProtectionType::KeyPhaseZero ||
      oneRttPhase == ProtectionType::KeyPhaseOne);
  CHECK(oneRttPhase != conn.oneRttWritePhase)
      << "Cannot replace cipher for current write phase";
  conn.oneRttWriteCipher = std::move(aead);
  conn.oneRttWritePhase = oneRttPhase;
  conn.oneRttWritePacketsSentInCurrentPhase = 0;
}

quic::Expected<void, QuicError> maybeHandleIncomingKeyUpdate(
    QuicConnectionStateBase& conn) {
  if (conn.readCodec->getCurrentOneRttReadPhase() != conn.oneRttWritePhase) {
    // Peer has initiated a key update.
    auto nextOneRttWriteCipherResult =
        conn.handshakeLayer->getNextOneRttWriteCipher();
    if (!nextOneRttWriteCipherResult.has_value()) {
      return quic::make_unexpected(nextOneRttWriteCipherResult.error());
    }
    updateOneRttWriteCipher(
        conn,
        std::move(nextOneRttWriteCipherResult.value()),
        conn.readCodec->getCurrentOneRttReadPhase());

    auto nextOneRttReadCipherResult =
        conn.handshakeLayer->getNextOneRttReadCipher();
    if (!nextOneRttReadCipherResult.has_value()) {
      return quic::make_unexpected(nextOneRttReadCipherResult.error());
    }
    conn.readCodec->setNextOneRttReadCipher(
        std::move(nextOneRttReadCipherResult.value()));

    // The peer has initiated a key update. We should use the regular key
    // update interval if we are initiating key updates.
    conn.transportSettings.firstKeyUpdatePacketCount.reset();
  }
  return {};
}

quic::Expected<void, QuicError> maybeInitiateKeyUpdate(
    QuicConnectionStateBase& conn) {
  if (conn.transportSettings.initiateKeyUpdate) {
    if (conn.nodeType == QuicNodeType::Server && conn.version.has_value() &&
        conn.version.value() == QuicVersion::MVFST &&
        conn.transportSettings.firstKeyUpdatePacketCount.has_value()) {
      // Some old versions of MVFST did not support key updates.
      // So as the server, do not attempt to initiate key updates if the client
      // hasn't initiated one yet.
      return {};
    }
    auto packetsBeforeNextUpdate =
        conn.transportSettings.firstKeyUpdatePacketCount
        ? conn.transportSettings.firstKeyUpdatePacketCount.value()
        : conn.transportSettings.keyUpdatePacketCountInterval;

    if ((conn.oneRttWritePacketsSentInCurrentPhase > packetsBeforeNextUpdate) &&
        conn.readCodec->canInitiateKeyUpdate()) {
      QUIC_STATS(conn.statsCallback, onKeyUpdateAttemptInitiated);
      conn.readCodec->advanceOneRttReadPhase();

      //  We have initiated a key update. We should use the regular key
      // update from now on.
      conn.transportSettings.firstKeyUpdatePacketCount.reset();

      auto nextOneRttWriteCipherResult =
          conn.handshakeLayer->getNextOneRttWriteCipher();
      if (!nextOneRttWriteCipherResult.has_value()) {
        return quic::make_unexpected(nextOneRttWriteCipherResult.error());
      }
      updateOneRttWriteCipher(
          conn,
          std::move(nextOneRttWriteCipherResult.value()),
          conn.readCodec->getCurrentOneRttReadPhase());

      auto nextOneRttReadCipherResult =
          conn.handshakeLayer->getNextOneRttReadCipher();
      if (!nextOneRttReadCipherResult.has_value()) {
        return quic::make_unexpected(nextOneRttReadCipherResult.error());
      }
      conn.readCodec->setNextOneRttReadCipher(
          std::move(nextOneRttReadCipherResult.value()));
      // Signal the transport that a key update has been initiated.
      conn.oneRttWritePendingVerification = true;
      conn.oneRttWritePendingVerificationPacketNumber.reset();
    }
  }
  return {};
}

quic::Expected<void, QuicError> maybeVerifyPendingKeyUpdate(
    QuicConnectionStateBase& conn,
    const OutstandingPacketWrapper& outstandingPacket,
    const RegularQuicPacket& ackPacket) {
  if (!(protectionTypeToEncryptionLevel(
            outstandingPacket.packet.header.getProtectionType()) ==
        EncryptionLevel::AppData)) {
    // This is not an app data packet. We can't have initiated a key update yet.
    return {};
  }

  if (conn.oneRttWritePendingVerificationPacketNumber &&
      outstandingPacket.packet.header.getPacketSequenceNum() >=
          conn.oneRttWritePendingVerificationPacketNumber.value()) {
    // There is a pending key update. This packet should be acked in
    // the current phase.
    if (ackPacket.header.getProtectionType() == conn.oneRttWritePhase) {
      // Key update is verified.
      conn.oneRttWritePendingVerificationPacketNumber.reset();
      conn.oneRttWritePendingVerification = false;
    } else {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::CRYPTO_ERROR,
          "Packet with key update was acked in the wrong phase"));
    }
  }
  return {};
}

// Unfortunate, we should make this more portable.
#if !defined IPV6_HOPLIMIT
#define IPV6_HOPLIMIT -1
#endif
#if !defined IP_TTL
#define IP_TTL -1
#endif
// Add a packet mark to the outstanding packet. Currently only supports
// TTLD marking.
void maybeAddPacketMark(
    QuicConnectionStateBase& conn,
    OutstandingPacketWrapper& op) {
  static constexpr folly::SocketOptionKey kHopLimitOptionKey = {
      IPPROTO_IPV6, IPV6_HOPLIMIT};
  static constexpr folly::SocketOptionKey kTTLOptionKey = {IPPROTO_IP, IP_TTL};
  if (!conn.socketCmsgsState.additionalCmsgs.has_value()) {
    return;
  }
  const auto& cmsgs = conn.socketCmsgsState.additionalCmsgs;
  auto it = cmsgs->find(kHopLimitOptionKey);
  if (it != cmsgs->end() && it->second == 255) {
    op.metadata.mark = OutstandingPacketMark::TTLD;
    return;
  }
  it = cmsgs->find(kTTLOptionKey);
  if (it != cmsgs->end() && it->second == 255) {
    op.metadata.mark = OutstandingPacketMark::TTLD;
  }
}

void maybeScheduleAckForCongestionFeedback(
    const ReceivedUdpPacket& receivedPacket,
    AckState& ackState) {
  // If the packet was marked as having encountered congestion, send an ACK
  // immediately to ensure timely response from the peer.
  // Note that the tosValue will be populated only if the enableEcnOnEgress
  // transport setting is enabled.
  if ((receivedPacket.tosValue & 0b11) == 0b11) {
    ackState.needsToSendAckImmediately = true;
  }
}

void updateNegotiatedAckFeatures(QuicConnectionStateBase& conn) {
  bool isAckReceiveTimestampsSupported =
      conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer &&
      conn.maybePeerAckReceiveTimestampsConfig;

  uint64_t peerRequestedTimestampsCount =
      conn.maybePeerAckReceiveTimestampsConfig.has_value()
      ? conn.maybePeerAckReceiveTimestampsConfig.value()
            .maxReceiveTimestampsPerAck
      : 0;

  conn.negotiatedAckReceiveTimestampSupport =
      isAckReceiveTimestampsSupported && (peerRequestedTimestampsCount > 0);

  conn.negotiatedExtendedAckFeatures = conn.peerAdvertisedExtendedAckFeatures &
      conn.transportSettings.enableExtendedAckFeatures;
  // Disable the ECN fields if we are not reading them
  if (!conn.transportSettings.readEcnOnIngress) {
    conn.negotiatedExtendedAckFeatures &=
        ~static_cast<ExtendedAckFeatureMaskType>(
            ExtendedAckFeatureMask::ECN_COUNTS);
  }
  // Disable the receive timestamps fields if we have not regoatiated receive
  // timestamps support
  if (!conn.negotiatedAckReceiveTimestampSupport) {
    conn.negotiatedExtendedAckFeatures &=
        ~static_cast<ExtendedAckFeatureMaskType>(
            ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS);
  }
}

} // namespace quic

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicPacketRebuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/StateData.h>
#include <quic/state/stream/StreamSendHandlers.h>

using namespace testing;

namespace quic::test {

OutstandingPacketWrapper makeDummyOutstandingPacket(
    const RegularQuicWritePacket& writePacket,
    uint64_t totalBytesSentOnConnection) {
  OutstandingPacketWrapper packet(
      writePacket,
      Clock::now(),
      1000,
      0,
      totalBytesSentOnConnection,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  return packet;
}

class QuicPacketRebuilderTest : public Test {};

TEST_F(QuicPacketRebuilderTest, RebuildEmpty) {
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen,
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(), 0),
      0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  QuicConnectionStateBase conn(QuicNodeType::Client);
  PacketRebuilder rebuilder(regularBuilder, conn);
  auto packet = std::move(regularBuilder).buildPacket();
  EXPECT_TRUE(packet.packet.frames.empty());
  EXPECT_FALSE(packet.header.empty());
  EXPECT_TRUE(packet.body.empty());
}

TEST_F(QuicPacketRebuilderTest, RebuildSmallInitial) {
  auto srcConnId = getTestConnectionId(0);
  auto dstConnId = getTestConnectionId(1);
  QuicVersion version = QuicVersion::MVFST;
  PacketNum num = 1;
  LongHeader initialHeader1(
      LongHeader::Types::Initial, srcConnId, dstConnId, num, version, "");
  LongHeader initialHeader2(
      LongHeader::Types::Initial, srcConnId, dstConnId, num + 1, version, "");

  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(initialHeader1), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(initialHeader2), 0);

  PingFrame pingFrame{};
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder1).hasError());
  MaxStreamsFrame maxStreamsFrame(4321, true);
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(maxStreamsFrame), regularBuilder1).hasError());
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  QuicConnectionStateBase conn(QuicNodeType::Client);
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto packet = std::move(regularBuilder1).buildPacket();
  auto outstanding = makeDummyOutstandingPacket(packet.packet, 1000);
  EXPECT_FALSE(packet.header.empty());
  ASSERT_EQ(packet.packet.frames.size(), 2);
  EXPECT_FALSE(packet.body.empty());
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto rebuilt = std::move(regularBuilder2).buildPacket();
  EXPECT_FALSE(rebuilt.header.empty());
  ASSERT_EQ(rebuilt.packet.frames.size(), 3);
  auto padding = rebuilt.packet.frames.back().asPaddingFrame();
  ASSERT_TRUE(padding != nullptr);
  EXPECT_GT(padding->numFrames, 1000);
  EXPECT_FALSE(rebuilt.body.empty());
  EXPECT_GT(rebuilt.body.computeChainDataLength(), 1200);
}

TEST_F(QuicPacketRebuilderTest, RebuildPacket) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  // Get a bunch frames
  ConnectionCloseFrame connCloseFrame(
      QuicErrorCode(TransportErrorCode::FRAME_ENCODING_ERROR),
      "The sun is in the sky.",
      FrameType::ACK);
  MaxStreamsFrame maxStreamsFrame(4321, true);
  AckBlocks ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  WriteAckFrameState writeAckState = {.acks = ackBlocks};
  //   WriteAckFrameMetaData ackMeta(ackBlocks, 0us, kDefaultAckDelayExponent);
  WriteAckFrameMetaData ackMeta = {
      .ackState = writeAckState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent)};
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  MaxDataFrame maxDataFrame(1000);
  MaxStreamDataFrame maxStreamDataFrame(streamId, 2000);
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  PingFrame pingFrame{};
  // Write them with a regular builder
  // Write the ACK frame first since it has special rebuilder handling.
  ASSERT_FALSE(writeAckFrame(ackMeta, regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(connCloseFrame, regularBuilder1).hasError());
  ASSERT_FALSE(
      writeFrame(QuicSimpleFrame(maxStreamsFrame), regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder1).hasError());
  (void)writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  ASSERT_FALSE(writeFrame(maxDataFrame, regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(maxStreamDataFrame, regularBuilder1).hasError());
  ASSERT_FALSE(
      writeCryptoFrame(
          cryptoOffset, ChainedByteRangeHead(cryptoBuf), regularBuilder1)
          .hasError());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(8, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(buf), 0, true)));
  conn.cryptoState->oneRttStream.retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(cryptoBuf), 0, true)));
  // Write an updated ackState that should be used when rebuilding the AckFrame
  conn.ackStates.appDataAckState.acks.insert(1000, 1200);
  conn.ackStates.appDataAckState.largestRecvdPacketTime = quic::Clock::now();

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  // rebuilder writes frames to regularBuilder2
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size());
  auto expectedConnFlowControlValue = std::max(
      conn.flowControlState.sumCurReadOffset + conn.flowControlState.windowSize,
      conn.flowControlState.advertisedMaxOffset);
  auto expectedStreamFlowControlValue = std::max(
      stream->currentReadOffset + stream->flowControlState.windowSize,
      stream->flowControlState.advertisedMaxOffset);
  for (const auto& frame : packet2.packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::ConnectionCloseFrame: {
        const ConnectionCloseFrame& closeFrame =
            *frame.asConnectionCloseFrame();
        const TransportErrorCode* transportErrorCode =
            closeFrame.errorCode.asTransportErrorCode();
        EXPECT_EQ(
            TransportErrorCode::FRAME_ENCODING_ERROR, *transportErrorCode);
        EXPECT_EQ("The sun is in the sky.", closeFrame.reasonPhrase);
        EXPECT_EQ(FrameType::ACK, closeFrame.closingFrameType);
        break;
      }
      case QuicWriteFrame::Type::PingFrame:
        EXPECT_NE(frame.asPingFrame(), nullptr);
        break;
      case QuicWriteFrame::Type::QuicSimpleFrame: {
        const QuicSimpleFrame& simpleFrame = *frame.asQuicSimpleFrame();
        switch (simpleFrame.type()) {
          case QuicSimpleFrame::Type::MaxStreamsFrame: {
            const MaxStreamsFrame* maxStreamFrame =
                simpleFrame.asMaxStreamsFrame();
            EXPECT_NE(maxStreamFrame, nullptr);
            EXPECT_EQ(4321, maxStreamFrame->maxStreams);
            break;
          }
          default:
            EXPECT_TRUE(false); /* fail if this happens */
        }
        break;
      }
      case QuicWriteFrame::Type::WriteAckFrame: {
        const WriteAckFrame& ack = *frame.asWriteAckFrame();
        EXPECT_EQ(1, ack.ackBlocks.size());
        EXPECT_EQ(Interval<PacketNum>(1000, 1200), ack.ackBlocks.back());
        break;
      }
      case QuicWriteFrame::Type::WriteStreamFrame: {
        const WriteStreamFrame& streamFrame = *frame.asWriteStreamFrame();
        EXPECT_EQ(streamId, streamFrame.streamId);
        EXPECT_EQ(0, streamFrame.offset);
        EXPECT_EQ(buf->computeChainDataLength(), streamFrame.len);
        EXPECT_EQ(true, streamFrame.fin);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
        const WriteCryptoFrame& cryptoFrame = *frame.asWriteCryptoFrame();
        EXPECT_EQ(cryptoFrame.offset, cryptoOffset);
        EXPECT_EQ(cryptoFrame.len, cryptoBuf->computeChainDataLength());
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        const MaxDataFrame& maxData = *frame.asMaxDataFrame();
        EXPECT_EQ(expectedConnFlowControlValue, maxData.maximumData);
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamData = *frame.asMaxStreamDataFrame();
        EXPECT_EQ(streamId, maxStreamData.streamId);
        EXPECT_EQ(expectedStreamFlowControlValue, maxStreamData.maximumData);
        break;
      }
      default:
        EXPECT_TRUE(false); /* should never happen*/
    }
  }
  EXPECT_TRUE(folly::IOBufEqualTo()(packet1.header, packet2.header));
  // TODO: I don't have a good way to verify body without decode them
}

TEST_F(QuicPacketRebuilderTest, RebuildAfterResetStream) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf = folly::IOBuf::copyBuffer("A million miles away.");
  (void)writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(1, packet1.packet.frames.size());

  // Then we reset the stream
  ASSERT_FALSE(sendRstSMHandler(*stream, GenericApplicationErrorCode::UNKNOWN)
                   .hasError());
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
}

TEST_F(QuicPacketRebuilderTest, FinOnlyStreamRebuild) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;

  // Write them with a regular builder
  (void)writeStreamFrameHeader(
      regularBuilder1, streamId, 0, 0, 0, true, std::nullopt /* skipLenHint */);
  auto packet1 = std::move(regularBuilder1).buildPacket();
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(), 0, true)));

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 2000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size());
  EXPECT_TRUE(
      0 ==
      memcmp(
          packet1.packet.frames.data(),
          packet2.packet.frames.data(),
          packet1.packet.frames.size()));
  EXPECT_TRUE(folly::IOBufEqualTo()(packet1.header, packet2.header));
  // Once we start to use the correct ack delay value in AckFrames, this needs
  // to be changed:
  EXPECT_TRUE(folly::IOBufEqualTo()(packet1.body, packet2.body));
}

TEST_F(QuicPacketRebuilderTest, RebuildDataStreamAndEmptyCryptoStream) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  // Get a bunch frames
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  StreamId streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  // Write them with a regular builder
  (void)writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  ASSERT_FALSE(
      writeCryptoFrame(
          cryptoOffset, ChainedByteRangeHead(cryptoBuf), regularBuilder1)
          .hasError());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(2, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(buf), 0, true)));
  // Do not add the buf to crypto stream's retransmission buffer,
  // imagine it was cleared

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  auto packet2 = std::move(regularBuilder2).buildPacket();
  // rebuilder writes frames to regularBuilder2
  EXPECT_EQ(packet1.packet.frames.size(), packet2.packet.frames.size() + 1);
  for (const auto& frame : packet2.packet.frames) {
    const WriteStreamFrame* streamFrame = frame.asWriteStreamFrame();
    if (!streamFrame) {
      EXPECT_TRUE(false); /* should never happen*/
    }
    EXPECT_EQ(streamId, streamFrame->streamId);
    EXPECT_EQ(0, streamFrame->offset);
    EXPECT_EQ(buf->computeChainDataLength(), streamFrame->len);
    EXPECT_EQ(true, streamFrame->fin);
  }
  EXPECT_TRUE(folly::IOBufEqualTo()(packet1.header, packet2.header));
}

TEST_F(QuicPacketRebuilderTest, CannotRebuildEmptyCryptoStream) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  // Get a bunch frames
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  uint64_t cryptoOffset = 0;
  auto cryptoBuf = folly::IOBuf::copyBuffer("NewSessionTicket");

  // Write them with a regular builder
  ASSERT_FALSE(
      writeCryptoFrame(
          cryptoOffset, ChainedByteRangeHead(cryptoBuf), regularBuilder1)
          .hasError());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(1, packet1.packet.frames.size());
  // Do not add the buf to crypto stream's retransmission buffer,
  // imagine it was cleared

  // rebuild a packet from the built out packet
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
}

TEST_F(QuicPacketRebuilderTest, CannotRebuild) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder1(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder1.encodePacketHeader().hasError());
  // Get a bunch frames
  ConnectionCloseFrame connCloseFrame(
      QuicErrorCode(TransportErrorCode::FRAME_ENCODING_ERROR),
      "The sun is in the sky.",
      FrameType::ACK);
  StreamsBlockedFrame maxStreamIdFrame(0x1024, true);
  AckBlocks ackBlocks;
  ackBlocks.insert(10, 100);
  ackBlocks.insert(200, 1000);
  WriteAckFrameState writeAckState = {.acks = ackBlocks};
  WriteAckFrameMetaData ackMeta = {
      .ackState = writeAckState,
      .ackDelay = 0us,
      .ackDelayExponent = static_cast<uint8_t>(kDefaultAckDelayExponent)};
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(10).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf =
      folly::IOBuf::copyBuffer("You can't deny you are looking for the sunset");
  PingFrame pingFrame;
  // Write them with a regular builder
  ASSERT_FALSE(writeFrame(connCloseFrame, regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(maxStreamIdFrame, regularBuilder1).hasError());
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder1).hasError());
  ASSERT_FALSE(writeAckFrame(ackMeta, regularBuilder1).hasError());
  (void)writeStreamFrameHeader(
      regularBuilder1,
      streamId,
      0,
      buf->computeChainDataLength(),
      buf->computeChainDataLength(),
      true,
      std::nullopt /* skipLenHint */);
  writeStreamFrameData(
      regularBuilder1, buf->clone(), buf->computeChainDataLength());
  auto packet1 = std::move(regularBuilder1).buildPacket();
  ASSERT_EQ(5, packet1.packet.frames.size());
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(buf), 0, true)));

  // new builder has a much smaller writable bytes limit
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      (packet1.header.computeChainDataLength() +
       packet1.body.computeChainDataLength()) /
          2,
      std::move(shortHeader2),
      0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto outstanding = makeDummyOutstandingPacket(packet1.packet, 1000);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstanding);
  ASSERT_FALSE(rebuildResult.hasError());
  EXPECT_FALSE(rebuildResult.value().has_value());
}

TEST_F(QuicPacketRebuilderTest, CloneCounter) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  MaxDataFrame maxDataFrame(31415926);
  ASSERT_FALSE(writeFrame(maxDataFrame, regularBuilder).hasError());
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 1000);
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0 /* largestAcked */);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  ASSERT_FALSE(rebuilder.rebuildFromPacket(outstandingPacket).hasError());
  EXPECT_TRUE(outstandingPacket.maybeClonedPacketIdentifier.has_value());
  EXPECT_EQ(1, conn.outstandings.numClonedPackets());
}

TEST_F(QuicPacketRebuilderTest, PurePingWillRebuild) {
  ShortHeader shortHeader1(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, std::move(shortHeader1), 0);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  PingFrame pingFrame;
  ASSERT_FALSE(writeFrame(pingFrame, regularBuilder).hasError());
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 50);
  EXPECT_EQ(1, outstandingPacket.packet.frames.size());
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ShortHeader shortHeader2(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder2(
      kDefaultUDPSendPacketLen, std::move(shortHeader2), 0);
  ASSERT_FALSE(regularBuilder2.encodePacketHeader().hasError());
  PacketRebuilder rebuilder(regularBuilder2, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstandingPacket);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
  EXPECT_TRUE(outstandingPacket.maybeClonedPacketIdentifier.has_value());
  EXPECT_EQ(1, conn.outstandings.numClonedPackets());
}

TEST_F(QuicPacketRebuilderTest, LastStreamFrameSkipLen) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(100).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf1 =
      folly::IOBuf::copyBuffer("Remember your days are fully numbered.");
  auto buf2 = folly::IOBuf::copyBuffer("Just march on");

  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, std::move(shortHeader), 0);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  (void)writeStreamFrameHeader(
      regularBuilder,
      streamId,
      0,
      buf1->computeChainDataLength(),
      buf1->computeChainDataLength(),
      false,
      std::nullopt);
  writeStreamFrameData(
      regularBuilder, buf1->clone(), buf1->computeChainDataLength());
  (void)writeStreamFrameHeader(
      regularBuilder,
      streamId,
      buf1->computeChainDataLength(),
      buf2->computeChainDataLength(),
      buf2->computeChainDataLength(),
      true,
      std::nullopt);
  writeStreamFrameData(
      regularBuilder, buf2->clone(), buf2->computeChainDataLength());
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 1200);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(buf1), 0, false)));
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(buf1->computeChainDataLength()),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(buf2), buf1->computeChainDataLength(), true)));
  MockQuicPacketBuilder mockBuilder;
  size_t packetLimit = 1200;
  EXPECT_CALL(mockBuilder, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return packetLimit;
  }));
  // write data twice
  EXPECT_CALL(mockBuilder, _insertRch(_, _))
      .Times(2)
      .WillRepeatedly(Invoke([&](const ChainedByteRangeHead&, size_t limit) {
        packetLimit -= limit;
      }));
  // Append frame twice
  EXPECT_CALL(mockBuilder, appendFrame(_)).Times(2);
  // initial byte:
  EXPECT_CALL(mockBuilder, writeBEUint8(_))
      .Times(2)
      .WillRepeatedly(Invoke([&](uint8_t) { packetLimit--; }));
  // Write streamId twice, offset once, then data len only once:
  EXPECT_CALL(mockBuilder, write(_))
      .Times(4)
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInt) {
        auto sizeResult = quicInt.getSize();
        ASSERT_FALSE(sizeResult.hasError());
        packetLimit -= sizeResult.value();
      }));

  PacketRebuilder rebuilder(mockBuilder, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstandingPacket);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
}

TEST_F(QuicPacketRebuilderTest, LastStreamFrameFinOnlySkipLen) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ASSERT_FALSE(
      conn.streamManager->setMaxLocalBidirectionalStreams(100).hasError());
  auto stream = conn.streamManager->createNextBidirectionalStream().value();
  auto streamId = stream->id;
  auto buf1 =
      folly::IOBuf::copyBuffer("Remember your days are fully numbered.");

  ShortHeader shortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), 0);
  RegularQuicPacketBuilder regularBuilder(
      kDefaultUDPSendPacketLen, std::move(shortHeader), 0);
  ASSERT_FALSE(regularBuilder.encodePacketHeader().hasError());
  (void)writeStreamFrameHeader(
      regularBuilder,
      streamId,
      0,
      buf1->computeChainDataLength(),
      buf1->computeChainDataLength(),
      false,
      std::nullopt);
  writeStreamFrameData(
      regularBuilder, buf1->clone(), buf1->computeChainDataLength());
  (void)writeStreamFrameHeader(
      regularBuilder,
      streamId,
      buf1->computeChainDataLength(),
      0,
      0,
      true,
      std::nullopt);
  writeStreamFrameData(regularBuilder, ChainedByteRangeHead(), 0);
  auto packet = std::move(regularBuilder).buildPacket();
  auto outstandingPacket = makeDummyOutstandingPacket(packet.packet, 1200);
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(0),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(buf1), 0, false)));
  stream->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(buf1->computeChainDataLength()),
      std::forward_as_tuple(std::make_unique<WriteStreamBuffer>(
          ChainedByteRangeHead(), buf1->computeChainDataLength(), true)));

  MockQuicPacketBuilder mockBuilder;
  size_t packetLimit = 1200;
  EXPECT_CALL(mockBuilder, remainingSpaceInPkt()).WillRepeatedly(Invoke([&]() {
    return packetLimit;
  }));
  // write data only
  EXPECT_CALL(mockBuilder, _insertRch(_, _))
      .Times(1)
      .WillOnce(Invoke([&](const ChainedByteRangeHead&, size_t limit) {
        packetLimit -= limit;
      }));
  // Append frame twice
  EXPECT_CALL(mockBuilder, appendFrame(_)).Times(2);
  // initial byte:
  EXPECT_CALL(mockBuilder, writeBEUint8(_))
      .Times(2)
      .WillRepeatedly(Invoke([&](uint8_t) { packetLimit--; }));
  // Write streamId twice, offset once, then data len twice:
  EXPECT_CALL(mockBuilder, write(_))
      .Times(5)
      .WillRepeatedly(Invoke([&](const QuicInteger& quicInt) {
        auto sizeResult = quicInt.getSize();
        ASSERT_FALSE(sizeResult.hasError());
        packetLimit -= sizeResult.value();
      }));

  PacketRebuilder rebuilder(mockBuilder, conn);
  auto rebuildResult = rebuilder.rebuildFromPacket(outstandingPacket);
  ASSERT_FALSE(rebuildResult.hasError());
  ASSERT_TRUE(rebuildResult.value().has_value());
}
} // namespace quic::test

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/Decode.h>

#include <folly/Random.h>
#include <folly/container/Array.h>
#include <folly/io/IOBuf.h>
#include <folly/portability/GTest.h>
#include <quic/codec/QuicReadCodec.h>
#include <quic/codec/Types.h>
#include <quic/common/test/TestUtils.h>
#include <ctime>

using namespace testing;

namespace quic::test {

using UnderlyingFrameType = std::underlying_type<FrameType>::type;

class DecodeTest : public Test {};

ShortHeader makeHeader() {
  PacketNum packetNum = 100;
  return ShortHeader(
      ProtectionType::KeyPhaseZero, getTestConnectionId(), packetNum);
}

// NormalizedAckBlocks are in order needed.
struct NormalizedAckBlock {
  QuicInteger gap; // Gap to previous AckBlock
  QuicInteger blockLen;

  NormalizedAckBlock(QuicInteger gapIn, QuicInteger blockLenIn)
      : gap(gapIn), blockLen(blockLenIn) {}
};

template <class LargestAckedType = uint64_t>
std::unique_ptr<folly::IOBuf> createAckFrame(
    Optional<QuicInteger> largestAcked,
    Optional<QuicInteger> ackDelay = std::nullopt,
    Optional<QuicInteger> numAdditionalBlocks = std::nullopt,
    Optional<QuicInteger> firstAckBlockLength = std::nullopt,
    std::vector<NormalizedAckBlock> ackBlocks = {},
    bool useRealValuesForLargestAcked = false,
    bool useRealValuesForAckDelay = false,
    bool addEcnCounts = false,
    bool useExtendedAck = false) {
  std::unique_ptr<folly::IOBuf> ackFrame = folly::IOBuf::create(0);
  BufAppender wcursor(ackFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (largestAcked) {
    if (useRealValuesForLargestAcked) {
      wcursor.writeBE<LargestAckedType>(largestAcked->getValue());
    } else {
      largestAcked->encode(appenderOp);
    }
  }
  if (ackDelay) {
    if (useRealValuesForAckDelay) {
      wcursor.writeBE(ackDelay->getValue());
    } else {
      ackDelay->encode(appenderOp);
    }
  }
  if (numAdditionalBlocks) {
    numAdditionalBlocks->encode(appenderOp);
  }
  if (firstAckBlockLength) {
    firstAckBlockLength->encode(appenderOp);
  }
  for (size_t i = 0; i < ackBlocks.size(); ++i) {
    ackBlocks[i].gap.encode(appenderOp);
    ackBlocks[i].blockLen.encode(appenderOp);
  }
  if (useExtendedAck) {
    // Write extended ack with ECN if enabled.
    QuicInteger extendedAckFeatures(
        addEcnCounts ? static_cast<ExtendedAckFeatureMaskType>(
                           ExtendedAckFeatureMask::ECN_COUNTS)
                     : 0);
    extendedAckFeatures.encode(appenderOp);
  }
  if (addEcnCounts) {
    QuicInteger ect0(1); // ECT-0 count
    QuicInteger ect1(2); // ECT-1 count
    QuicInteger ce(3); // CE count
    ect0.encode(appenderOp);
    ect1.encode(appenderOp);
    ce.encode(appenderOp);
  }
  return ackFrame;
}

std::unique_ptr<folly::IOBuf> createRstStreamFrame(
    StreamId streamId,
    ApplicationErrorCode errorCode,
    uint64_t finalSize,
    Optional<uint64_t> reliableSize = std::nullopt) {
  std::unique_ptr<folly::IOBuf> rstStreamFrame = folly::IOBuf::create(0);
  BufAppender wcursor(rstStreamFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };

  FrameType frameType =
      reliableSize ? FrameType::RST_STREAM_AT : FrameType::RST_STREAM;

  // Write the frame type
  QuicInteger frameTypeQuicInt(static_cast<uint8_t>(frameType));
  frameTypeQuicInt.encode(appenderOp);

  // Write the stream id
  QuicInteger streamIdQuicInt(streamId);
  streamIdQuicInt.encode(appenderOp);

  // Write the error code
  QuicInteger errorCodeQuicInt(static_cast<uint64_t>(errorCode));
  errorCodeQuicInt.encode(appenderOp);

  // Write the final size
  QuicInteger finalSizeQuicInt(finalSize);
  finalSizeQuicInt.encode(appenderOp);

  if (reliableSize) {
    // Write the reliable size
    QuicInteger reliableSizeQuicInt(*reliableSize);
    reliableSizeQuicInt.encode(appenderOp);
  }

  return rstStreamFrame;
}

template <class StreamIdType = StreamId>
std::unique_ptr<folly::IOBuf> createStreamFrame(
    Optional<QuicInteger> streamId,
    Optional<QuicInteger> offset = std::nullopt,
    Optional<QuicInteger> dataLength = std::nullopt,
    BufPtr data = nullptr,
    bool useRealValuesForStreamId = false,
    Optional<QuicInteger> groupId = std::nullopt) {
  std::unique_ptr<folly::IOBuf> streamFrame = folly::IOBuf::create(0);
  BufAppender wcursor(streamFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (streamId) {
    if (useRealValuesForStreamId) {
      wcursor.writeBE<StreamIdType>(streamId->getValue());
    } else {
      streamId->encode(appenderOp);
    }
  }
  if (groupId) {
    groupId->encode(appenderOp);
  }
  if (offset) {
    offset->encode(appenderOp);
  }
  if (dataLength) {
    dataLength->encode(appenderOp);
  }
  if (data) {
    wcursor.insert(std::move(data));
  }
  return streamFrame;
}

std::unique_ptr<folly::IOBuf> createCryptoFrame(
    Optional<QuicInteger> offset = std::nullopt,
    Optional<QuicInteger> dataLength = std::nullopt,
    BufPtr data = nullptr) {
  std::unique_ptr<folly::IOBuf> cryptoFrame = folly::IOBuf::create(0);
  BufAppender wcursor(cryptoFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (offset) {
    offset->encode(appenderOp);
  }
  if (dataLength) {
    dataLength->encode(appenderOp);
  }
  if (data) {
    wcursor.insert(std::move(data));
  }
  return cryptoFrame;
}

std::unique_ptr<folly::IOBuf> createAckFrequencyFrame(
    Optional<QuicInteger> sequenceNumber,
    Optional<QuicInteger> packetTolerance,
    Optional<QuicInteger> maxAckDelay,
    Optional<QuicInteger> reorderThreshold) {
  QuicInteger intFrameType(static_cast<uint64_t>(FrameType::ACK_FREQUENCY));
  std::unique_ptr<folly::IOBuf> ackFrequencyFrame = folly::IOBuf::create(0);
  BufAppender wcursor(ackFrequencyFrame.get(), 50);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (sequenceNumber) {
    sequenceNumber->encode(appenderOp);
  }
  if (packetTolerance) {
    packetTolerance->encode(appenderOp);
  }
  if (maxAckDelay) {
    maxAckDelay->encode(appenderOp);
  }
  if (reorderThreshold) {
    reorderThreshold->encode(appenderOp);
  }
  return ackFrequencyFrame;
}

TEST_F(DecodeTest, VersionNegotiationPacketDecodeTest) {
  ConnectionId srcCid = getTestConnectionId(0),
               destCid = getTestConnectionId(1);
  std::vector<QuicVersion> versions{
      {static_cast<QuicVersion>(1234),
       static_cast<QuicVersion>(4321),
       static_cast<QuicVersion>(2341),
       static_cast<QuicVersion>(3412),
       static_cast<QuicVersion>(4123)}};
  auto packet =
      VersionNegotiationPacketBuilder(srcCid, destCid, versions).buildPacket();
  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(packet.second));
  auto versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(versionPacket.has_value());
  EXPECT_EQ(versionPacket->destinationConnectionId, destCid);
  EXPECT_EQ(versionPacket->sourceConnectionId, srcCid);
  EXPECT_EQ(versionPacket->versions.size(), versions.size());
  EXPECT_EQ(versionPacket->versions, versions);
}

TEST_F(DecodeTest, DifferentCIDLength) {
  ConnectionId sourceConnectionId = getTestConnectionId();
  ConnectionId destinationConnectionId =
      ConnectionId::createAndMaybeCrash({1, 2, 3, 4, 5, 6});
  std::vector<QuicVersion> versions{
      {static_cast<QuicVersion>(1234),
       static_cast<QuicVersion>(4321),
       static_cast<QuicVersion>(2341),
       static_cast<QuicVersion>(3412),
       static_cast<QuicVersion>(4123)}};
  auto packet = VersionNegotiationPacketBuilder(
                    sourceConnectionId, destinationConnectionId, versions)
                    .buildPacket();
  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(packet.second));
  auto versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(versionPacket.has_value());
  EXPECT_EQ(versionPacket->sourceConnectionId, sourceConnectionId);
  EXPECT_EQ(versionPacket->destinationConnectionId, destinationConnectionId);
  EXPECT_EQ(versionPacket->versions.size(), versions.size());
  EXPECT_EQ(versionPacket->versions, versions);
}

TEST_F(DecodeTest, VersionNegotiationPacketBadPacketTest) {
  ConnectionId connId = getTestConnectionId();
  QuicVersionType version = static_cast<QuicVersionType>(QuicVersion::MVFST);

  auto buf = folly::IOBuf::create(10);
  folly::io::Appender appender(buf.get(), 10);
  appender.writeBE<uint8_t>(kHeaderFormMask);
  appender.push(connId.data(), connId.size());
  appender.writeBE<QuicVersionType>(
      static_cast<QuicVersionType>(QuicVersion::VERSION_NEGOTIATION));
  appender.push((uint8_t*)&version, sizeof(QuicVersion) - 1);

  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  AckStates ackStates;
  auto packetQueue = bufToQueue(std::move(buf));
  auto packet = codec->parsePacket(packetQueue, ackStates);
  EXPECT_EQ(packet.regularPacket(), nullptr);

  buf = folly::IOBuf::create(0);
  packetQueue = bufToQueue(std::move(buf));
  packet = codec->parsePacket(packetQueue, ackStates);
  // Packet with empty versions
  EXPECT_EQ(packet.regularPacket(), nullptr);
}

TEST_F(DecodeTest, ValidAckFrame) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  Cursor cursor(result.get());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.has_value());
  auto ackFrame = *res;
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  EXPECT_EQ(ackFrame.largestAcked, 1000);
  // Since 100 is the encoded value, we use the decoded value.
  EXPECT_EQ(ackFrame.ackDelay.count(), 100 << kDefaultAckDelayExponent);
}

TEST_F(DecodeTest, AckEcnFrame) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks,
      false, // useRealValuesForLargestAcked
      false, // useRealValuesForAckDelay
      true); // addEcnCounts
  Cursor cursor(result.get());
  auto res = decodeAckFrameWithECN(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.has_value());
  auto ackFrame = *res->asReadAckFrame();
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  EXPECT_EQ(ackFrame.largestAcked, 1000);
  // Since 100 is the encoded value, we use the decoded value.
  EXPECT_EQ(ackFrame.ackDelay.count(), 100 << kDefaultAckDelayExponent);

  // These values are hardcoded in the createAckFrame function
  EXPECT_EQ(ackFrame.ecnECT0Count, 1);
  EXPECT_EQ(ackFrame.ecnECT1Count, 2);
  EXPECT_EQ(ackFrame.ecnCECount, 3);
}

TEST_F(DecodeTest, AckExtendedFrameWithECN) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks,
      false, // useRealValuesForLargestAcked
      false, // useRealValuesForAckDelay
      true, // addEcnCounts
      true); // useExtendedAck
  Cursor cursor(result.get());
  auto ackFrameRes = decodeAckExtendedFrame(
      cursor,
      makeHeader(),
      CodecParameters(
          kDefaultAckDelayExponent,
          QuicVersion::MVFST,
          std::nullopt,
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::ECN_COUNTS)));
  ASSERT_TRUE(ackFrameRes.has_value());
  auto ackFrame = *ackFrameRes;
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  EXPECT_EQ(ackFrame.largestAcked, 1000);
  // Since 100 is the encoded value, we use the decoded value.
  EXPECT_EQ(ackFrame.ackDelay.count(), 100 << kDefaultAckDelayExponent);

  EXPECT_EQ(ackFrame.frameType, FrameType::ACK_EXTENDED);

  // These values are hardcoded in the createAckFrame function
  EXPECT_EQ(ackFrame.ecnECT0Count, 1);
  EXPECT_EQ(ackFrame.ecnECT1Count, 2);
  EXPECT_EQ(ackFrame.ecnCECount, 3);
}

TEST_F(DecodeTest, AckExtendedFrameWithNoFeatures) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks,
      false, // useRealValuesForLargestAcked
      false, // useRealValuesForAckDelay
      false, // addEcnCounts
      true); // useExtendedAck
  Cursor cursor(result.get());
  auto ackFrameRes = decodeAckExtendedFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(ackFrameRes.has_value());
  auto ackFrame = *ackFrameRes;
  EXPECT_EQ(ackFrame.ackBlocks.size(), 2);
  EXPECT_EQ(ackFrame.largestAcked, 1000);
  // Since 100 is the encoded value, we use the decoded value.
  EXPECT_EQ(ackFrame.ackDelay.count(), 100 << kDefaultAckDelayExponent);

  EXPECT_EQ(ackFrame.frameType, FrameType::ACK_EXTENDED);

  EXPECT_EQ(ackFrame.ecnECT0Count, 0);
  EXPECT_EQ(ackFrame.ecnECT1Count, 0);
  EXPECT_EQ(ackFrame.ecnCECount, 0);
}

TEST_F(DecodeTest, AckExtendedFrameThrowsWithUnsupportedFeatures) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(1);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks,
      false, // useRealValuesForLargestAcked
      false, // useRealValuesForAckDelay
      true, // addEcnCounts
      true); // useExtendedAck
  Cursor cursor(result.get());

  // Try to decode extended ack with ECN but we only support Timestamps
  auto decodeResult = decodeAckExtendedFrame(
      cursor,
      makeHeader(),
      CodecParameters(
          kDefaultAckDelayExponent,
          QuicVersion::MVFST,
          std::nullopt,
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::RECEIVE_TIMESTAMPS)));
  EXPECT_TRUE(decodeResult.hasError());
  EXPECT_EQ(
      decodeResult.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameLargestAckExceedsRange) {
  // An integer larger than the representable range of quic integer.
  QuicInteger largestAcked(std::numeric_limits<uint64_t>::max());
  QuicInteger ackDelay(10);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(10);
  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      {},
      true);
  Cursor cursor(result.get());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.has_value());
  auto ackFrame = *res;
  // it will interpret this as a 8 byte range with the max value.
  EXPECT_EQ(ackFrame.largestAcked, 4611686018427387903);
}

TEST_F(DecodeTest, AckFrameLargestAckInvalid) {
  // An integer larger than the representable range of quic integer.
  QuicInteger largestAcked(std::numeric_limits<uint64_t>::max());
  QuicInteger ackDelay(10);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(10);
  auto result = createAckFrame<uint8_t>(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      {},
      true);
  Cursor cursor(result.get());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameDelayEncodingInvalid) {
  QuicInteger largestAcked(1000);
  // Maximal representable value by quic integer.
  QuicInteger ackDelay(4611686018427387903);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(10);
  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      {},
      false,
      true);
  Cursor cursor(result.get());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameDelayExceedsRange) {
  QuicInteger largestAcked(1000);
  // Maximal representable value by quic integer.
  QuicInteger ackDelay(4611686018427387903);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(10);
  auto result = createAckFrame(
      largestAcked, ackDelay, numAdditionalBlocks, firstAckBlockLength);
  Cursor cursor(result.get());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameAdditionalBlocksUnderflow) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  Cursor cursor(result.get());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameAdditionalBlocksOverflow) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  Cursor cursor(result.get());
  ASSERT_FALSE(
      decodeAckFrame(
          cursor,
          makeHeader(),
          CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST))
          .hasError());
}

TEST_F(DecodeTest, AckFrameMissingFields) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));

  auto result1 = createAckFrame(
      largestAcked,
      std::nullopt,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  Cursor cursor1(result1.get());

  auto res = decodeAckFrame(
      cursor1,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  auto result2 = createAckFrame(
      largestAcked, ackDelay, std::nullopt, firstAckBlockLength, ackBlocks);
  Cursor cursor2(result2.get());
  res = decodeAckFrame(
      cursor2,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  auto result3 = createAckFrame(
      largestAcked, ackDelay, std::nullopt, firstAckBlockLength, ackBlocks);
  Cursor cursor3(result3.get());
  res = decodeAckFrame(
      cursor3,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  auto result4 = createAckFrame(
      largestAcked, ackDelay, numAdditionalBlocks, std::nullopt, ackBlocks);
  Cursor cursor4(result4.get());
  res = decodeAckFrame(
      cursor4,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  auto result5 = createAckFrame(
      largestAcked, ackDelay, numAdditionalBlocks, firstAckBlockLength, {});
  Cursor cursor5(result5.get());
  res = decodeAckFrame(
      cursor5,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameFirstBlockLengthInvalid) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(0);
  QuicInteger firstAckBlockLength(2000);

  auto result = createAckFrame(
      largestAcked, ackDelay, numAdditionalBlocks, firstAckBlockLength);
  Cursor cursor(result.get());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameBlockLengthInvalid) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(1000));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  Cursor cursor(result.get());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameBlockGapInvalid) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(2);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(1000), QuicInteger(0));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  Cursor cursor(result.get());
  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, AckFrameBlockLengthZero) {
  QuicInteger largestAcked(1000);
  QuicInteger ackDelay(100);
  QuicInteger numAdditionalBlocks(3);
  QuicInteger firstAckBlockLength(10);

  std::vector<NormalizedAckBlock> ackBlocks;
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(10));
  ackBlocks.emplace_back(QuicInteger(10), QuicInteger(0));
  ackBlocks.emplace_back(QuicInteger(0), QuicInteger(10));

  auto result = createAckFrame(
      largestAcked,
      ackDelay,
      numAdditionalBlocks,
      firstAckBlockLength,
      ackBlocks);
  Cursor cursor(result.get());

  auto res = decodeAckFrame(
      cursor,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(res.has_value());
  auto readAckFrame = *res;
  EXPECT_EQ(readAckFrame.ackBlocks[0].endPacket, 1000);
  EXPECT_EQ(readAckFrame.ackBlocks[0].startPacket, 990);
  EXPECT_EQ(readAckFrame.ackBlocks[1].endPacket, 978);
  EXPECT_EQ(readAckFrame.ackBlocks[1].startPacket, 968);
  EXPECT_EQ(readAckFrame.ackBlocks[2].endPacket, 956);
  EXPECT_EQ(readAckFrame.ackBlocks[2].startPacket, 956);
  EXPECT_EQ(readAckFrame.ackBlocks[3].endPacket, 954);
  EXPECT_EQ(readAckFrame.ackBlocks[3].startPacket, 944);
}

TEST_F(DecodeTest, StreamDecodeSuccess) {
  QuicInteger streamId(10);
  QuicInteger offset(10);
  QuicInteger length(1);
  auto streamType =
      StreamTypeField::Builder().setFin().setOffset().setLength().build();
  auto streamFrame = createStreamFrame(
      streamId, offset, length, folly::IOBuf::copyBuffer("a"));
  BufQueue queue;
  queue.append(streamFrame->clone());
  auto decodedFrameRes = decodeStreamFrame(queue, streamType);
  ASSERT_TRUE(decodedFrameRes.has_value());
  auto decodedFrame = decodedFrameRes.value();
  EXPECT_EQ(decodedFrame.offset, 10);
  EXPECT_EQ(decodedFrame.data->computeChainDataLength(), 1);
  EXPECT_EQ(decodedFrame.streamId, 10);
  EXPECT_TRUE(decodedFrame.fin);
}

TEST_F(DecodeTest, StreamLengthStreamIdInvalid) {
  QuicInteger streamId(std::numeric_limits<uint64_t>::max());
  auto streamType =
      StreamTypeField::Builder().setFin().setOffset().setLength().build();
  auto streamFrame = createStreamFrame<uint8_t>(
      streamId, std::nullopt, std::nullopt, nullptr, true);
  BufQueue queue;
  queue.append(streamFrame->clone());
  auto result = decodeStreamFrame(queue, streamType);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, StreamOffsetNotPresent) {
  QuicInteger streamId(10);
  QuicInteger length(1);
  auto streamType =
      StreamTypeField::Builder().setFin().setOffset().setLength().build();
  auto streamFrame = createStreamFrame(
      streamId, std::nullopt, length, folly::IOBuf::copyBuffer("a"));
  BufQueue queue;
  queue.append(streamFrame->clone());
  auto result = decodeStreamFrame(queue, streamType);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, StreamIncorrectDataLength) {
  QuicInteger streamId(10);
  QuicInteger offset(10);
  QuicInteger length(10);
  auto streamType =
      StreamTypeField::Builder().setFin().setOffset().setLength().build();
  auto streamFrame = createStreamFrame(
      streamId, offset, length, folly::IOBuf::copyBuffer("a"));
  BufQueue queue;
  queue.append(streamFrame->clone());
  auto result = decodeStreamFrame(queue, streamType);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, StreamNoRemainingData) {
  // assume after parsing the frame type (stream frame), there was no remaining
  // data
  quic::BufPtr buf = folly::IOBuf::copyBuffer("test");
  BufQueue queue(std::move(buf));
  queue.trimStartAtMost(4);

  const auto streamType =
      StreamTypeField(static_cast<uint8_t>(FrameType::STREAM));
  auto result = decodeStreamFrame(queue, streamType);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, DatagramNoRemainingData) {
  // assume after parsing the frame type (datagram frame), there was no
  // remaining data
  quic::BufPtr buf = folly::IOBuf::copyBuffer("test");
  BufQueue queue(std::move(buf));
  queue.trimStartAtMost(4);

  // invalid len
  auto result = decodeDatagramFrame(queue, true);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

std::unique_ptr<folly::IOBuf> CreateMaxStreamsIdFrame(
    unsigned long long maxStreamsId) {
  std::unique_ptr<folly::IOBuf> buf = folly::IOBuf::create(sizeof(QuicInteger));
  BufAppender wcursor(buf.get(), sizeof(QuicInteger));
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  QuicInteger maxStreamsIdVal(maxStreamsId);
  maxStreamsIdVal.encode(appenderOp);
  return buf;
}

// Uni and BiDi have same max limits so uses single 'frame' to check both.
void MaxStreamsIdCheckSuccess(StreamId maxStreamsId) {
  std::unique_ptr<folly::IOBuf> buf = CreateMaxStreamsIdFrame(maxStreamsId);

  Cursor cursorBiDi(buf.get());
  auto maxStreamsBiDiFrameRes = decodeBiDiMaxStreamsFrame(cursorBiDi);
  ASSERT_TRUE(maxStreamsBiDiFrameRes.has_value());
  EXPECT_EQ(maxStreamsBiDiFrameRes->maxStreams, maxStreamsId);

  Cursor cursorUni(buf.get());
  auto maxStreamsUniFrameRes = decodeUniMaxStreamsFrame(cursorUni);
  ASSERT_TRUE(maxStreamsUniFrameRes.has_value());
  EXPECT_EQ(maxStreamsUniFrameRes->maxStreams, maxStreamsId);
}

// Uni and BiDi have same max limits so uses single 'frame' to check both.
void MaxStreamsIdCheckInvalid(StreamId maxStreamsId) {
  std::unique_ptr<folly::IOBuf> buf = CreateMaxStreamsIdFrame(maxStreamsId);

  Cursor cursorBiDi(buf.get());
  auto bidiResult = decodeBiDiMaxStreamsFrame(cursorBiDi);
  EXPECT_TRUE(bidiResult.hasError());
  EXPECT_EQ(bidiResult.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);

  Cursor cursorUni(buf.get());
  auto uniResult = decodeUniMaxStreamsFrame(cursorUni);
  EXPECT_TRUE(uniResult.hasError());
  EXPECT_EQ(uniResult.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, MaxStreamsIdChecks) {
  MaxStreamsIdCheckSuccess(0);
  MaxStreamsIdCheckSuccess(123);
  MaxStreamsIdCheckSuccess(kMaxMaxStreams);

  MaxStreamsIdCheckInvalid(kMaxMaxStreams + 1);
  MaxStreamsIdCheckInvalid(kMaxMaxStreams + 123);
  MaxStreamsIdCheckInvalid(kMaxStreamId - 1);
}

TEST_F(DecodeTest, CryptoDecodeSuccess) {
  QuicInteger offset(10);
  QuicInteger length(1);
  auto cryptoFrame =
      createCryptoFrame(offset, length, folly::IOBuf::copyBuffer("a"));
  Cursor cursor(cryptoFrame.get());
  auto decodedFrame = decodeCryptoFrame(cursor);
  EXPECT_EQ(decodedFrame->offset, 10);
  EXPECT_EQ(decodedFrame->data->computeChainDataLength(), 1);
}

TEST_F(DecodeTest, CryptoOffsetNotPresent) {
  QuicInteger length(1);
  auto cryptoFrame =
      createCryptoFrame(std::nullopt, length, folly::IOBuf::copyBuffer("a"));
  Cursor cursor(cryptoFrame.get());
  auto result = decodeCryptoFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, CryptoLengthNotPresent) {
  QuicInteger offset(0);
  auto cryptoFrame = createCryptoFrame(offset, std::nullopt, nullptr);
  Cursor cursor(cryptoFrame.get());
  auto result = decodeCryptoFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, CryptoIncorrectDataLength) {
  QuicInteger offset(10);
  QuicInteger length(10);
  auto cryptoFrame =
      createCryptoFrame(offset, length, folly::IOBuf::copyBuffer("a"));
  Cursor cursor(cryptoFrame.get());
  auto result = decodeCryptoFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, PaddingFrameTest) {
  auto buf = folly::IOBuf::create(sizeof(UnderlyingFrameType));
  buf->append(1);
  memset(buf->writableData(), 0, 1);

  Cursor cursor(buf.get());
  ASSERT_FALSE(decodePaddingFrame(cursor).hasError());
}

TEST_F(DecodeTest, PaddingFrameNoBytesTest) {
  auto buf = folly::IOBuf::create(sizeof(UnderlyingFrameType));

  Cursor cursor(buf.get());
  ASSERT_FALSE(decodePaddingFrame(cursor).hasError());
}

TEST_F(DecodeTest, DecodeMultiplePaddingInterleavedTest) {
  auto buf = folly::IOBuf::create(20);
  buf->append(10);
  memset(buf->writableData(), 0, 10);
  buf->append(1);
  // something which is not padding
  memset(buf->writableData() + 10, 5, 1);

  Cursor cursor(buf.get());
  ASSERT_FALSE(decodePaddingFrame(cursor).hasError());
  // If we encountered an interleaved frame, leave the whole thing
  // as is
  EXPECT_EQ(cursor.totalLength(), 11);
}

TEST_F(DecodeTest, DecodeMultiplePaddingTest) {
  auto buf = folly::IOBuf::create(20);
  buf->append(10);
  memset(buf->writableData(), 0, 10);

  Cursor cursor(buf.get());
  ASSERT_FALSE(decodePaddingFrame(cursor).hasError());
  EXPECT_EQ(cursor.totalLength(), 0);
}

std::unique_ptr<folly::IOBuf> createNewTokenFrame(
    Optional<QuicInteger> tokenLength = std::nullopt,
    BufPtr token = nullptr) {
  std::unique_ptr<folly::IOBuf> newTokenFrame = folly::IOBuf::create(0);
  BufAppender wcursor(newTokenFrame.get(), 10);
  auto appenderOp = [&](auto val) { wcursor.writeBE(val); };
  if (tokenLength) {
    tokenLength->encode(appenderOp);
  }
  if (token) {
    wcursor.insert(std::move(token));
  }
  return newTokenFrame;
}

TEST_F(DecodeTest, NewTokenDecodeSuccess) {
  QuicInteger length(1);
  auto newTokenFrame =
      createNewTokenFrame(length, folly::IOBuf::copyBuffer("a"));
  Cursor cursor(newTokenFrame.get());
  auto decodedFrame = decodeNewTokenFrame(cursor);
  EXPECT_EQ(decodedFrame->token->computeChainDataLength(), 1);
}

TEST_F(DecodeTest, NewTokenLengthNotPresent) {
  auto newTokenFrame =
      createNewTokenFrame(std::nullopt, folly::IOBuf::copyBuffer("a"));
  Cursor cursor(newTokenFrame.get());
  auto result = decodeNewTokenFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, NewTokenIncorrectDataLength) {
  QuicInteger length(10);
  auto newTokenFrame =
      createNewTokenFrame(length, folly::IOBuf::copyBuffer("a"));
  Cursor cursor(newTokenFrame.get());
  auto result = decodeNewTokenFrame(cursor);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, ParsePlaintextNewToken) {
  folly::IPAddress clientIp("127.0.0.1");
  uint64_t timestampInMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  NewToken newToken(clientIp, timestampInMs);
  BufPtr plaintextNewToken = newToken.getPlaintextToken();

  Cursor cursor(plaintextNewToken.get());

  auto parseResult = parsePlaintextRetryOrNewToken(cursor);

  EXPECT_TRUE(parseResult.has_value());

  EXPECT_EQ(parseResult.value(), timestampInMs);
}

TEST_F(DecodeTest, ParsePlaintextRetryToken) {
  ConnectionId odcid = getTestConnectionId();
  folly::IPAddress clientIp("109.115.3.49");
  uint16_t clientPort = 42069;
  uint64_t timestampInMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();

  RetryToken retryToken(odcid, clientIp, clientPort, timestampInMs);
  BufPtr plaintextRetryToken = retryToken.getPlaintextToken();

  Cursor cursor(plaintextRetryToken.get());

  /**
   * Now we continue with the parsing logic here.
   */
  auto parseResult = parsePlaintextRetryOrNewToken(cursor);

  EXPECT_TRUE(parseResult.has_value());

  EXPECT_EQ(parseResult.value(), timestampInMs);
}

TEST_F(DecodeTest, StreamGroupDecodeSuccess) {
  QuicInteger streamId(10);
  QuicInteger groupId(20);
  QuicInteger offset(10);
  QuicInteger length(1);
  auto streamType = StreamTypeField::Builder()
                        .switchToStreamGroups()
                        .setFin()
                        .setOffset()
                        .setLength()
                        .build();

  auto streamFrame = createStreamFrame(
      streamId,
      offset,
      length,
      folly::IOBuf::copyBuffer("a"),
      false /* useRealValuesForStreamId */,
      groupId);
  BufQueue queue;
  queue.append(streamFrame->clone());
  auto decodedFrameRes =
      decodeStreamFrame(queue, streamType, true /* isGroupFrame */);
  ASSERT_TRUE(decodedFrameRes.has_value());
  auto decodedFrame = decodedFrameRes.value();
  EXPECT_EQ(decodedFrame.offset, 10);
  EXPECT_EQ(decodedFrame.data->computeChainDataLength(), 1);
  EXPECT_EQ(decodedFrame.streamId, 10);
  EXPECT_EQ(*decodedFrame.streamGroupId, 20);
  EXPECT_TRUE(decodedFrame.fin);
}

TEST_F(DecodeTest, AckFrequencyFrameDecodeValid) {
  QuicInteger sequenceNumber(1);
  QuicInteger packetTolerance(100);
  QuicInteger maxAckDelay(100000); // 100 ms
  QuicInteger reorderThreshold(50);
  auto ackFrequencyFrame = createAckFrequencyFrame(
      sequenceNumber, packetTolerance, maxAckDelay, reorderThreshold);
  ASSERT_NE(ackFrequencyFrame, nullptr);

  Cursor cursor(ackFrequencyFrame.get());
  auto res = decodeAckFrequencyFrame(cursor);
  EXPECT_TRUE(res.has_value());
  auto decodedFrame = *res->asAckFrequencyFrame();
  EXPECT_EQ(decodedFrame.sequenceNumber, 1);
  EXPECT_EQ(decodedFrame.packetTolerance, 100);
  EXPECT_EQ(decodedFrame.updateMaxAckDelay, 100000);
  EXPECT_EQ(decodedFrame.reorderThreshold, 50);
}

TEST_F(DecodeTest, AckFrequencyFrameDecodeInvalidReserved) {
  QuicInteger sequenceNumber(1);
  QuicInteger packetTolerance(100);
  QuicInteger maxAckDelay(100000); // 100 ms
  auto ackFrequencyFrame = createAckFrequencyFrame(
      sequenceNumber, packetTolerance, maxAckDelay, std::nullopt);
  ASSERT_NE(ackFrequencyFrame, nullptr);

  Cursor cursor(ackFrequencyFrame.get());
  auto res = decodeAckFrequencyFrame(cursor);
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, RstStreamFrame) {
  auto buf = createRstStreamFrame(0, 0, 10);
  BufQueue queue(std::move(buf));
  auto frame = parseFrame(
      queue,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  auto rstStreamFrame = frame->asRstStreamFrame();
  EXPECT_EQ(rstStreamFrame->streamId, 0);
  EXPECT_EQ(rstStreamFrame->errorCode, 0);
  EXPECT_EQ(rstStreamFrame->finalSize, 10);
  EXPECT_FALSE(rstStreamFrame->reliableSize.has_value());
}

TEST_F(DecodeTest, RstStreamAtFrame) {
  auto buf = createRstStreamFrame(0, 0, 10, 9);
  BufQueue queue(std::move(buf));
  auto frame = parseFrame(
      queue,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  auto rstStreamFrameRes = frame->asRstStreamFrame();
  ASSERT_TRUE(rstStreamFrameRes);
  auto rstStreamFrame = *rstStreamFrameRes;
  EXPECT_EQ(rstStreamFrame.streamId, 0);
  EXPECT_EQ(rstStreamFrame.errorCode, 0);
  EXPECT_EQ(rstStreamFrame.finalSize, 10);
  EXPECT_EQ(*rstStreamFrame.reliableSize, 9);
}

TEST_F(DecodeTest, RstStreamAtFrameRelSizeGreaterThanOffset) {
  auto buf = createRstStreamFrame(0, 0, 10, 11);
  BufQueue queue(std::move(buf));
  auto result = parseFrame(
      queue,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

TEST_F(DecodeTest, RstStreamAtTruncated) {
  auto buf = createRstStreamFrame(0, 0, 10, 9);
  buf->coalesce();
  buf->trimEnd(1);
  BufQueue queue(std::move(buf));
  auto result = parseFrame(
      queue,
      makeHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(result.error().code, TransportErrorCode::FRAME_ENCODING_ERROR);
}

} // namespace quic::test

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>

#include <quic/api/test/Mocks.h>
#include <quic/api/test/QuicTypedTransportTestUtil.h>
#include <quic/codec/Types.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>
#include <quic/fizz/client/test/QuicClientTransportTestUtil.h>
#include <quic/server/test/QuicServerTransportTestUtil.h>
#include <quic/state/AckEvent.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/test/Mocks.h>

using namespace folly;
using namespace testing;

namespace {

using TransportTypes = testing::Types<
    quic::test::QuicClientTransportTestBase,
    quic::test::QuicServerTransportTestBase>;

class TransportTypeNames {
 public:
  template <typename T>
  static std::string GetName(int) {
    // we have to remove "::" from the string that we return here,
    // or gtest will silently refuse to run these tests!
    auto str = folly::demangle(typeid(T)).toStdString();
    if (str.find_last_of("::") != str.npos) {
      return str.substr(str.find_last_of("::") + 1);
    }
    return str;
  }
};

} // namespace

namespace quic::test {

template <typename T>
class QuicTypedTransportTest : public virtual testing::Test,
                               public QuicTypedTransportTestBase<T> {
 public:
  ~QuicTypedTransportTest() override = default;

  void SetUp() override {
    // trigger setup of the underlying transport
    QuicTypedTransportTestBase<T>::SetUp();
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportTest,
    ::TransportTypes,
    ::TransportTypeNames);

/**
 * Verify that connection start time is properly stored in TransportInfo.
 */
TYPED_TEST(QuicTypedTransportTest, TransportInfoConnectionTime) {
  TestFixture::startTransport();
  const auto afterStartTs = std::chrono::steady_clock::now();
  EXPECT_LE(
      std::chrono::steady_clock::time_point().time_since_epoch().count(),
      this->getTransport()
          ->getTransportInfo()
          .connectionTime.time_since_epoch()
          .count());
  EXPECT_GE(
      afterStartTs.time_since_epoch().count(),
      this->getTransport()
          ->getTransportInfo()
          .connectionTime.time_since_epoch()
          .count());
  this->destroyTransport();
}

template <typename T>
class QuicTypedTransportAfterStartTest : public QuicTypedTransportTest<T> {
 public:
  ~QuicTypedTransportAfterStartTest() override = default;

  void SetUp() override {
    QuicTypedTransportTest<T>::SetUp();
    QuicTypedTransportTestBase<T>::startTransport();
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportAfterStartTest,
    ::TransportTypes,
    ::TransportTypeNames);

/**
 * Verify that RTT signals are properly passed through to TransportInfo.
 *
 * Currently tests mrtt, mrttNoAckDelay, lrttRaw, lrttRawAckDelay
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, TransportInfoRttSignals) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    ASSERT_FALSE(this->getTransport()
                     ->writeChain(streamId, IOBuf::copyBuffer("hello"), false)
                     .hasError());
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(std::nullopt, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      std::nullopt,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 31ms (5 ms) |     26ms      ||   31   |       26       | (both)
  //    2  | 30ms (3 ms) |     27ms      ||   30   |       26       | (1)
  //    3  | 30ms (8 ms) |     22ms      ||   30   |       22       | (2)
  //    4  | 37ms (8 ms) |     29ms      ||   30   |       22       | (none)
  //    5  | 25ms (0 ms) |     29ms      ||   25   |       22       | (1)
  //    6  | 25ms (4 ms) |     29ms      ||   25   |       21       | (2)
  //    7  | 20ms (0 ms) |     29ms      ||   20   |       20       | (both)

  // case 1 [31ms (5 ms)]
  {
    const auto rtt = 31ms;
    const auto ackDelay = 5ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 31ms;
    const auto expectedMinRttNoAckDelay = 26ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 2 [30ms (3 ms)]
  {
    const auto rtt = 30ms;
    const auto ackDelay = 3ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 30ms;
    const auto expectedMinRttNoAckDelay = 26ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 3 [30ms (8 ms)]
  {
    const auto rtt = 30ms;
    const auto ackDelay = 8ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 30ms;
    const auto expectedMinRttNoAckDelay = 22ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 4 [37ms (8 ms)]
  {
    const auto rtt = 37ms;
    const auto ackDelay = 8ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 30ms;
    const auto expectedMinRttNoAckDelay = 22ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 5 [25ms (0 ms)]
  {
    const auto rtt = 25ms;
    const auto ackDelay = 0ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    const auto expectedMinRttNoAckDelay = 22ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 6 [25ms (4 ms)]
  {
    const auto rtt = 25ms;
    const auto ackDelay = 4ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    const auto expectedMinRttNoAckDelay = 21ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 7 [20ms (0 ms)]
  {
    const auto rtt = 20ms;
    const auto ackDelay = 0ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 20ms;
    const auto expectedMinRttNoAckDelay = 20ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Test case where the ACK delay is equal to the RTT sample.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, RttSampleAckDelayEqual) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    ASSERT_FALSE(this->getTransport()
                     ->writeChain(streamId, IOBuf::copyBuffer("hello"), false)
                     .hasError());
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(std::nullopt, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      std::nullopt,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 25ms (25 ms)|     25ms      ||   25   |       0        | (both)
  {
    const auto rtt = 25ms;
    const auto ackDelay = 25ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    const auto expectedMinRttNoAckDelay = 0ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Test case where the ACK delay is greater than the RTT sample.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, RttSampleAckDelayGreater) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    ASSERT_FALSE(this->getTransport()
                     ->writeChain(streamId, IOBuf::copyBuffer("hello"), false)
                     .hasError());
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(std::nullopt, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      std::nullopt,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 25ms (26 ms)|     25ms      ||   25   |  std::nullopt   | (1)
  {
    const auto rtt = 25ms;
    const auto ackDelay = 26ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(std::nullopt, tInfo.maybeMinRttNoAckDelay); // unavailable
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Test case where the RTT sample has zero time based on socket RX timestamp.
 *
 * In this case, we should fallback to using system clock timestamp, and thus
 * should end up with a non-zero RTT.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, RttSampleZeroTime) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    auto typedTestWriteChain4 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(std::nullopt, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      std::nullopt,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 0ms (0 ms)  |     0ms       ||   >0   |      >0        | (both)
  {
    const auto rtt = 0ms;
    const auto ackDelay = 0ms;
    sendAndAckPacket(rtt, ackDelay);
    if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    } else if constexpr (std::is_base_of_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_LE(0ms, tInfo.maybeLrtt.value());
      EXPECT_GE(500ms, tInfo.maybeLrtt.value());
      EXPECT_EQ(0ms, tInfo.maybeLrttAckDelay.value());
      EXPECT_EQ(tInfo.maybeLrtt, tInfo.maybeMinRtt);
      EXPECT_EQ(tInfo.maybeMinRtt, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Verify vector used to store ACK events has no capacity if no pkts in flight.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    AckEventsNoAllocatedSpaceWhenNoOutstanding) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain5 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets),
      std::chrono::steady_clock::time_point());

  // should be no space (capacity) for ACK events
  EXPECT_EQ(0, this->getConn().lastProcessedAckEvents.capacity());

  this->destroyTransport();
}

/**
 * Verify vector used to store ACK events has no capacity if no pkts in flight.
 *
 * Two packets to give opportunity for packets in flight.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    AckEventsNoAllocatedSpaceWhenNoOutstandingTwoInFlight) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain6 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // write some more bytes into the same stream
  auto typedTestWriteChain7 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // should have sent another packet
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));

  // deliver an ACK for the first packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1),
      std::chrono::steady_clock::time_point());

  // should be space allocated for ACK events
  EXPECT_NE(0, this->getConn().lastProcessedAckEvents.capacity());

  // deliver an ACK for the second packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2),
      std::chrono::steady_clock::time_point());

  // should be no space (capacity) for ACK events
  EXPECT_EQ(0, this->getConn().lastProcessedAckEvents.capacity());

  this->destroyTransport();
}

/**
 * Verify vector used to store ACK events has no capacity if no pkts in flight.
 *
 * Two packets ACKed in reverse to give opportunity for packets in flight.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    AckEventsNoAllocatedSpaceWhenNoOutstandingTwoInFlightReverse) {
  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain8 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // write some more bytes into the same stream
  auto typedTestWriteChain9 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // should have sent another packet
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));

  // deliver an ACK for the second packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2),
      std::chrono::steady_clock::time_point());

  // should be space allocated for ACK events
  EXPECT_NE(0, this->getConn().lastProcessedAckEvents.capacity());

  // deliver an ACK for the first packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1),
      std::chrono::steady_clock::time_point());

  // should be no space (capacity) for ACK events
  EXPECT_EQ(0, this->getConn().lastProcessedAckEvents.capacity());

  this->destroyTransport();
}

/**
 * Verify PacketProcessor callbacks when sending a packet and its ack
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorSendSingleDataPacketWithAck) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
      .Times(1)
      .WillOnce(Invoke([&](auto& outstandingPacket) {
        EXPECT_EQ(3, outstandingPacket.metadata.writeCount);
      }));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain10 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets));
  quic::PacketNum lastPacketNum = maybeWrittenPackets->end;

  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent) {
        ASSERT_THAT(ackEvent, Not(IsNull()));
        if (ackEvent) {
          EXPECT_EQ(1, ackEvent->ackedPackets.size());
          EXPECT_EQ(44, ackEvent->ackedBytes);
          EXPECT_EQ(44, ackEvent->totalBytesAcked);
          EXPECT_EQ(
              this->getNonConstConn().lossState.totalBytesAcked,
              ackEvent->totalBytesAcked);
          EXPECT_EQ(lastPacketNum, ackEvent->largestAckedPacket);
          EXPECT_EQ(lastPacketNum, ackEvent->largestNewlyAckedPacket);
        }
      }));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets),
      std::chrono::steady_clock::time_point());
  this->destroyTransport();
}

/**
 * Verify PacketProcessor send and ACK callbacks.
 *
 * Send two packets and receive one ACK.
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorSendTwoDataPacketsWithAck) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
      .Times(2)
      .WillOnce(Invoke([&](auto& outstandingPacket) {
        EXPECT_EQ(3, outstandingPacket.metadata.writeCount);
      }))
      .WillOnce(Invoke([&](auto& outstandingPacket) {
        EXPECT_EQ(4, outstandingPacket.metadata.writeCount);
      }));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain11 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain12 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // should have sent two packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets2->end;
  EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);

  EXPECT_CALL(*rawPacketProcessor, onPacketAck(_))
      .Times(1)
      .WillOnce(Invoke([&](auto ackEvent) {
        ASSERT_THAT(ackEvent, Not(IsNull()));
        if (ackEvent) {
          EXPECT_EQ(2, ackEvent->ackedPackets.size());
          EXPECT_EQ(2 * 44, ackEvent->ackedBytes);
          EXPECT_EQ(2 * 44, ackEvent->totalBytesAcked);
          EXPECT_EQ(
              this->getNonConstConn().lossState.totalBytesAcked,
              ackEvent->totalBytesAcked);
          EXPECT_EQ(lastPacketNum, ackEvent->largestAckedPacket);
          EXPECT_EQ(lastPacketNum, ackEvent->largestNewlyAckedPacket);
        }
      }));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(this->buildAckPacketForSentAppDataPackets(
      std::vector<Optional<typename TestFixture::NewOutstandingPacketInterval>>{
          maybeWrittenPackets1, maybeWrittenPackets2}));
  this->destroyTransport();
}

/**
 * Verify app limited time tracking and annotation.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, TotalAppLimitedTime) {
  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // prevent packets from being marked as lost for at least 100ms, regardless
  // of the RTT measured by the test
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      100000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  // install StaticCwndCongestionController
  const auto cwndInBytes = 7000;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          this->getNonConstConn(),
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  // install PacketProcessor
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  // write 1700 bytes to stream to generate two packets back to back
  // both packets should have the same app limited time
  auto firstPacketTotalAppLimitedTimeUsecs = 0us;
  {
    EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
        .Times(2)
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(3, outstandingPacket.metadata.writeCount);
          EXPECT_NE(0us, outstandingPacket.metadata.totalAppLimitedTimeUsecs);
          firstPacketTotalAppLimitedTimeUsecs =
              outstandingPacket.metadata.totalAppLimitedTimeUsecs;
        }))
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(3, outstandingPacket.metadata.writeCount);
          EXPECT_EQ(
              firstPacketTotalAppLimitedTimeUsecs,
              outstandingPacket.metadata.totalAppLimitedTimeUsecs);
        }));

    const auto bufLength = 1700;
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain13 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets1 = this->loopForWrites();

    // should have sent two packets
    ASSERT_TRUE(maybeWrittenPackets1.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets1->end;
    EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);
  }

  // next, we wait for 10ms to get 10ms (or more) of app limited time.
  //
  // TODO(bschlinker): We should accomplish this by advancing a mock clock, but
  // this will also require being able to mock the timers set up on the
  // EventBase so that they are aligned with the mock clock.
  //
  // A loss detection alarm was scheduled for the previous write but even if
  // the machine running this test is slow, the following operation should be
  // executed before the loss alarm given that we've inflated the loss timeout
  // so that the alarm timeout is >= 100ms
  std::this_thread::sleep_for(10ms);

  // write 10000 bytes to stream to generate multiple packets back to back
  // not all will be sent at once because our CWND is only 7000 bytes, and
  // we already used 1700 bytes+ in previous send
  //
  // when (eventually) sent, all packets should have
  //   - the same app limited time
  //   - app limited time >= 10ms + firstPacketTotalAppLimitedTimeUsecs
  auto thirdPacketTotalAppLimitedTimeUsecs = 0us;
  {
    EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
        .Times(4)
        .WillOnce(Invoke(
            [&firstPacketTotalAppLimitedTimeUsecs,
             &thirdPacketTotalAppLimitedTimeUsecs](auto& outstandingPacket) {
              EXPECT_EQ(4, outstandingPacket.metadata.writeCount);
              EXPECT_LE(
                  firstPacketTotalAppLimitedTimeUsecs + 10ms,
                  outstandingPacket.metadata.totalAppLimitedTimeUsecs);
              thirdPacketTotalAppLimitedTimeUsecs =
                  outstandingPacket.metadata.totalAppLimitedTimeUsecs;
            }))
        .WillRepeatedly(Invoke(
            [&thirdPacketTotalAppLimitedTimeUsecs](auto& outstandingPacket) {
              EXPECT_EQ(
                  thirdPacketTotalAppLimitedTimeUsecs,
                  outstandingPacket.metadata.totalAppLimitedTimeUsecs);
            }));

    const auto bufLength = 10000;
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain14 = this->getTransport()->writeChain(
        streamId, std::move(buf), false /* eof */);

    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent four or five packets
    //
    // we allow five packets in the case where a loss detection alarm fires and
    // probe packets are sent (would only happen if test execution is slow)
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    const auto packetsSent = lastPacketNum - firstPacketNum + 1;

    EXPECT_THAT(packetsSent, AnyOf(Eq(4), Eq(5)));
  }

  // deliver an ACK for all of the outstanding packets
  this->ackAllOutstandingPackets();

  // after the ACK, we'll be able to send the rest of the data
  // all sent packets should have the same app limited time as packet #3
  //
  // regardless of whether we sent four or five packets above, we will end up
  // sending three packets here, as the amount of outstanding data remains the
  // same (when we send probe packets, two packets contain same new data)
  {
    EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
        .Times(3)
        .WillRepeatedly(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(
              thirdPacketTotalAppLimitedTimeUsecs,
              outstandingPacket.metadata.totalAppLimitedTimeUsecs);
        }));

    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);
  }

  // deliver an ACK for all of the outstanding packets
  this->ackAllOutstandingPackets();

  // now we're going to be application limited again for 10ms (or more)
  // there's no packets in flight, so no need to worry about loss detection
  std::this_thread::sleep_for(10ms);

  // finally, write 1700 bytes again, and verify we see a new app limited time
  {
    auto penultimatePacketTotalAppLimitedTimeUsecs = 0us;
    EXPECT_CALL(*rawPacketProcessor, onPacketSent(_))
        .Times(2)
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_LE(
              thirdPacketTotalAppLimitedTimeUsecs + 10ms,
              outstandingPacket.metadata.totalAppLimitedTimeUsecs);
          penultimatePacketTotalAppLimitedTimeUsecs =
              outstandingPacket.metadata.totalAppLimitedTimeUsecs;
        }))
        .WillOnce(Invoke([&](auto& outstandingPacket) {
          EXPECT_EQ(
              penultimatePacketTotalAppLimitedTimeUsecs,
              outstandingPacket.metadata.totalAppLimitedTimeUsecs);
        }));

    const auto bufLength = 1700;
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain15 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets1 = this->loopForWrites();

    // should have sent two packets
    ASSERT_TRUE(maybeWrittenPackets1.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets1->end;
    EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

/**
 * Verify PacketProcessor prewrite requests are collected
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorPrewriteRequestQueried) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // First packet processor
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));
  EXPECT_CALL(*rawPacketProcessor, prewrite()).Times(1).WillOnce([]() {
    PacketProcessor::PrewriteRequest req;
    req.cmsgs = {{{IPPROTO_IPV6, IPV6_HOPLIMIT}, 255}};
    return req;
  });

  // Second packet processor
  auto mockPacketProcessor2 = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor2 = mockPacketProcessor2.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor2));

  EXPECT_CALL(*rawPacketProcessor2, prewrite()).Times(1).WillOnce([]() {
    PacketProcessor::PrewriteRequest req;
    req.cmsgs = {{{IPPROTO_IPV6, IPV6_DONTFRAG}, 1}};
    return req;
  });

  // Third packet processor whose cmsgs will not be applied because priority is
  // given to the cmsg value from the second one.
  auto mockPacketProcessor3 = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor3 = mockPacketProcessor3.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor3));

  EXPECT_CALL(*rawPacketProcessor3, prewrite()).Times(1).WillOnce([]() {
    PacketProcessor::PrewriteRequest req;
    req.cmsgs = {{{IPPROTO_IPV6, IPV6_DONTFRAG}, 0}};
    return req;
  });

  auto streamId = this->getTransport()->createBidirectionalStream().value();
  const auto bufLength = 1000;
  auto buf = buildRandomInputData(bufLength);
  auto typedTestWriteChain16 =
      this->getTransport()->writeChain(streamId, std::move(buf), false);
  this->loopForWrites();
  ASSERT_FALSE(this->getConn().outstandings.packets.empty());

  auto pkt = this->getConn().outstandings.packets.rbegin();
  EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
  this->destroyTransport();
}

/**
 * Verify PacketProcessor prewrite requests apply to each write
 * and are honored for each packet
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    PacketProcessorPrewriteRequestMultiple) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // Packet processor
  auto mockPacketProcessor = std::make_unique<MockPacketProcessor>();
  auto rawPacketProcessor = mockPacketProcessor.get();
  this->getNonConstConn().packetProcessors.push_back(
      std::move(mockPacketProcessor));

  auto packetsSent = 0;
  {
    // Send two packets with the same marking
    EXPECT_CALL(*rawPacketProcessor, prewrite()).Times(1).WillOnce([]() {
      PacketProcessor::PrewriteRequest req;
      req.cmsgs = {{{IPPROTO_IPV6, IPV6_HOPLIMIT}, 255}};
      return req;
    });
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    const auto bufLength = 1700; // Two packets
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain17 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    this->loopForWrites();
    packetsSent += 2;
    ASSERT_EQ(this->getConn().outstandings.packets.size(), packetsSent);

    // Verify both packets are marked
    auto pkt = this->getConn().outstandings.packets.rbegin();
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
    pkt++;
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
  }

  {
    // Send two packets with no marking
    EXPECT_CALL(*rawPacketProcessor, prewrite()).Times(1).WillOnce([]() {
      return std::nullopt;
    });
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    const auto bufLength = 1700; // Two packets
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain18 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    this->loopForWrites();
    packetsSent += 2;
    ASSERT_EQ(this->getConn().outstandings.packets.size(), packetsSent);

    // Verify the last two packets have no marks
    auto pkt = this->getConn().outstandings.packets.rbegin();
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::NONE);
    pkt++;
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::NONE);
  }

  {
    // Send two packets with the same marking
    EXPECT_CALL(*rawPacketProcessor, prewrite()).Times(1).WillOnce([]() {
      PacketProcessor::PrewriteRequest req;
      req.cmsgs = {{{IPPROTO_IPV6, IPV6_HOPLIMIT}, 255}};
      return req;
    });
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    const auto bufLength = 1700; // Two packets
    auto buf = buildRandomInputData(bufLength);
    auto typedTestWriteChain19 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    this->loopForWrites();
    packetsSent += 2;
    ASSERT_EQ(this->getConn().outstandings.packets.size(), packetsSent);

    // Verify the last two packets are marked
    auto pkt = this->getConn().outstandings.packets.rbegin();
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
    pkt++;
    EXPECT_EQ(pkt->metadata.mark, OutstandingPacketMark::TTLD);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StreamAckedIntervalsDeliveryCallbacks) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto data1 = IOBuf::copyBuffer("hello");
  auto typedTestWriteChain20 =
      this->getTransport()->writeChain(streamId, data1->clone(), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto data2 = IOBuf::copyBuffer("world");
  auto typedTestWriteChain21 =
      this->getTransport()->writeChain(streamId, data2->clone(), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  data1->appendToChain(std::move(data2));
  auto combined = std::move(data1);

  // should have sent two packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets2->end;
  EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);

  MockDeliveryCallback cb;
  for (uint64_t offset = 0; offset < combined->computeChainDataLength();
       offset++) {
    auto typedTestRegisterDelivery1 =
        this->getTransport()->registerDeliveryCallback(streamId, offset, &cb);
    EXPECT_CALL(cb, onDeliveryAck(streamId, offset, _)).Times(1);
  }
  auto typedTestRegisterDelivery2 =
      this->getTransport()->registerDeliveryCallback(
          streamId, combined->computeChainDataLength(), &cb);
  EXPECT_CALL(
      cb, onDeliveryAck(streamId, combined->computeChainDataLength(), _))
      .Times(0);
  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(this->buildAckPacketForSentAppDataPackets(
      std::vector<Optional<typename TestFixture::NewOutstandingPacketInterval>>{
          maybeWrittenPackets1, maybeWrittenPackets2}));
  auto streamExpected =
      this->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  EXPECT_FALSE(stream->ackedIntervals.empty());
  EXPECT_EQ(stream->ackedIntervals.size(), 1);
  EXPECT_EQ(stream->ackedIntervals.front().start, 0);
  // The largest ACKed offset is the size of the stream data - 1
  EXPECT_EQ(
      stream->ackedIntervals.front().end,
      combined->computeChainDataLength() - 1);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StreamAckedIntervalsDeliveryCallbacksFinOnly) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain22 =
      this->getTransport()->writeChain(streamId, nullptr, true);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  MockDeliveryCallback cb;
  auto typedTestRegisterDelivery3 =
      this->getTransport()->registerDeliveryCallback(streamId, 0, &cb);
  EXPECT_CALL(cb, onDeliveryAck(streamId, 0, _));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));
  auto streamExpected =
      this->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  EXPECT_FALSE(stream->ackedIntervals.empty());
  EXPECT_EQ(stream->ackedIntervals.size(), 1);
  EXPECT_EQ(stream->ackedIntervals.front().start, 0);
  EXPECT_EQ(stream->ackedIntervals.front().end, 0);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    StreamAckedIntervalsDeliveryCallbacksSingleByteNoFin) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain23 = this->getTransport()->writeChain(
      streamId, folly::IOBuf::copyBuffer("a"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  MockDeliveryCallback cb;
  auto typedTestRegisterDelivery4 =
      this->getTransport()->registerDeliveryCallback(streamId, 0, &cb);
  EXPECT_CALL(cb, onDeliveryAck(streamId, 0, _));

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1),
      std::chrono::steady_clock::time_point());
  auto streamExpected =
      this->getNonConstConn().streamManager->getStream(streamId);
  ASSERT_FALSE(streamExpected.hasError());
  auto stream = streamExpected.value();
  EXPECT_FALSE(stream->ackedIntervals.empty());
  EXPECT_EQ(stream->ackedIntervals.size(), 1);
  EXPECT_EQ(stream->ackedIntervals.front().start, 0);
  EXPECT_EQ(stream->ackedIntervals.front().end, 0);
  this->destroyTransport();
}

/**
 * Handle a successful incoming key update. This verifies that the write phase
 * is advanced whenever a key update is detected.
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, HandleIncomingKeyUpdate) {
  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send a packet in the current phase
    auto typedTestWriteChain24 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);
  }

  {
    // Receive a packet in the current phase. Both read and writer ciphers
    // should remain in phase zero
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // Receive a packet in the next phase. This is a key update that should
    // update both the read and write ciphers to phase one.
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello3"), ProtectionType::KeyPhaseOne));
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);

    // No packets have been written in phase one yet.
    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);
  }

  {
    // Send a packet. The connection should stay in phase one and increment the
    // number of packets written in this phase.
    auto typedTestWriteChain25 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello4"), false);
    this->loopForWrites();
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);
  }

  {
    // Receive an out-of-order packet in the previous phase. It should increment
    // total number of bytes received but the current phase shouldn't change.
    auto tmpData = IOBuf::copyBuffer("hello out of order");
    auto pktBuf = quic::test::packetToBuf(createStreamPacket(
        this->getSrcConnectionId(),
        this->getDstConnectionId(),
        this->peerPacketNumStore.nextAppDataPacketNum - 2, // older packet
        streamId,
        *tmpData /* stream data */,
        0 /* cipherOverhead */,
        0 /* largest acked */,
        // // the following technically ignores lost ACK packets from peer, but
        // // should meet the needs of the majority of tests...
        // getConn().ackStates.appDataAckState.largestAckedByPeer.value_or(0),
        std::nullopt /* longHeaderOverride */,
        false /* eof */,
        ProtectionType::KeyPhaseZero));
    pktBuf->coalesce();

    auto receivedBytesBeforePacket = this->getConn().lossState.totalBytesRecvd;

    this->deliverPacket(std::move(pktBuf));
    // Read and Write phases don't advance.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);

    // The bytes from the old packet were received successfully.
    EXPECT_GT(
        this->getConn().lossState.totalBytesRecvd, receivedBytesBeforePacket);
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

/**
 * Initiate a key update - Successful attempt
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, InitiateKeyUpdateSuccess) {
  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send and receive a packet in the current phase
    auto typedTestWriteChain26 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));

    // Both read and writer ciphers should be in phase zero.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // Force initiate a key update
    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    conn.transportSettings.keyUpdatePacketCountInterval =
        numberOfWrittenPacketsInPhase;
    // Only do the period updates.
    conn.transportSettings.firstKeyUpdatePacketCount.reset();

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain27 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    this->loopForWrites();

    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);

    // Both read and writer ciphers should have advanced to phase one.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
  }

  {
    // Another key update should not be allowed until this one is verified
    QuicConnectionStateBase& conn = this->getNonConstConn();
    EXPECT_FALSE(conn.readCodec->canInitiateKeyUpdate());
    EXPECT_FALSE(conn.readCodec->advanceOneRttReadPhase());
  }

  {
    // Receiving a packet in the new phase verifies the pending key update
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello4"), ProtectionType::KeyPhaseOne));

    EXPECT_TRUE(this->getConn().readCodec->canInitiateKeyUpdate());
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

/**
 * Initiate a key update - Failed attempt
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, InitiateKeyUpdateFailure) {
  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send and receive a packet in the current phase
    auto typedTestWriteChain28 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));

    // Both read and writer ciphers should be in phase zero.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // Force initiate a key update.
    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    conn.transportSettings.keyUpdatePacketCountInterval =
        numberOfWrittenPacketsInPhase;
    // Only do the period updates.
    conn.transportSettings.firstKeyUpdatePacketCount.reset();

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain29 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    ASSERT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));
    // const auto packetSentTime =
    //     CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);

    // Both read and writer ciphers should have advanced to phase one.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
  }

  {
    // Send a packet in the new phase.
    auto typedTestWriteChain30 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    ASSERT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    // The peer acks the new packet in the old phase. This is a CRYPTO_ERROR.
    auto oldestOutstandingPkt =
        this->getOldestOutstandingPacket(PacketNumberSpace::AppData);
    auto newestOutstandingPkt =
        this->getNewestOutstandingPacket(PacketNumberSpace::AppData);
    quic::AckBlocks acks = {
        {oldestOutstandingPkt->packet.header.getPacketSequenceNum(),
         newestOutstandingPkt->packet.header.getPacketSequenceNum()}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(acks)
            .setAckDelay(0us)
            .setShortHeaderProtectionType(ProtectionType::KeyPhaseZero)
            .build());
    buf->coalesce();

    // Crypto error: Packet with key update was acked in the wrong phase
    EXPECT_THROW(this->deliverPacket(std::move(buf)), std::runtime_error);
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

/**
 * Initiate the first key update - Successful attempt
 */
TYPED_TEST(QuicTypedTransportAfterStartTest, InitiateFirstKeyUpdateSuccess) {
  // Use QUIC_V1 for the server since MVFST has special handling to accommodate
  // older client versions without key update support. That behavior is covered
  // in another test
  if (this->getConn().nodeType == QuicNodeType::Server) {
    this->getNonConstConn().version = QuicVersion::QUIC_V1;
  }

  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send and receive a packet in the current phase
    auto typedTestWriteChain31 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));

    // Both read and writer ciphers should be in phase zero.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // Force initiate a key update through the firstKeyUpdatePacketCount
    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    // Trigger this update as a first update
    conn.transportSettings.firstKeyUpdatePacketCount =
        numberOfWrittenPacketsInPhase;
    // Periodic interval is high enough not to be triggered
    conn.transportSettings.keyUpdatePacketCountInterval =
        kDefaultKeyUpdatePacketCountInterval;

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain32 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    this->loopForWrites();

    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);

    // Both read and writer ciphers should have advanced to phase one.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
  }

  {
    // Another key update should not be allowed until this one is verified
    QuicConnectionStateBase& conn = this->getNonConstConn();
    EXPECT_FALSE(conn.readCodec->canInitiateKeyUpdate());
    EXPECT_FALSE(conn.readCodec->advanceOneRttReadPhase());
  }

  {
    // Receiving a packet in the new phase verifies the pending key update
    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello4"), ProtectionType::KeyPhaseOne));

    EXPECT_TRUE(this->getConn().readCodec->canInitiateKeyUpdate());
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

/**
 * As a server, do not initiate key updates for QuicVersion::MVFST unless the
 * client has performed a key update.
 * (Old versions of MVFST did not support key updates)
 */
TYPED_TEST(
    QuicTypedTransportAfterStartTest,
    ServerInitiateKeyUpdateForMvfstClient) {
  if (this->getConn().nodeType != QuicNodeType::Server) {
    // This test is for the server behavior only
    return;
  }

  ASSERT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  this->getNonConstConn().version = QuicVersion::MVFST;

  auto numberOfWrittenPacketsInPhase =
      this->getConn().oneRttWritePacketsSentInCurrentPhase;

  auto streamId = this->getTransport()->createBidirectionalStream().value();

  {
    // Send and receive a packet in the current phase
    auto typedTestWriteChain33 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    this->loopForWrites();
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    this->deliverPacket(this->buildPeerPacketWithStreamData(
        streamId, IOBuf::copyBuffer("hello2"), ProtectionType::KeyPhaseZero));

    // Both read and writer ciphers should be in phase zero.
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  {
    // First key update is due but it shouldn't trigger one because connection
    // is for QuicVersion::MVFST and the peer hasn't initiated a key update yet

    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    // Trigger this update as a first update
    conn.transportSettings.firstKeyUpdatePacketCount =
        numberOfWrittenPacketsInPhase;
    // Periodic interval is high enough not to be triggered
    conn.transportSettings.keyUpdatePacketCountInterval =
        kDefaultKeyUpdatePacketCountInterval;

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain34 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    this->loopForWrites();

    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        ++numberOfWrittenPacketsInPhase);

    // Both read and writer ciphers should still be at Phase Zero
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseZero);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseZero);
  }

  // Clear firstKeyUpdatePacketCount to indicate that a key update was performed
  // by the peer.
  this->getNonConstConn().transportSettings.firstKeyUpdatePacketCount.reset();

  {
    // Now that the peer had initiated a key update, the server can trigger one
    // too.
    QuicConnectionStateBase& conn = this->getNonConstConn();
    conn.transportSettings.initiateKeyUpdate = true;
    // Indicate that a regular update is due
    conn.transportSettings.keyUpdatePacketCountInterval =
        numberOfWrittenPacketsInPhase;

    // A key update should be triggered after this write is completed.
    auto typedTestWriteChain35 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello3"), false);
    this->loopForWrites();

    numberOfWrittenPacketsInPhase = 0;
    EXPECT_EQ(
        this->getConn().oneRttWritePacketsSentInCurrentPhase,
        numberOfWrittenPacketsInPhase);

    // Read and writer ciphers should advance to Key Phase One
    EXPECT_EQ(
        this->getConn().readCodec->getCurrentOneRttReadPhase(),
        ProtectionType::KeyPhaseOne);
    EXPECT_EQ(this->getConn().oneRttWritePhase, ProtectionType::KeyPhaseOne);
  }

  this->getNonConstConn().outstandings.reset();

  this->destroyTransport();
}

template <typename T>
struct AckEventMatcherBuilder {
  using Builder = AckEventMatcherBuilder;

  Builder&& setExpectedAckedIntervals(
      std::vector<
          typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
          expectedAckedIntervals) {
    maybeExpectedAckedIntervals = std::move(expectedAckedIntervals);
    return std::move(*this);
  }

  Builder&& setExpectedAckedIntervals(
      std::vector<Optional<
          typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>>
          expectedAckedIntervalsOpt) {
    std::vector<
        typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
        expectedAckedIntervals;
    for (const auto& maybeInterval : expectedAckedIntervalsOpt) {
      CHECK(maybeInterval.has_value());
      expectedAckedIntervals.push_back(maybeInterval.value());
    }
    maybeExpectedAckedIntervals = std::move(expectedAckedIntervals);
    return std::move(*this);
  }

  Builder&& setExpectedNumAckedPackets(const uint64_t expectedNumAckedPackets) {
    maybeExpectedNumAckedPackets = expectedNumAckedPackets;
    return std::move(*this);
  }

  Builder&& setAckTime(TimePoint ackTime) {
    maybeAckTime = ackTime;
    return std::move(*this);
  }

  Builder&& setAckDelay(std::chrono::microseconds ackDelay) {
    maybeAckDelay = ackDelay;
    return std::move(*this);
  }

  Builder&& setLargestAckedPacket(quic::PacketNum largestAckedPacketIn) {
    maybeLargestAckedPacket = largestAckedPacketIn;
    return std::move(*this);
  }

  Builder&& setLargestNewlyAckedPacket(
      quic::PacketNum largestNewlyAckedPacketIn) {
    maybeLargestNewlyAckedPacket = largestNewlyAckedPacketIn;
    return std::move(*this);
  }

  Builder&& setRtt(const OptionalMicros& rttIn) {
    maybeRtt = rttIn;
    CHECK(!noRtt);
    return std::move(*this);
  }

  Builder&& setRttNoAckDelay(const OptionalMicros& rttNoAckDelayIn) {
    maybeRttNoAckDelay = rttNoAckDelayIn;
    CHECK(!noRtt);
    CHECK(!noRttWithNoAckDelay);
    return std::move(*this);
  }

  Builder&& setNoRtt() {
    noRtt = true;
    CHECK(!maybeRtt);
    CHECK(!maybeRttNoAckDelay);
    return std::move(*this);
  }

  Builder&& setNoRttWithNoAckDelay() {
    noRttWithNoAckDelay = true;
    CHECK(!maybeRttNoAckDelay);
    return std::move(*this);
  }

  auto build() && {
    CHECK(
        noRtt ||
        (maybeRtt.has_value() &&
         (noRttWithNoAckDelay || maybeRttNoAckDelay.has_value())));

    CHECK(maybeExpectedAckedIntervals.has_value());
    const auto& expectedAckedIntervals = *maybeExpectedAckedIntervals;
    CHECK_LT(0, expectedAckedIntervals.size());

    CHECK(maybeExpectedNumAckedPackets.has_value());
    const auto& expectedNumAckedPackets = *maybeExpectedNumAckedPackets;

    CHECK(maybeAckTime.has_value());
    const auto& ackTime = *maybeAckTime;

    CHECK(maybeAckDelay.has_value());
    const auto& ackDelay = *maybeAckDelay;

    CHECK(maybeLargestAckedPacket.has_value());
    const auto& largestAckedPacket = *maybeLargestAckedPacket;

    CHECK(maybeLargestNewlyAckedPacket.has_value());
    const auto& largestNewlyAckedPacket = *maybeLargestNewlyAckedPacket;

    // sanity check expectedNumAckedPackets and expectedAckedIntervals
    // reduces potential of error in test design
    {
      uint64_t expectedNumAckedPacketsFromIntervals = 0;
      std::vector<
          typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
          processedExpectedAckedIntervals;

      for (const auto& interval : expectedAckedIntervals) {
        CHECK_LE(interval.start, interval.end);
        CHECK_LE(0, interval.end);
        expectedNumAckedPacketsFromIntervals +=
            interval.end - interval.start + 1;

        // should not overlap with existing intervals
        for (const auto& processedInterval : processedExpectedAckedIntervals) {
          CHECK(
              processedInterval.end < interval.start ||
              processedInterval.start < interval.end);
        }

        processedExpectedAckedIntervals.push_back(interval);
      }
      CHECK_EQ(expectedNumAckedPacketsFromIntervals, expectedNumAckedPackets);
    }

    if constexpr (std::is_base_of_v<T, QuicClientTransportTestBase>) {
      return testing::Property(
          &quic::SocketObserverInterface::AcksProcessedEvent::getAckEvents,
          testing::ElementsAre(testing::AllOf(
              // ack time, adjusted ack time, RTT not supported for client now
              testing::Field(&quic::AckEvent::ackDelay, testing::Eq(ackDelay)),
              testing::Field(
                  &quic::AckEvent::largestAckedPacket,
                  testing::Eq(largestAckedPacket)),
              testing::Field(
                  &quic::AckEvent::largestNewlyAckedPacket,
                  testing::Eq(largestNewlyAckedPacket)),
              testing::Field(
                  &quic::AckEvent::ackedPackets,
                  testing::SizeIs(expectedNumAckedPackets)))));
    } else if constexpr (std::is_base_of_v<T, QuicServerTransportTestBase>) {
      return testing::Property(
          &quic::SocketObserverInterface::AcksProcessedEvent::getAckEvents,
          testing::ElementsAre(testing::AllOf(
              testing::Field(&quic::AckEvent::ackTime, testing::Eq(ackTime)),
              testing::Field(
                  &quic::AckEvent::adjustedAckTime,
                  testing::Eq(ackTime - ackDelay)),
              testing::Field(&quic::AckEvent::ackDelay, testing::Eq(ackDelay)),
              testing::Field(
                  &quic::AckEvent::largestAckedPacket,
                  testing::Eq(largestAckedPacket)),
              testing::Field(
                  &quic::AckEvent::largestNewlyAckedPacket,
                  testing::Eq(largestNewlyAckedPacket)),
              testing::Field(
                  &quic::AckEvent::ackedPackets,
                  testing::SizeIs(expectedNumAckedPackets)),
              testing::Field(&quic::AckEvent::rttSample, testing::Eq(maybeRtt)),
              testing::Field(
                  &quic::AckEvent::rttSampleNoAckDelay,
                  testing::Eq(maybeRttNoAckDelay)))));
    } else {
      FAIL(); // unhandled typed test
    }
  }

  explicit AckEventMatcherBuilder() = default;

  Optional<std::vector<
      typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>>
      maybeExpectedAckedIntervals;
  OptionalIntegral<uint64_t> maybeExpectedNumAckedPackets;
  Optional<TimePoint> maybeAckTime;
  OptionalMicros maybeAckDelay;
  OptionalIntegral<quic::PacketNum> maybeLargestAckedPacket;
  OptionalIntegral<quic::PacketNum> maybeLargestNewlyAckedPacket;
  OptionalMicros maybeRtt;
  OptionalMicros maybeRttNoAckDelay;
  bool noRtt{false};
  bool noRttWithNoAckDelay{false};
};

template <typename T>
struct ReceivedUdpPacketMatcherBuilder {
  using Builder = ReceivedUdpPacketMatcherBuilder;
  using Obj =
      quic::SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket;

  Builder&& setExpectedPacketReceiveTime(
      const TimePoint expectedPacketReceiveTime) {
    maybeExpectedPacketReceiveTime = expectedPacketReceiveTime;
    return std::move(*this);
  }

  Builder&& setExpectedPacketNumBytes(const uint64_t expectedPacketNumBytes) {
    maybeExpectedPacketNumBytes = expectedPacketNumBytes;
    return std::move(*this);
  }

  Builder&& setExpectedTosValue(const uint8_t expectedTosValue) {
    maybeExpectedTosValue = expectedTosValue;
    return std::move(*this);
  }

  auto build() && {
    CHECK(maybeExpectedPacketReceiveTime.has_value());
    const auto& packetReceiveTime = *maybeExpectedPacketReceiveTime;

    CHECK(maybeExpectedPacketNumBytes.has_value());
    const auto& packetNumBytes = *maybeExpectedPacketNumBytes;

    CHECK(maybeExpectedTosValue.has_value());
    const auto& packetTosValue = *maybeExpectedTosValue;

    if constexpr (std::is_base_of_v<T, QuicClientTransportTestBase>) {
      return testing::AllOf(
          // client does not currently support socket RX timestamps, so we
          // expect ts >= now() at time of matcher build
          testing::Field(
              &Obj::packetReceiveTime,
              testing::AnyOf(
                  testing::Eq(packetReceiveTime),
                  testing::Ge(TimePoint::clock::now()))),
          testing::Field(&Obj::packetNumBytes, testing::Eq(packetNumBytes)),
          testing::Field(&Obj::packetTos, testing::Eq(packetTosValue)));
    } else if constexpr (std::is_base_of_v<T, QuicServerTransportTestBase>) {
      return testing::AllOf(
          testing::Field(
              "packetReceiveTime",
              &Obj::packetReceiveTime,
              testing::Eq(packetReceiveTime)),
          testing::Field(
              "packetNumBytes",
              &Obj::packetNumBytes,
              testing::Eq(packetNumBytes)),
          testing::Field(
              "packetTos", &Obj::packetTos, testing::Eq(packetTosValue)));
    } else {
      FAIL(); // unhandled typed test
    }
  }

  explicit ReceivedUdpPacketMatcherBuilder() = default;

  Optional<TimePoint> maybeExpectedPacketReceiveTime;
  OptionalIntegral<uint64_t> maybeExpectedPacketNumBytes;
  Optional<uint8_t> maybeExpectedTosValue;
};

template <typename T>
class QuicTypedTransportTestForObservers : public QuicTypedTransportTest<T> {
 public:
  void SetUp() override {
    QuicTypedTransportTest<T>::SetUp();
  }

  auto getStreamEventMatcherOpt(
      const StreamId streamId,
      const StreamInitiator streamInitiator,
      const StreamDirectionality streamDirectionality) {
    return testing::AllOf(
        testing::Field(
            &quic::SocketObserverInterface::StreamEvent::streamId,
            testing::Eq(streamId)),
        testing::Field(
            &quic::SocketObserverInterface::StreamEvent::streamInitiator,
            testing::Eq(streamInitiator)),
        testing::Field(
            &quic::SocketObserverInterface::StreamEvent::streamDirectionality,
            testing::Eq(streamDirectionality)));
  }
};

template <typename T>
class QuicTypedTransportAfterStartTestForObservers
    : public QuicTypedTransportTestForObservers<T> {
 public:
  ~QuicTypedTransportAfterStartTestForObservers() override = default;

  void SetUp() override {
    QuicTypedTransportTestForObservers<T>::SetUp();
    QuicTypedTransportTestForObservers<T>::startTransport();
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportTestForObservers,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST_SUITE(
    QuicTypedTransportAfterStartTestForObservers,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST(QuicTypedTransportTestForObservers, AttachThenDetach) {
  this->startTransport();

  InSequence s;
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_EQ(0, transport->numObservers());
  EXPECT_THAT(transport->getObservers(), IsEmpty());

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_EQ(1, transport->numObservers());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  EXPECT_CALL(*observer, detached(transport));
  EXPECT_TRUE(transport->removeObserver(observer.get()));
  Mock::VerifyAndClearExpectations(observer.get());
  EXPECT_EQ(0, transport->numObservers());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseNoDrainNoErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = false;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError defaultError = QuicError(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{defaultError}))));
  EXPECT_CALL(*observer, closing(transport, _));
  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(observer.get());
  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
  Mock::VerifyAndClearExpectations(observer.get());
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseNoErrorDrainEnabled_DrainThenDestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = true;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError defaultError = QuicError(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{defaultError}))));
  transport->close(std::nullopt);

  // wait for the drain
  EXPECT_CALL(*observer, closing(transport, _));
  auto follyEvb = transport->getEventBase()
                      ->template getTypedEventBase<FollyQuicEventBase>()
                      ->getBackingEventBase();
  follyEvb->timer().scheduleTimeoutFn(
      [&] { transport->getEventBase()->terminateLoopSoon(); },
      folly::chrono::ceil<std::chrono::milliseconds>(
          1ms + kDrainFactor * calculatePTO(this->getConn())));
  transport->getEventBase()->loop();
  Mock::VerifyAndClearExpectations(observer.get());

  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseNoErrorDrainEnabled_DestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = true;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError defaultError = QuicError(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{defaultError}))));
  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(observer.get());

  // destroy transport without waiting for drain
  EXPECT_CALL(*observer, closing(transport, _));
  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseWithErrorDrainDisabled_DestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = false;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError testError = QuicError(
      QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
      std::string("testError"));
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{testError}))));
  EXPECT_CALL(*observer, closing(transport, _));
  transport->close(testError);
  Mock::VerifyAndClearExpectations(observer.get());

  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseWithErrorDrainEnabled_DestroyTransport) {
  auto transport = this->getTransport();
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = true;
    transport->setTransportSettings(transportSettings);
  }
  this->startTransport();

  InSequence s;
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError testError = QuicError(
      QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
      std::string("testError"));

  // because of the error, we won't wait for the drain despite it being enabled.
  EXPECT_CALL(
      *observer,
      closeStarted(
          transport,
          AllOf(
              // should not be equal to an empty event
              testing::Ne(
                  SocketObserverInterface::CloseStartedEvent{std::nullopt}),
              // should be equal to a populated event with default error
              testing::Eq(
                  SocketObserverInterface::CloseStartedEvent{testError}))));
  EXPECT_CALL(*observer, closing(transport, _));
  transport->close(testError);
  Mock::VerifyAndClearExpectations(observer.get());

  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedBiStream) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createBidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data, see a packet be written
  auto typedTestWriteChain36 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver ACK for first packet sent by local
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver a packet with stream data from the remote
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello2")));

  // local sends goodbye with EOF, gets the ACK
  auto typedTestWriteChain37 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("goodbye1"), true /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  // one more message from the peer, this time with EOF
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye2")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedBiStreamImmediateEofLocal) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createBidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data with EOF, see a packet be written
  auto typedTestWriteChain38 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), true /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver ACK for first packet sent by local
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver a packet with stream data from the remote
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello2")));

  // one more message from the peer, this time with EOF
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedBiStreamImmediateEofLocalRemote) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createBidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data with EOF, see a packet be written
  auto typedTestWriteChain39 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), true /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver ACK for first packet sent by local
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver a packet with stream data from the remote with an EOF
  // stream should close on arrival of packet from remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello2")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedUniStreamRstSentThenAcked) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalUnidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Unidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createUnidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data, see a packet be written
  auto typedTestWriteChain40 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // local writes a reset
  const auto result = this->getTransport()->resetStream(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(result.hasError());
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  // //
  // this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for the data sent in first write
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver ACK for the reset packet sent by local
  // stream should close on arrival of ACK
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Unidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsLocalOpenedUniStreamRstSentThenAckedBytesInFlight) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalUnidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Unidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createUnidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data, see a packet be written
  auto typedTestWriteChain41 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // local writes a reset
  const auto result = this->getTransport()->resetStream(
      streamId, GenericApplicationErrorCode::UNKNOWN);
  ASSERT_FALSE(result.hasError());
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  // //
  // this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for the reset packet sent by local
  // stream should close on arrival of ACK
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Unidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStream) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, gets the ACK
  auto typedTestWriteChain42 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // one more message from the peer, this time with EOF
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye1")));

  // local sends goodbye with EOF too, get the ACK, stream should close
  auto typedTestWriteChain43 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("goodbye2"), true /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamImmediateEofRemote) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data + EOF from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // send some stream data, see a packet be written, get the ACK
  auto typedTestWriteChain44 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // local sends goodbye with EOF too, get the ACK, stream should close
  auto typedTestWriteChain45 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("goodbye"), true /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamImmediateEofLocalRemote) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data + EOF from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // send some stream data with EOF, see a packet be written, get the ACK
  auto typedTestWriteChain46 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), true /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // stream should close on arrival of ACK
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamStopSendingPlusRstTriggersRst) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, gets the ACK
  auto typedTestWriteChain47 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver reset from remote
  this->deliverPacket(
      this->buildPeerPacketWithRstStreamFrame(streamId, 6 /* offset */));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for rst packet, then stream should close
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamStopSendingPlusRstTriggersRstBytesInFlight) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, ACK not received
  auto typedTestWriteChain48 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver reset from remote
  this->deliverPacket(
      this->buildPeerPacketWithRstStreamFrame(streamId, 6 /* offset */));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for rst packet, then stream should close
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsPeerOpenedBiStreamImmediateEorStopSendingTriggersRstBytesInFlight) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, ACK not received
  auto typedTestWriteChain49 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for rst packet, then stream should close
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    StreamEventsAckEventsPeerOpenedBiStreamImmediateEorStopSendingTriggersRstBytesInFlightPartiallyAckedAfterRstSent) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written
  auto typedTestWriteChain50 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // local sends some more stream data, see another packet be written
  auto typedTestWriteChain51 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacketNoWrites(
      this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeWrittenPackets3 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets3));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for first packet
  // despite reset being sent, observer should still be notified of ACK
  {
    ASSERT_TRUE(maybeWrittenPackets1.has_value());
    const auto& writtenPackets1 = maybeWrittenPackets1.value();
    const auto sentTime = writtenPackets1.sentTime;
    const auto ackRecvTime = sentTime + 27ms;
    const auto ackDelay = 0us;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals(
                std::vector<typename TestFixture::NewOutstandingPacketInterval>{
                    writtenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(writtenPackets1.end)
            .setLargestNewlyAckedPacket(writtenPackets1.end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*obs1, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*obs2, acksProcessed(transport, matcher));
    EXPECT_CALL(*obs3, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {writtenPackets1.start, writtenPackets1.end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver ACK for rst packet, then stream should close
  {
    ASSERT_TRUE(maybeWrittenPackets3.has_value());
    const auto& writtenPackets3 = maybeWrittenPackets3.value();
    const auto sentTime = writtenPackets3.sentTime;
    const auto ackRecvTime = sentTime + 27ms;
    const auto ackDelay = 0us;
    const auto ackEventMatcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals(
                std::vector<typename TestFixture::NewOutstandingPacketInterval>{
                    writtenPackets3})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(writtenPackets3.end)
            .setLargestNewlyAckedPacket(writtenPackets3.end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*obs1, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*obs2, acksProcessed(transport, ackEventMatcher));
    EXPECT_CALL(*obs3, acksProcessed(transport, ackEventMatcher));

    const auto streamEventMatcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, streamEventMatcher));
    EXPECT_CALL(*obs3, streamClosed(transport, streamEventMatcher));

    const quic::AckBlocks ackBlocks = {
        {writtenPackets3.start, writtenPackets3.end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketSent) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // install StaticCwndCongestionController
  const auto cwndInBytes = 10000;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          this->getNonConstConn(),
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // string to write
  const std::string str1 = "hello";
  const auto strLength = str1.length();

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // setup matchers
  {
    writeCount++; // write count will be incremented

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(
        *obs2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *obs3,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(cwndInBytes - strLength))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(strLength)));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(cwndInBytes - strLength))));

    EXPECT_CALL(*obs1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
    EXPECT_CALL(*obs3, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
  }

  // open a stream and write string
  {
    auto typedTestWriteChain52 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer(str1), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketSentInvokeForEach) {
  struct InvokedOutstandingPacketFields {
    PacketNumberSpace pnSpace{PacketNumberSpace::Initial};
    PacketNum packetNum{0};
  };

  InSequence s;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsWrittenEvents);
  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(obs1.get()));

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // first write of a single packet worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto typedTestWriteChain53 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(::testing::AllOf(
            ::testing::Field(
                &InvokedOutstandingPacketFields::pnSpace,
                PacketNumberSpace::AppData),
            ::testing::Field(
                &InvokedOutstandingPacketFields::packetNum, firstPacketNum))));
  }

  // second write of a single packet worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto typedTestWriteChain54 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("goodbye"), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(::testing::AllOf(
            ::testing::Field(
                &InvokedOutstandingPacketFields::pnSpace,
                PacketNumberSpace::AppData),
            ::testing::Field(
                &InvokedOutstandingPacketFields::packetNum, firstPacketNum))));
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingMultiplePacketsSentInvokeForEach) {
  struct InvokedOutstandingPacketFields {
    PacketNumberSpace pnSpace{PacketNumberSpace::Initial};
    PacketNum packetNum{0};
  };

  InSequence s;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsWrittenEvents);
  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(obs1.get()));

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // first write of two packets worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto buf = buildRandomInputData(2000 /* bufLength */);
    auto typedTestWriteChain55 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent two packets
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(2, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    firstPacketNum)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    lastPacketNum))));
  }

  // second write of a single packet worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto typedTestWriteChain56 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("goodbye"), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(::testing::AllOf(
            ::testing::Field(
                &InvokedOutstandingPacketFields::pnSpace,
                PacketNumberSpace::AppData),
            ::testing::Field(
                &InvokedOutstandingPacketFields::packetNum, firstPacketNum))));
  }

  // third write of three packets worth of data
  {
    // capture invoked packets
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    EXPECT_CALL(*obs1, packetsWritten(_, _))
        .WillOnce([&outstandingPacketsDuringInvoke](
                      const auto& /* socket */, const auto& event) {
          event.invokeForEachNewOutstandingPacketOrdered(
              [&outstandingPacketsDuringInvoke](
                  const OutstandingPacketWrapper& outstandingPacket) {
                outstandingPacketsDuringInvoke.emplace_back(
                    InvokedOutstandingPacketFields{
                        outstandingPacket.packet.header.getPacketNumberSpace(),
                        outstandingPacket.packet.header
                            .getPacketSequenceNum()});
              });
        });

    // open a stream and write string
    auto buf = buildRandomInputData(3000 /* bufLength */);
    auto typedTestWriteChain57 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent three packets
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);

    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    firstPacketNum)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    firstPacketNum + 1)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum,
                    lastPacketNum))));
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketSentWroteMoreThanCwnd) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // install StaticCwndCongestionController with a CWND < MSS
  const auto cwndInBytes = 800;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          this->getNonConstConn(),
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // we're going to write 1000 bytes with a smaller CWND
  // because MSS > CWND, we're going to overshoot
  const auto bufLength = 1000;
  auto buf = buildRandomInputData(bufLength);
  EXPECT_GT(bufLength, cwndInBytes);

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // setup matchers
  {
    writeCount++; // write count will be incremented

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(
        *obs2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *obs3,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(0))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce(), expect overshoot CWND
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::AllOf(testing::Gt(bufLength), testing::Gt(cwndInBytes))));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
  }

  // open a stream and write string
  {
    auto typedTestWriteChain58 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  // TODO(bschlinker): Check for appRateLimited on ACK so that we get an
  // appRateLimited signal when the outstanding packet is ACKed.

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketsSentCwndLimited) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // install StaticCwndCongestionController
  const auto cwndInBytes = 7000;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          this->getNonConstConn(),
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // we're going to write 10000 bytes with a CWND of 7000
  const auto bufLength = 10000;
  auto buf = buildRandomInputData(bufLength);
  EXPECT_EQ(7000, cwndInBytes);

  // setup matchers for first write, write the entire buffer, trigger loop
  // we will NOT become app limited after this write, as CWND limited
  {
    writeCount++; // write count will be incremented
    const auto packetsExpectedWritten = 5;

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(
        *obs2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *obs3,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(0))), // CWND exhausted
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Ge(cwndInBytes))); // full CWND written
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    auto typedTestWriteChain59 =
        this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // make sure we wrote
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(packetsExpectedWritten, lastPacketNum - firstPacketNum + 1);
  }

  // ACK all outstanding packets
  this->ackAllOutstandingPackets();

  // setup matchers for second write, then trigger loop
  // we will become app limited after this write
  {
    writeCount++; // write count will be incremented
    const auto packetsExpectedWritten = 2;

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Lt(cwndInBytes)));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
    EXPECT_CALL(*obs3, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo(),
                   cwndInBytes = cwndInBytes](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });

    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(packetsExpectedWritten, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    WriteEventsOutstandingPacketSentNoCongestionController) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // remove congestion controller
  this->getNonConstConn().congestionController = nullptr;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // string to write
  const std::string str1 = "hello";
  const auto strLength = str1.length();

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // setup matchers
  {
    writeCount++; // write count will be incremented

    // no congestion controller == no startWritingFromAppLimited events
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(*obs3, startWritingFromAppLimited(_, _)).Times(0);

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(Optional<uint64_t>(std::nullopt))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(Optional<uint64_t>(std::nullopt))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(strLength)));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // no congestion controller == no appRateLimited events
    EXPECT_CALL(*obs1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs3, appRateLimited(_, _)).Times(0);
  }

  // open a stream and write str1
  {
    auto typedTestWriteChain60 = this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer(str1), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsOutstandingPacketSentThenAckedNoAckDelay) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain61 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 27ms;
  const auto ackDelay = 0us;
  const auto matcher =
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(ackDelay)
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setRttNoAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime - ackDelay))
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(ackDelay)
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsOutstandingPacketSentThenAckedWithAckDelay) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain62 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  const quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  const quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 50ms;
  const auto ackDelay = 5ms;
  const auto matcher =
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(ackDelay)
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setRttNoAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime - ackDelay))
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(ackDelay)
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsOutstandingPacketSentThenAckedWithAckDelayEqRtt) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain63 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  const quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  const quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 50ms;
  const auto ackDelay = ackRecvTime - sentTime; // ack delay == RTT!
  const auto matcher =
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setRttNoAckDelay(0us)
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(
      *observerWithAcks1,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(testing::AllOf(testing::Field(
                      &quic::AckEvent::rttSampleNoAckDelay,
                      testing::AnyOf(
                          testing::Eq(0ms), testing::Eq(std::nullopt)))))))));
  EXPECT_CALL(
      *observerWithAcks2,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(testing::AllOf(testing::Field(
                      &quic::AckEvent::rttSampleNoAckDelay,
                      testing::AnyOf(
                          testing::Eq(0ms), testing::Eq(std::nullopt)))))))));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsOutstandingPacketSentThenAckedWithTooLargeAckDelay) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain64 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  const quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  const quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 50ms;
  const auto ackDelay = ackRecvTime + 1ms - sentTime; // ack delay >> RTT!
  const auto matcher =
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setNoRttWithNoAckDelay()
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(
      *observerWithAcks1,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(testing::AllOf(testing::Field(
                      &quic::AckEvent::rttSampleNoAckDelay,
                      testing::Eq(std::nullopt))))))));
  EXPECT_CALL(
      *observerWithAcks2,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(testing::AllOf(testing::Field(
                      &quic::AckEvent::rttSampleNoAckDelay,
                      testing::Eq(std::nullopt))))))));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenAllAckedAtOnce) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain65 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain66 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  auto typedTestWriteChain67 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets3->end;
  EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets3->sentTime;
  const auto ackRecvTime = sentTime + 27ms;
  const auto ackDelay = 5ms;
  const auto matcher =
      AckEventMatcherBuilder<TypeParam>()
          .setExpectedAckedIntervals(
              {maybeWrittenPackets1,
               maybeWrittenPackets2,
               maybeWrittenPackets3})
          .setExpectedNumAckedPackets(3)
          .setAckTime(ackRecvTime)
          .setAckDelay(ackDelay)
          .setLargestAckedPacket(maybeWrittenPackets3->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setRttNoAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime - ackDelay))
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(ackDelay)
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentAndAckedSequentially) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream, write some bytes, send packet, deliver ACK
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain68 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());

    const auto sentTime = maybeWrittenPackets->sentTime;
    const auto ackRecvTime = sentTime + 27ms;
    const auto ackDelay = 5ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets->start, maybeWrittenPackets->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // write some more bytes into the same stream, send packet, deliver ACK
  auto typedTestWriteChain69 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    const auto sentTime = maybeWrittenPackets->sentTime;
    const auto ackRecvTime = sentTime + 443ms;
    const auto ackDelay = 7ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets->start, maybeWrittenPackets->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // third and final write, this time with EOF, send packet, deliver ACK
  auto typedTestWriteChain70 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());

    const auto sentTime = maybeWrittenPackets->sentTime;
    const auto ackRecvTime = sentTime + 62ms;
    const auto ackDelay = 3ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets->start, maybeWrittenPackets->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenAckedSequentially) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain71 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain72 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  auto typedTestWriteChain73 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets3->end;
  EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for packet 1
  {
    const auto sentTime = maybeWrittenPackets1->sentTime;
    const auto ackRecvTime = sentTime + 122ms;
    const auto ackDelay = 3ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets1->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets1->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    const auto sentTime = maybeWrittenPackets2->sentTime;
    const auto ackRecvTime = sentTime + 62ms;
    const auto ackDelay = 1ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets2})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets2->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets2->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets2->start, maybeWrittenPackets2->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 3
  {
    const auto sentTime = maybeWrittenPackets3->sentTime;
    const auto ackRecvTime = sentTime + 82ms;
    const auto ackDelay = 20ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets3})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets3->start, maybeWrittenPackets3->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenFirstLastAckedSequentiallyThenSecondAcked) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain74 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain75 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  auto typedTestWriteChain76 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  EXPECT_EQ(
      3,
      this->getNumPacketsWritten(
          {maybeWrittenPackets1, maybeWrittenPackets2, maybeWrittenPackets3}));

  // deliver an ACK for packet 1
  {
    const auto sentTime = maybeWrittenPackets1->sentTime;
    const auto ackRecvTime = sentTime + 20ms;
    const auto ackDelay = 5ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets1->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets1->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 3
  {
    const auto sentTime = maybeWrittenPackets3->sentTime;
    const auto ackRecvTime = sentTime + 11ms;
    const auto ackDelay = 4ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets3->start, maybeWrittenPackets3->end},
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    // base ACK receive time off of (3) as sent packet was reordered
    const auto ackRecvTime = maybeWrittenPackets3->sentTime + 11ms;
    const auto ackDelay = 2ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end) // still 3
            .setLargestNewlyAckedPacket(maybeWrittenPackets2->end) // 2
            .setNoRtt() // no RTT because largest ACKed (3) acked earlier
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets3->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenFirstLastAckedAtOnceThenSecondAcked) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  auto typedTestWriteChain77 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  auto typedTestWriteChain78 = this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  auto typedTestWriteChain79 =
      this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  EXPECT_EQ(
      3,
      this->getNumPacketsWritten(
          {maybeWrittenPackets1, maybeWrittenPackets2, maybeWrittenPackets3}));

  // deliver an ACK for packet 1 and 3
  {
    const auto sentTime = maybeWrittenPackets3->sentTime; // 3 is latest sent
    const auto ackRecvTime = sentTime + 20ms;
    const auto ackDelay = 5ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals(
                {maybeWrittenPackets1, maybeWrittenPackets3})
            .setExpectedNumAckedPackets(2)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets3->start, maybeWrittenPackets3->end},
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    // base ACK receive time off of (3) as sent packet was reordered
    const auto ackRecvTime = maybeWrittenPackets3->sentTime + 11ms;
    const auto ackDelay = 2ms;
    const auto matcher =
        AckEventMatcherBuilder<TypeParam>()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end) // still 3
            .setLargestNewlyAckedPacket(maybeWrittenPackets2->end) // 2
            .setNoRtt() // no RTT because largest ACKed (3) acked earlier
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets3->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    PacketsReceivedEventsSingle) {
  using Event = quic::SocketObserverInterface::PacketsReceivedEvent;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsReceivedEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver pkt1 with stream data from the remote
  auto pkt1 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(100));
  const auto pkt1RecvTime = TimePoint::clock::now();
  const auto pkt1NumBytes = pkt1->computeChainDataLength();

#ifndef _WIN32
  const uint8_t packetTosValue = kEcnECT0;
#else
  uint8_t packetTosValue = kEcnECT0;
  if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    // QuicClientTransport does not support reading ECN bits using the default
    // recvmsg read path.
    packetTosValue = 0;
  }
#endif

  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(1)),
        testing::Field(&Event::numBytesReceived, testing::Eq(pkt1NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(1)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(ReceivedUdpPacketMatcherBuilder<TypeParam>()
                                     .setExpectedPacketReceiveTime(pkt1RecvTime)
                                     .setExpectedPacketNumBytes(pkt1NumBytes)
                                     .setExpectedTosValue(packetTosValue)
                                     .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPacket(std::move(pkt1), pkt1RecvTime, packetTosValue);

  // deliver pkt2 with stream data from the remote
  auto pkt2 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(500));
  const auto pkt2RecvTime = pkt1RecvTime + 50ms;
  const auto pkt2NumBytes = pkt2->computeChainDataLength();
  EXPECT_NE(pkt2NumBytes, pkt1NumBytes);
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(1)),
        testing::Field(&Event::numBytesReceived, testing::Eq(pkt2NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(1)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(ReceivedUdpPacketMatcherBuilder<TypeParam>()
                                     .setExpectedPacketReceiveTime(pkt2RecvTime)
                                     .setExpectedPacketNumBytes(pkt2NumBytes)
                                     .setExpectedTosValue(packetTosValue)
                                     .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPacket(std::move(pkt2), pkt2RecvTime, packetTosValue);

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportAfterStartTestForObservers,
    PacketsReceivedEventsMulti) {
  // skip for client transport tests for now as supporting test foundation
  // does not properly support batch delivery
  if constexpr (std::is_base_of_v<TypeParam, QuicClientTransportTestBase>) {
    return;
  }

  using Event = quic::SocketObserverInterface::PacketsReceivedEvent;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsReceivedEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver pkt1 and pkt2 at same time with stream data from the remote
  auto pkt1 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(100));
  auto pkt2 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(500));
  const auto pkt1NumBytes = pkt1->computeChainDataLength();
  const auto pkt2NumBytes = pkt2->computeChainDataLength();
  EXPECT_NE(pkt1NumBytes, pkt2NumBytes);

  std::vector<std::unique_ptr<folly::IOBuf>> pktBatch1;
  pktBatch1.emplace_back(std::move(pkt1));
  pktBatch1.emplace_back(std::move(pkt2));
  const auto pktBatch1RecvTime = TimePoint::clock::now();
  const auto pktBatch1NumBytes = pkt1NumBytes + pkt2NumBytes;

  const uint8_t packetTosValue = kEcnECT1;
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            "receiveLoopTime",
            &Event::receiveLoopTime,
            testing::Ge(TimePoint::clock::now())),
        testing::Field(
            "numPacketsReceived", &Event::numPacketsReceived, testing::Eq(2)),
        testing::Field(
            "numBytesReceived",
            &Event::numBytesReceived,
            testing::Eq(pktBatch1NumBytes)),
        testing::Field(
            "receivedPacketsCount",
            &Event::receivedPackets,
            testing::SizeIs(2)),
        testing::Field(
            "receivedPacketsElements",
            &Event::receivedPackets,
            testing::ElementsAre(
                // pkt1
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pktBatch1RecvTime)
                    .setExpectedPacketNumBytes(pkt1NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build(),
                // pkt2
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pktBatch1RecvTime)
                    .setExpectedPacketNumBytes(pkt2NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPackets(std::move(pktBatch1), pktBatch1RecvTime, packetTosValue);

  // deliver pkt3 and pkt4 at same time with stream data from the remote
  auto pkt3 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(200));
  auto pkt4 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(800));
  const auto pkt3NumBytes = pkt3->computeChainDataLength();
  const auto pkt4NumBytes = pkt4->computeChainDataLength();
  EXPECT_NE(pkt3NumBytes, pkt4NumBytes);

  std::vector<std::unique_ptr<folly::IOBuf>> pktBatch2;
  pktBatch2.emplace_back(std::move(pkt3));
  pktBatch2.emplace_back(std::move(pkt4));
  const auto pktBatch2RecvTime = pktBatch1RecvTime + 50ms;
  const auto pktBatch2NumBytes = pkt3NumBytes + pkt4NumBytes;
  EXPECT_NE(pktBatch1NumBytes, pktBatch2NumBytes);
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(2)),
        testing::Field(
            &Event::numBytesReceived, testing::Eq(pktBatch2NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(2)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(
                // pkt1
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pktBatch2RecvTime)
                    .setExpectedPacketNumBytes(pkt3NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build(),
                // pkt2
                ReceivedUdpPacketMatcherBuilder<TypeParam>()
                    .setExpectedPacketReceiveTime(pktBatch2RecvTime)
                    .setExpectedPacketNumBytes(pkt4NumBytes)
                    .setExpectedTosValue(packetTosValue)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPackets(std::move(pktBatch2), pktBatch2RecvTime, packetTosValue);

  this->destroyTransport();
}

} // namespace quic::test

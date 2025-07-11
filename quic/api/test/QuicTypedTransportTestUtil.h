/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicTransportBase.h>
#include <quic/common/test/TestPacketBuilders.h>
#include <quic/common/test/TestUtils.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/StateData.h>

namespace quic::test {

template <typename QuicTransportTestClass>
class QuicTypedTransportTestBase : protected QuicTransportTestClass {
 public:
  using QuicTransportTestClass::QuicTransportTestClass;

  ~QuicTypedTransportTestBase() override = default;

  void SetUp() override {
    QuicTransportTestClass::SetUp();
  }

  QuicTransportBase* getTransport() {
    return QuicTransportTestClass::getTransport();
  }

  const QuicConnectionStateBase& getConn() {
    return QuicTransportTestClass::getConn();
  }

  QuicConnectionStateBase& getNonConstConn() {
    return QuicTransportTestClass::getNonConstConn();
  }

  /**
   * Contains interval of OutstandingPackets that were just written.
   */
  struct NewOutstandingPacketInterval {
    const PacketNum start;
    const PacketNum end;
    const TimePoint sentTime;
  };

  /**
   * Provide transport with opportunity to write packets.
   *
   * If new AppData packets written, returns packet numbers in interval.
   *
   * @return    Interval of newly written AppData packet numbers, or
   * std::nullopt.
   */
  Optional<NewOutstandingPacketInterval> loopForWrites() {
    // store the next packet number
    const auto preSendNextAppDataPacketNum =
        getNextPacketNum(getConn(), PacketNumberSpace::AppData);

    // loop to trigger writes
    QuicTransportTestClass::loopForWrites();

    // if we cannot find an outstanding AppData packet, we sent nothing new.
    //
    // we include "lost" to protect against the unusual case of the test somehow
    // causing a packet that was just written to be immediately marked lost.
    const auto it = quic::getLastOutstandingPacket(
        getNonConstConn(),
        PacketNumberSpace::AppData,
        true /* includeDeclaredLost */);

    if (it == getConn().outstandings.packets.rend()) {
      return std::nullopt;
    }
    const auto& packet = it->packet;
    const auto& metadata = it->metadata;
    const auto lastAppDataPacketNum = packet.header.getPacketSequenceNum();
    const auto sendTime = metadata.time;

    // if packet number of last AppData packet < nextAppDataPacketNum, then
    // we sent nothing new and we have nothing to do...
    if (lastAppDataPacketNum < preSendNextAppDataPacketNum) {
      return std::nullopt;
    }

    // we sent new AppData packets
    return NewOutstandingPacketInterval{
        preSendNextAppDataPacketNum, lastAppDataPacketNum, sendTime};
  }

  /**
   * Returns the first outstanding packet written of the specified type.
   *
   * If no outstanding packets of the specified type, returns nullptr.
   *
   * Since this is a reference to a packet in the outstanding packets deque, it
   * should not be stored.
   */
  const OutstandingPacketWrapper* FOLLY_NULLABLE
  getOldestOutstandingPacket(const quic::PacketNumberSpace packetNumberSpace) {
    const auto outstandingPacketIt =
        getFirstOutstandingPacket(this->getNonConstConn(), packetNumberSpace);
    if (outstandingPacketIt ==
        this->getNonConstConn().outstandings.packets.end()) {
      return nullptr;
    }
    return &*outstandingPacketIt;
  }

  /**
   * Returns the last outstanding packet written of the specified type.
   *
   * If no outstanding packets of the specified type, returns nullptr.
   *
   * Since this is a reference to a packet in the outstanding packets deque, it
   * should not be stored.
   */
  const OutstandingPacketWrapper* FOLLY_NULLABLE
  getNewestOutstandingPacket(const quic::PacketNumberSpace packetNumberSpace) {
    const auto outstandingPacketIt =
        getLastOutstandingPacket(this->getNonConstConn(), packetNumberSpace);
    if (outstandingPacketIt ==
        this->getNonConstConn().outstandings.packets.rend()) {
      return nullptr;
    }
    return &*outstandingPacketIt;
  }

  /**
   * Returns the last outstanding AppData packet written of the specified type.
   *
   * If no packet, nullptr returned.
   *
   * Since this is a reference to a packet in the outstanding packets deque, it
   * should not be stored.
   */
  const OutstandingPacketWrapper* FOLLY_NULLABLE
  getNewestAppDataOutstandingPacket() {
    return getNewestOutstandingPacket(PacketNumberSpace::AppData);
  }

  /**
   * Acks all outstanding packets for the specified packet number space.
   */
  void ackAllOutstandingPackets(
      quic::PacketNumberSpace pnSpace,
      quic::TimePoint recvTime = TimePoint::clock::now()) {
    auto oldestOutstandingPkt = getOldestOutstandingPacket(pnSpace);
    auto newestOutstandingPkt = getNewestOutstandingPacket(pnSpace);
    CHECK_EQ(oldestOutstandingPkt == nullptr, newestOutstandingPkt == nullptr);
    if (!oldestOutstandingPkt) {
      return;
    }

    QuicTransportTestClass::deliverData(
        NetworkData(
            buildAckPacketForSentPackets(
                pnSpace,
                oldestOutstandingPkt->packet.header.getPacketSequenceNum(),
                newestOutstandingPkt->packet.header.getPacketSequenceNum()),
            recvTime,
            0),
        false /* loopForWrites */);
  }

  /**
   * Acks all outstanding packets for all packet number spaces.
   */
  void ackAllOutstandingPackets(
      quic::TimePoint recvTime = TimePoint::clock::now()) {
    ackAllOutstandingPackets(quic::PacketNumberSpace::Initial, recvTime);
    ackAllOutstandingPackets(quic::PacketNumberSpace::Handshake, recvTime);
    ackAllOutstandingPackets(quic::PacketNumberSpace::AppData, recvTime);
  }

  /**
   * Deliver a single packet from the remote.
   */
  void deliverPacket(
      BufPtr&& buf,
      quic::TimePoint recvTime = TimePoint::clock::now(),
      uint8_t tosValue = 0,
      bool loopForWrites = true) {
    QuicTransportTestClass::deliverData(
        NetworkData(std::move(buf), recvTime, tosValue), loopForWrites);
  }

  /**
   * Deliver a single packet from the remote, do not loop for writes.
   */
  void deliverPacketNoWrites(
      BufPtr&& buf,
      quic::TimePoint recvTime = TimePoint::clock::now(),
      uint8_t tosValue = 0) {
    deliverPacket(
        std::move(buf), recvTime, tosValue, false /* loopForWrites */);
  }

  /**
   * Deliver multiple packets from the remote.
   */
  void deliverPackets(
      std::vector<BufPtr>&& bufs,
      quic::TimePoint recvTime = TimePoint::clock::now(),
      uint8_t tosValue = 0,
      bool loopForWrites = true) {
    auto networkData = NetworkData();
    // This overrides the timing in added packets.
    networkData.setReceiveTimePoint(recvTime);
    for (auto& buf : bufs) {
      auto udpPacket = ReceivedUdpPacket(
          std::move(buf),
          ReceivedUdpPacket::Timings{}, // NetworkData receiveTimePoint will
                                        // override this
          tosValue);
      networkData.addPacket(std::move(udpPacket));
    }
    QuicTransportTestClass::deliverData(std::move(networkData), loopForWrites);
  }

  /**
   * Deliver multiple packets from the remote, do not loop for writes.
   */
  void deliverPacketsNoWrites(
      std::vector<BufPtr>&& bufs,
      quic::TimePoint recvTime = TimePoint::clock::now()) {
    deliverPackets(std::move(bufs), recvTime, false /* loopForWrites */);
  }

  /**
   * Build a packet with stream data from peer.
   */
  quic::BufPtr buildPeerPacketWithStreamData(
      const quic::StreamId streamId,
      BufPtr data,
      Optional<ProtectionType> shortHeaderProtectionOverride = std::nullopt) {
    auto buf = quic::test::packetToBuf(createStreamPacket(
        getSrcConnectionId(),
        getDstConnectionId(),
        ++peerPacketNumStore.nextAppDataPacketNum,
        streamId,
        *data /* stream data */,
        0 /* cipherOverhead */,
        0 /* largest acked */,
        // // the following technically ignores lost ACK packets from peer, but
        // // should meet the needs of the majority of tests...
        // getConn().ackStates.appDataAckState.largestAckedByPeer.value_or(0),
        std::nullopt /* longHeaderOverride */,
        false /* eof */,
        shortHeaderProtectionOverride));
    buf->coalesce();
    return buf;
  }

  /**
   * Build a packet with stream data from peer.
   */
  quic::BufPtr buildPeerPacketWithStreamDataAndEof(
      const quic::StreamId streamId,
      BufPtr data) {
    auto buf = quic::test::packetToBuf(createStreamPacket(
        getSrcConnectionId(),
        getDstConnectionId(),
        ++peerPacketNumStore.nextAppDataPacketNum,
        streamId,
        *data /* stream data */,
        0 /* cipherOverhead */,
        0 /* largest acked */,
        std::nullopt /* longHeaderOverride */,
        true /* eof */));

    buf->coalesce();
    return buf;
  }

  /**
   * Build a packet with a StopSendingFrame from peer.
   */
  quic::BufPtr buildPeerPacketWithStopSendingFrame(
      const quic::StreamId streamId) {
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        getDstConnectionId(),
        peerPacketNumStore.nextAppDataPacketNum++);
    RegularQuicPacketBuilder builder(
        getConn().udpSendPacketLen, std::move(header), 0 /* largestAcked */);
    CHECK(!builder.encodePacketHeader().hasError());
    CHECK(builder.canBuildPacket());

    StopSendingFrame stopSendingFrame(
        streamId, GenericApplicationErrorCode::UNKNOWN);
    CHECK(!writeSimpleFrame(stopSendingFrame, builder).hasError());

    auto buf = quic::test::packetToBuf(std::move(builder).buildPacket());
    buf->coalesce();
    return buf;
  }

  /**
   * Build a packet with a RstStreamFrame from peer.
   */
  quic::BufPtr buildPeerPacketWithRstStreamFrame(
      const quic::StreamId streamId,
      const uint64_t offset) {
    ShortHeader header(
        ProtectionType::KeyPhaseZero,
        getDstConnectionId(),
        peerPacketNumStore.nextAppDataPacketNum++);
    RegularQuicPacketBuilder builder(
        getConn().udpSendPacketLen, std::move(header), 0 /* largestAcked */);
    CHECK(!builder.encodePacketHeader().hasError());
    CHECK(builder.canBuildPacket());

    RstStreamFrame rstStreamFrame(
        streamId, GenericApplicationErrorCode::UNKNOWN, offset);
    CHECK(!writeFrame(rstStreamFrame, builder).hasError());

    auto buf = quic::test::packetToBuf(std::move(builder).buildPacket());
    buf->coalesce();
    return buf;
  }

  /**
   * Build a packet from peer with ACK frame for previously sent packets.
   */
  quic::BufPtr buildAckPacketForSentPackets(
      quic::PacketNumberSpace pnSpace,
      quic::AckBlocks acks,
      std::chrono::microseconds ackDelay = 0us) {
    auto buf =
        quic::test::packetToBuf(AckPacketBuilder()
                                    .setDstConn(&getNonConstConn())
                                    .setPacketNumberSpace(pnSpace)
                                    .setAckPacketNumStore(&peerPacketNumStore)
                                    .setAckBlocks(acks)
                                    .setAckDelay(ackDelay)
                                    .build());
    buf->coalesce();
    return buf;
  }

  /**
   * Build a packet from peer with ACK frame for previously sent packets.
   */
  quic::BufPtr buildAckPacketForSentPackets(
      quic::PacketNumberSpace pnSpace,
      quic::PacketNum intervalStart,
      quic::PacketNum intervalEnd,
      std::chrono::microseconds ackDelay = 0us) {
    quic::AckBlocks acks = {{intervalStart, intervalEnd}};
    return buildAckPacketForSentPackets(pnSpace, acks, ackDelay);
  }

  /**
   * Build a packet from peer with ACK frame for previously sent AppData pkts.
   */
  quic::BufPtr buildAckPacketForSentAppDataPackets(
      quic::AckBlocks acks,
      std::chrono::microseconds ackDelay = 0us) {
    return buildAckPacketForSentPackets(
        quic::PacketNumberSpace::AppData, acks, ackDelay);
  }

  /**
   * Build a packet with ACK frame for previously sent AppData packet.
   */
  quic::BufPtr buildAckPacketForSentAppDataPacket(
      quic::PacketNum packetNum,
      std::chrono::microseconds ackDelay = 0us) {
    quic::AckBlocks acks = {{packetNum, packetNum}};
    return buildAckPacketForSentAppDataPackets(acks, ackDelay);
  }

  /**
   * Build a packet with ACK frame for previously sent AppData packets.
   */
  quic::BufPtr buildAckPacketForSentAppDataPackets(
      NewOutstandingPacketInterval writeInterval,
      std::chrono::microseconds ackDelay = 0us) {
    const quic::PacketNum firstPacketNum = writeInterval.start;
    const quic::PacketNum lastPacketNum = writeInterval.end;
    quic::AckBlocks acks = {{firstPacketNum, lastPacketNum}};
    return buildAckPacketForSentAppDataPackets(acks, ackDelay);
  }

  /**
   * Build a packet with ACK frame for previously sent AppData packets.
   */
  quic::BufPtr buildAckPacketForSentAppDataPackets(
      Optional<NewOutstandingPacketInterval> maybeWriteInterval,
      std::chrono::microseconds ackDelay = 0us) {
    CHECK(maybeWriteInterval.has_value());
    return buildAckPacketForSentAppDataPackets(
        maybeWriteInterval.value(), ackDelay);
  }

  /**
   * Build a packet with ACK frame for previously sent AppData packets.
   */
  quic::BufPtr buildAckPacketForSentAppDataPackets(
      std::vector<NewOutstandingPacketInterval> writeIntervals,
      std::chrono::microseconds ackDelay = 0us) {
    quic::AckBlocks acks;
    for (const auto& writeInterval : writeIntervals) {
      acks.insert(writeInterval.start, writeInterval.end);
    }
    return buildAckPacketForSentAppDataPackets(acks, ackDelay);
  }

  /**
   * Build a packet with ACK frame for previously sent AppData packets.
   */
  quic::BufPtr buildAckPacketForSentAppDataPackets(
      std::vector<Optional<NewOutstandingPacketInterval>> maybeWriteIntervals,
      std::chrono::microseconds ackDelay = 0us) {
    std::vector<NewOutstandingPacketInterval> writeIntervals;
    for (const auto& maybeWriteInterval : maybeWriteIntervals) {
      CHECK(maybeWriteInterval.has_value());
      writeIntervals.emplace_back(maybeWriteInterval.value());
    }
    return buildAckPacketForSentAppDataPackets(writeIntervals, ackDelay);
  }

  /**
   * Build a packet with ACK frame for previously sent AppData packets.
   */
  quic::BufPtr buildAckPacketForSentAppDataPackets(
      const std::vector<quic::PacketNum>& packetNums,
      std::chrono::microseconds ackDelay = 0us) {
    quic::AckBlocks acks;
    for (const auto& packetNum : packetNums) {
      acks.insert(packetNum, packetNum);
    }
    return buildAckPacketForSentAppDataPackets(acks, ackDelay);
  }

  template <class T0, class... Ts>
  using are_same = std::conjunction<std::is_same<T0, Ts>...>;

  /**
   * Build a packet with ACK frame for previously sent AppData packets.
   */
  template <
      class T0,
      class... Ts,
      class = std::enable_if_t<
          std::is_same<
              std::remove_const_t<std::remove_reference_t<T0>>,
              quic::PacketNum>::value,
          void>,
      class = std::enable_if_t<are_same<T0, Ts...>::value, void>>
  quic::BufPtr buildAckPacketForSentAppDataPackets(T0&& first, Ts&&... args) {
    std::vector<quic::PacketNum> packetNums{
        std::forward<T0>(first), std::forward<Ts>(args)...};
    return buildAckPacketForSentAppDataPackets(packetNums);
  }

  /**
   * Returns the first outstanding packet with containing frame of type T.
   */
  template <QuicWriteFrame::Type Type>
  Optional<quic::PacketNum> getFirstOutstandingPacketWithFrame() {
    auto packetItr = std::find_if(
        getNonConstConn().outstandings.packets.begin(),
        getNonConstConn().outstandings.packets.end(),
        findFrameInPacketFunc<Type>());
    if (packetItr == getNonConstConn().outstandings.packets.end()) {
      return std::nullopt;
    }
    return packetItr->packet.header.getPacketSequenceNum();
  }

  /**
   * Returns the number of stream bytes in the packet.
   */
  struct GetNewStreamBytesInPacketsQueryBuilder {
    using Builder = GetNewStreamBytesInPacketsQueryBuilder;

    explicit GetNewStreamBytesInPacketsQueryBuilder(
        QuicTypedTransportTestBase* testObjIn)
        : testObj(testObjIn) {}

    Builder&& setStreamId(const uint64_t streamIdIn) {
      maybeStreamId = streamIdIn;
      return std::move(*this);
    }

    template <class T0, class... Ts>
    Builder&& setPacketNums(T0&& first, Ts&&... args) {
      std::vector<std::decay_t<T0>> packetNums{
          std::forward<T0>(first), std::forward<Ts>(args)...};
      maybePacketNums.emplace(std::move(packetNums));
      return std::move(*this);
    }

    Builder&& setPacketNums(const std::vector<quic::PacketNum>& packetNums) {
      maybePacketNums.emplace(packetNums);
      return std::move(*this);
    }

    auto go() && {
      uint64_t sum = 0;

      CHECK(maybeStreamId.has_value()) << "Stream ID must be set";
      const auto& streamId = maybeStreamId.value();

      CHECK(maybePacketNums.has_value()) << "Packet numbers must be set";
      const auto& packetNums = maybePacketNums.value();

      for (const auto& packetNum : packetNums) {
        const auto packetItr = std::find_if(
            testObj->getNonConstConn().outstandings.packets.begin(),
            testObj->getNonConstConn().outstandings.packets.end(),
            [&packetNum](const auto& outstandingPacket) {
              return packetNum ==
                  outstandingPacket.packet.header.getPacketSequenceNum();
            });
        if (packetItr ==
            testObj->getNonConstConn().outstandings.packets.end()) {
          continue;
        }

        auto streamDetailsItr = std::find_if(
            packetItr->metadata.detailsPerStream.begin(),
            packetItr->metadata.detailsPerStream.end(),
            [&streamId](const auto& it) { return streamId == it.first; });
        if (streamDetailsItr == packetItr->metadata.detailsPerStream.end()) {
          continue;
        }

        sum += streamDetailsItr->second.newStreamBytesSent;
      }

      return sum;
    }

   private:
    QuicTypedTransportTestBase* const testObj;
    Optional<quic::StreamId> maybeStreamId;
    Optional<std::vector<quic::PacketNum>> maybePacketNums;
  };

  auto getNewStreamBytesInPackets() {
    return GetNewStreamBytesInPacketsQueryBuilder(this);
  }

  uint64_t getNewStreamBytesInPackets(
      const quic::StreamId targetStreamId,
      const quic::PacketNum targetPacketNum) {
    const auto packetItr = std::find_if(
        getNonConstConn().outstandings.packets.begin(),
        getNonConstConn().outstandings.packets.end(),
        [&targetPacketNum](const auto& outstandingPacket) {
          return targetPacketNum ==
              outstandingPacket.packet.header.getPacketSequenceNum();
        });
    if (packetItr == getNonConstConn().outstandings.packets.end()) {
      return 0;
    }

    auto streamDetailsItr = std::find_if(
        packetItr->metadata.detailsPerStream.begin(),
        packetItr->metadata.detailsPerStream.end(),
        [&targetStreamId](const auto& it) {
          return targetStreamId == it.first;
        });
    if (streamDetailsItr == packetItr->metadata.detailsPerStream.end()) {
      return 0;
    }

    return streamDetailsItr->second.newStreamBytesSent;
  }

  /**
   * Returns the number of stream bytes in the packet.
   */
  uint64_t getNewStreamBytesInPacket(
      const quic::PacketNum targetPacketNum,
      const quic::StreamId targetStreamId) {
    auto packetItr = std::find_if(
        getNonConstConn().outstandings.packets.begin(),
        getNonConstConn().outstandings.packets.end(),
        [&targetPacketNum](const auto& outstandingPacket) {
          return targetPacketNum ==
              outstandingPacket.packet.header.getPacketSequenceNum();
        });
    if (packetItr == getNonConstConn().outstandings.packets.end()) {
      return 0;
    }

    auto streamDetailsItr = std::find_if(
        packetItr->metadata.detailsPerStream.begin(),
        packetItr->metadata.detailsPerStream.end(),
        [&targetStreamId](const auto& it) {
          return targetStreamId == it.first;
        });
    if (streamDetailsItr == packetItr->metadata.detailsPerStream.end()) {
      return 0;
    }

    return streamDetailsItr->second.newStreamBytesSent;
  }

  /**
   * Have local (self) create a new unidirectional stream.
   */
  StreamId createUnidirectionalStream() {
    const auto expectedStreamId =
        this->getTransport()->createUnidirectionalStream();
    CHECK(expectedStreamId.has_value());
    return expectedStreamId.value();
  }

  /**
   * Have local (self) create a new bidirectional stream.
   */
  StreamId createBidirectionalStream() {
    const auto expectedStreamId =
        this->getTransport()->createBidirectionalStream();
    CHECK(expectedStreamId.has_value());
    return expectedStreamId.value();
  }

  /**
   * Get next acceptable local (self) bidirectional stream number.
   */
  StreamId getNextLocalBidirectionalStreamId() {
    const auto maybeStreamId =
        getConn().streamManager->nextAcceptableLocalBidirectionalStreamId();
    CHECK(maybeStreamId.has_value());
    return maybeStreamId.value();
  }

  /**
   * Get next acceptable local (self) unidirectional stream number.
   */
  StreamId getNextLocalUnidirectionalStreamId() {
    const auto maybeStreamId =
        getConn().streamManager->nextAcceptableLocalUnidirectionalStreamId();
    CHECK(maybeStreamId.has_value());
    return maybeStreamId.value();
  }

  /**
   * Get next acceptable remote (peer) bidirectional stream number.
   */
  StreamId getNextPeerBidirectionalStreamId() {
    const auto maybeStreamId =
        getConn().streamManager->nextAcceptablePeerBidirectionalStreamId();
    CHECK(maybeStreamId.has_value());
    return maybeStreamId.value();
  }

  /**
   * Get next acceptable remote (peer) unidirectional stream number.
   */
  StreamId getNextPeerUnidirectionalStreamId() {
    const auto maybeStreamId =
        getConn().streamManager->nextAcceptablePeerUnidirectionalStreamId();
    CHECK(maybeStreamId.has_value());
    return maybeStreamId.value();
  }

  /**
   * Get source (local / self) connection ID.
   */
  ConnectionId getSrcConnectionId() {
    const auto maybeConnId =
        (getConn().nodeType == QuicNodeType::Client
             ? getConn().serverConnectionId
             : getConn().clientConnectionId);
    CHECK(maybeConnId.has_value());
    return maybeConnId.value();
  }

  /**
   * Get destination (remote / peer) connection ID.
   */
  ConnectionId getDstConnectionId() {
    const auto maybeConnId =
        (getConn().nodeType == QuicNodeType::Client
             ? getConn().clientConnectionId
             : getConn().serverConnectionId);
    CHECK(maybeConnId.has_value());
    return maybeConnId.value();
  }

  /**
   * Return the number of packets written in the write interval.
   */
  static uint64_t getNumPacketsWritten(
      const NewOutstandingPacketInterval& writeInterval) {
    const quic::PacketNum firstPacketNum = writeInterval.start;
    const quic::PacketNum lastPacketNum = writeInterval.end;
    CHECK_LE(firstPacketNum, lastPacketNum);
    return writeInterval.end - writeInterval.start + 1;
  }

  /**
   * Return the number of packets written in the write interval.
   */
  static uint64_t getNumPacketsWritten(
      const Optional<NewOutstandingPacketInterval>& maybeWriteInterval) {
    if (!maybeWriteInterval.has_value()) {
      return 0;
    }
    return getNumPacketsWritten(maybeWriteInterval.value());
  }

  /**
   * Return the number of packets written in the write interval.
   */
  static uint64_t getNumPacketsWritten(
      const std::vector<Optional<NewOutstandingPacketInterval>>&
          maybeWriteIntervals) {
    uint64_t sum = 0;
    for (const auto& maybeWriteInterval : maybeWriteIntervals) {
      sum += getNumPacketsWritten(maybeWriteInterval);
    }
    return sum;
  }

  /**
   * Returns a vector of packet numbers written in one or more intervals.
   */
  static std::vector<quic::PacketNum> getPacketNumsFromIntervals(
      const std::vector<NewOutstandingPacketInterval>& writeIntervals) {
    std::vector<quic::PacketNum> packetNums;
    for (const auto& writeInterval : writeIntervals) {
      for (auto i = writeInterval.start; i <= writeInterval.end; i++) {
        CHECK_LE(writeInterval.start, writeInterval.end);
        packetNums.emplace_back(i);
      }
    }
    return packetNums;
  }

  /**
   * Returns a vector of packet numbers written in one or more intervals.
   */
  static std::vector<quic::PacketNum> getPacketNumsFromIntervals(
      const std::vector<Optional<NewOutstandingPacketInterval>>&
          maybeWriteIntervals) {
    std::vector<NewOutstandingPacketInterval> writeIntervals;
    for (const auto& maybeWriteInterval : maybeWriteIntervals) {
      if (!maybeWriteInterval.has_value()) {
        continue;
      }
      writeIntervals.emplace_back(maybeWriteInterval.value());
    }
    return getPacketNumsFromIntervals(writeIntervals);
  }

  PacketNumStore peerPacketNumStore;
};

} // namespace quic::test

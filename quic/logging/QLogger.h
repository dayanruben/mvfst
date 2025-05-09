/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/Types.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/priority/PriorityQueue.h>

namespace quic {

class QLogger {
 public:
  explicit QLogger(VantagePoint vantagePointIn, std::string protocolTypeIn)
      : vantagePoint(vantagePointIn), protocolType(std::move(protocolTypeIn)) {}

  Optional<ConnectionId> dcid;
  Optional<ConnectionId> scid;
  VantagePoint vantagePoint;
  std::string protocolType;
  QLogger() = delete;
  virtual ~QLogger() = default;
  virtual void addPacket(
      const RegularQuicPacket& regularPacket,
      uint64_t packetSize) = 0;
  virtual void addPacket(
      const VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd) = 0;
  virtual void addPacket(
      const RegularQuicWritePacket& writePacket,
      uint64_t packetSize) = 0;
  virtual void addPacket(
      const RetryPacket& retryPacket,
      uint64_t packetSize,
      bool isPacketRecvd) = 0;
  virtual void addConnectionClose(
      std::string error,
      std::string reason,
      bool drainConnection,
      bool sendCloseImmediately) = 0;

  struct TransportSummaryArgs {
    uint64_t totalBytesSent{};
    uint64_t totalBytesRecvd{};
    uint64_t sumCurWriteOffset{};
    uint64_t sumMaxObservedOffset{};
    uint64_t sumCurStreamBufferLen{};
    uint64_t totalBytesRetransmitted{};
    uint64_t totalStreamBytesCloned{};
    uint64_t totalBytesCloned{};
    uint64_t totalCryptoDataWritten{};
    uint64_t totalCryptoDataRecvd{};
    uint64_t currentWritableBytes{};
    uint64_t currentConnFlowControl{};
    uint64_t totalPacketsSpuriouslyMarkedLost{};
    uint64_t finalPacketLossReorderingThreshold{};
    uint64_t finalPacketLossTimeReorderingThreshDividend{};
    bool usedZeroRtt{};
    QuicVersion quicVersion{QuicVersion::MVFST_INVALID};
    uint64_t dsrPacketCount{};
    uint16_t initialPacketsReceived{};
    uint16_t uniqueInitialCryptoFramesReceived{};
    std::chrono::milliseconds timeUntilLastInitialCryptoFrameReceived;
    std::string alpn;
    std::string namedGroup;
    std::string pskType;
    std::string echStatus;
  };

  virtual void addTransportSummary(const TransportSummaryArgs& args) = 0;
  virtual void addCongestionMetricUpdate(
      uint64_t bytesInFlight,
      uint64_t currentCwnd,
      std::string congestionEvent,
      std::string state = "",
      std::string recoveryState = "") = 0;
  virtual void addBandwidthEstUpdate(
      uint64_t bytes,
      std::chrono::microseconds interval) = 0;
  virtual void addAppLimitedUpdate() = 0;
  virtual void addAppUnlimitedUpdate() = 0;
  virtual void addPacingMetricUpdate(
      uint64_t pacingBurstSizeIn,
      std::chrono::microseconds pacingIntervalIn) = 0;
  virtual void addPacingObservation(
      std::string actual,
      std::string expected,
      std::string conclusion) = 0;
  virtual void addAppIdleUpdate(std::string idleEvent, bool idle) = 0;
  virtual void addPacketDrop(size_t packetSize, std::string dropReasonIn) = 0;
  virtual void addDatagramReceived(uint64_t dataLen) = 0;
  virtual void addLossAlarm(
      PacketNum largestSent,
      uint64_t alarmCount,
      uint64_t outstandingPackets,
      std::string type) = 0;
  virtual void addPacketsLost(
      PacketNum largestLostPacketNum,
      uint64_t lostBytes,
      uint64_t lostPackets) = 0;
  virtual void addTransportStateUpdate(std::string update) = 0;
  virtual void addPacketBuffered(
      ProtectionType protectionType,
      uint64_t packetSize) = 0;
  virtual void addMetricUpdate(
      std::chrono::microseconds latestRtt,
      std::chrono::microseconds mrtt,
      std::chrono::microseconds srtt,
      std::chrono::microseconds ackDelay) = 0;
  virtual void addStreamStateUpdate(
      quic::StreamId streamId,
      std::string update,
      Optional<std::chrono::milliseconds> timeSinceStreamCreation) = 0;
  virtual void addConnectionMigrationUpdate(bool intentionalMigration) = 0;
  virtual void addPathValidationEvent(bool success) = 0;
  virtual void addPriorityUpdate(
      quic::StreamId streamId,
      PriorityQueue::PriorityLogFields priority) = 0;
  virtual void
  addL4sWeightUpdate(double l4sWeight, uint32_t newEct1, uint32_t newCe) = 0;
  virtual void addNetworkPathModelUpdate(
      uint64_t inflightHi,
      uint64_t inflightLo,
      uint64_t bandwidthHiBytes,
      std::chrono::microseconds bandwidthHiInterval,
      uint64_t bandwidthLoBytes,
      std::chrono::microseconds bandwidthLoInterval) = 0;
  virtual void setDcid(Optional<ConnectionId> connID) = 0;
  virtual void setScid(Optional<ConnectionId> connID) = 0;
};

std::string getFlowControlEvent(int offset);

std::string
getRxStreamWU(StreamId streamId, PacketNum packetNum, uint64_t maximumData);

std::string getRxConnWU(PacketNum packetNum, uint64_t maximumData);

std::string getPeerClose(const std::string& errMsg);

std::string getFlowControlWindowAvailable(uint64_t windowAvailable);

std::string getClosingStream(const std::string& streamId);

} // namespace quic

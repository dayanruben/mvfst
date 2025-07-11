/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/codec/QuicReadCodec.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/CircularDeque.h>
#include <quic/common/Expected.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/congestion_control/PacketProcessor.h>
#include <quic/congestion_control/ThrottlingSignalProvider.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/logging/QLogger.h>
#include <quic/observer/SocketObserverTypes.h>
#include <quic/state/AckEvent.h>
#include <quic/state/AckStates.h>
#include <quic/state/ClonedPacketIdentifier.h>
#include <quic/state/LossState.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/PendingPathRateLimiter.h>
#include <quic/state/QuicConnectionStats.h>
#include <quic/state/QuicStreamGroupRetransmissionPolicy.h>
#include <quic/state/QuicStreamManager.h>
#include <quic/state/QuicTransportStatsCallback.h>
#include <quic/state/StreamData.h>
#include <quic/state/TransportSettings.h>

#include <folly/io/IOBuf.h>
#include <folly/io/async/DelayedDestruction.h>
#include <quic/common/Optional.h>

#include <chrono>
#include <list>
#include <numeric>
#include <queue>

namespace quic {

struct OutstandingsInfo {
  // Sent packets which have not been acked. These are sorted by PacketNum.
  std::deque<OutstandingPacketWrapper> packets;

  // All PacketEvents of this connection. If a OutstandingPacketWrapper doesn't
  // have an maybeClonedPacketIdentifier or if it's not in this set, there is no
  // need to process its frames upon ack or loss.
  UnorderedSet<ClonedPacketIdentifier, ClonedPacketIdentifierHash>
      clonedPacketIdentifiers;

  // Number of outstanding packets not including cloned
  EnumArray<PacketNumberSpace, uint64_t> packetCount{};

  // Number of packets are clones or cloned.
  EnumArray<PacketNumberSpace, uint64_t> clonedPacketCount{};

  // Number of packets currently declared lost.
  uint64_t declaredLostCount{0};

  // Number of outstanding inflight DSR packet. That is, when a DSR packet is
  // declared lost, this counter will be decreased.
  uint64_t dsrCount{0};

  // We just use this to get the correct number of outstanding packets. We
  // subtract the number of packets declared lost and scheduled for destruction
  // from the number of packets in the outstanding packets list.
  uint64_t scheduledForDestructionCount{0};

  // Number of packets outstanding and not declared lost.
  uint64_t numOutstanding() {
    CHECK_GE(packets.size(), declaredLostCount + scheduledForDestructionCount);
    return packets.size() - declaredLostCount - scheduledForDestructionCount;
  }

  // Total number of cloned packets.
  uint64_t numClonedPackets() {
    return clonedPacketCount[PacketNumberSpace::Initial] +
        clonedPacketCount[PacketNumberSpace::Handshake] +
        clonedPacketCount[PacketNumberSpace::AppData];
  }

  void reset() {
    packets.clear();
    clonedPacketIdentifiers.clear();
    packetCount = {};
    clonedPacketCount = {};
    declaredLostCount = 0;
    scheduledForDestructionCount = 0;
    dsrCount = 0;
  }
};

class AppLimitedTracker {
 public:
  /**
   * Mark the connection as application limited.
   */
  void setAppLimited() {
    DCHECK(!isAppLimited_);
    isAppLimited_ = true;
    appLimitedStartTime_ = Clock::now();
  }

  /**
   * Mark the connection as not being application limited.
   */
  void setNotAppLimited() {
    DCHECK(isAppLimited_);
    isAppLimited_ = false;
    totalAppLimitedTime_ +=
        std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now() - appLimitedStartTime_);
  }

  /**
   * Returns whether the connection has been marked as application limited.
   */
  bool isAppLimited() {
    return isAppLimited_;
  }

  /**
   * Returns total time connection has spent application limited.
   *
   * If connection is currently application limited, the time in the current
   * application limited period is included.
   */
  std::chrono::microseconds getTotalAppLimitedTime() {
    if (isAppLimited_) {
      return std::chrono::duration_cast<std::chrono::microseconds>(
                 Clock::now() - appLimitedStartTime_) +
          totalAppLimitedTime_;
    }
    return totalAppLimitedTime_;
  }

 private:
  // Total time spent application limited, excluding now.
  std::chrono::microseconds totalAppLimitedTime_{0us};

  // Whether we're currently application limited.
  // Initialize to true since all connections start off application limited.
  bool isAppLimited_{true};

  // When we last became application limited.
  // Initialize to now() since all connections start off application limited.
  Clock::time_point appLimitedStartTime_{Clock::now()};
};

struct Pacer {
  virtual ~Pacer() = default;

  /**
   * API for CongestionController to notify Pacer the latest cwnd value in bytes
   * and connection RTT so that Pacer can recalculate pacing rates.
   * Note the third parameter is here for testing purposes.
   */
  virtual void refreshPacingRate(
      uint64_t cwndBytes,
      std::chrono::microseconds rtt,
      TimePoint currentTime = Clock::now()) = 0;

  /**
   * Set the pacers rate to the given value in Bytes per second
   */
  virtual void setPacingRate(uint64_t rateBps) = 0;

  /**
   * Set an upper limit on the rate this pacer can use.
   * - If the pacer is currently using a faster pace, it will be brought down to
   *   maxRateBytesPerSec.
   * - If refreshPacingRate or setPacingRate are called with a value
   * greater than maxRateBytesPerSec, maxRateBytesPerSec will be used instead.
   */
  virtual void setMaxPacingRate(uint64_t maxRateBytesPerSec) = 0;

  /**
   * Resets the pacer, which should have the effect of the next write
   * happening immediately.
   */
  virtual void reset() = 0;

  /**
   * Set the factor by which to multiply the RTT before determining the
   * inter-burst interval. E.g. a numerator of 1 and a denominator of 2
   * would effectively double the pacing rate.
   */
  virtual void setRttFactor(uint8_t numerator, uint8_t denominator) = 0;

  /**
   * API for Trnasport to query the interval before next write
   */
  [[nodiscard]] virtual std::chrono::microseconds getTimeUntilNextWrite(
      TimePoint currentTime = Clock::now()) const = 0;

  /**
   * API for Transport to query a recalculated batch size based on currentTime
   * and previously scheduled write time. The batch size is how many packets the
   * transport can write out per eventbase loop.
   *
   * currentTime: The caller is expected to pass in a TimePoint value so that
   *              the Pacer can compensate the timer drift.
   */
  virtual uint64_t updateAndGetWriteBatchSize(TimePoint currentTime) = 0;

  /**
   * Getter API of the most recent write batch size.
   */
  virtual uint64_t getCachedWriteBatchSize() const = 0;

  virtual void onPacketSent() = 0;
  virtual void onPacketsLoss() = 0;

  virtual void setExperimental(bool experimental) = 0;
};

struct PacingRate {
  std::chrono::microseconds interval{0us};
  uint64_t burstSize{0};

  struct Builder {
    Builder&& setInterval(std::chrono::microseconds interval) &&;
    Builder&& setBurstSize(uint64_t burstSize) &&;
    PacingRate build() &&;

   private:
    std::chrono::microseconds interval_{0us};
    uint64_t burstSize_{0};
  };

 private:
  PacingRate(std::chrono::microseconds interval, uint64_t burstSize);
};

struct QuicCryptoStream : public QuicStreamLike {
  ~QuicCryptoStream() override = default;
};

struct QuicCryptoState {
  // Stream to exchange the initial cryptographic material.
  QuicCryptoStream initialStream;

  // Stream to exchange the one rtt key material.
  QuicCryptoStream handshakeStream;

  // Stream to exchange handshake data encrypted with 1-rtt keys.
  QuicCryptoStream oneRttStream;

  // Time point that the last initial packet with crypto frame received.
  TimePoint lastInitialCryptoFrameReceivedTimePoint;
};

struct ConnectionCloseEvent {
  TransportErrorCode errorCode;
  std::string reasonPhrase;
  PacketNum packetSequenceNum;
};

struct RstStreamEvent {
  RstStreamEvent(StreamId id, uint64_t offset, ApplicationErrorCode error)
      : stream(id), byteOffset(offset), errorCode(error) {}

  StreamId stream;
  uint64_t byteOffset;
  ApplicationErrorCode errorCode;
};

using Resets = UnorderedMap<StreamId, RstStreamFrame>;

using FrameList = std::vector<QuicSimpleFrame>;

class CongestionControllerFactory;
class LoopDetectorCallback;
class PendingPathRateLimiter;
class EcnL4sTracker;

struct ReadDatagram {
  ReadDatagram(TimePoint recvTimePoint, BufQueue data)
      : receiveTimePoint_{recvTimePoint}, buf_{std::move(data)} {}

  [[nodiscard]] TimePoint receiveTimePoint() const noexcept {
    return receiveTimePoint_;
  }

  [[nodiscard]] BufQueue& bufQueue() noexcept {
    return buf_;
  }

  [[nodiscard]] const BufQueue& bufQueue() const noexcept {
    return buf_;
  }

  // Move only to match BufQueue behavior
  ReadDatagram(ReadDatagram&& other) noexcept = default;
  ReadDatagram& operator=(ReadDatagram&& other) = default;
  ReadDatagram(const ReadDatagram&) = delete;
  ReadDatagram& operator=(const ReadDatagram&) = delete;

 private:
  TimePoint receiveTimePoint_;
  BufQueue buf_;
};

struct QuicConnectionStateBase : public folly::DelayedDestruction {
  virtual ~QuicConnectionStateBase() override = default;

  explicit QuicConnectionStateBase(QuicNodeType type) : nodeType(type) {}

  // Accessor to output buffer for continuous memory GSO writes
  BufAccessor* bufAccessor{nullptr};

  std::unique_ptr<Handshake> handshakeLayer;

  // Crypto stream
  std::unique_ptr<QuicCryptoState> cryptoState;

  // Connection Congestion controller
  std::unique_ptr<CongestionController> congestionController;

  std::vector<std::shared_ptr<PacketProcessor>> packetProcessors;

  std::shared_ptr<ThrottlingSignalProvider> throttlingSignalProvider;

  // Pacer
  std::unique_ptr<Pacer> pacer;

  // Congestion Controller factory to create specific impl of cc algorithm
  std::shared_ptr<CongestionControllerFactory> congestionControllerFactory;

  std::unique_ptr<QuicStreamManager> streamManager;

  // When server receives early data attempt without valid source address token,
  // server will limit bytes in flight to avoid amplification attack.
  // This limit should be cleared and set back to max after CFIN is received.
  OptionalIntegral<uint64_t> writableBytesLimit;

  std::unique_ptr<PendingPathRateLimiter> pathValidationLimiter;

  // Outstanding packets, packet events, and associated counters wrapped in one
  // class
  OutstandingsInfo outstandings;

  // The read codec to decrypt and decode packets.
  std::unique_ptr<QuicReadCodec> readCodec;

  // Initial header cipher.
  std::unique_ptr<PacketNumberCipher> initialHeaderCipher;

  // Handshake header cipher.
  std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher;

  // One rtt write header cipher.
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher;

  // Write cipher for 1-RTT data
  std::unique_ptr<Aead> oneRttWriteCipher;
  ProtectionType oneRttWritePhase{ProtectionType::KeyPhaseZero};
  uint64_t oneRttWritePacketsSentInCurrentPhase = 0;
  // Whether there is a locally-initiated key update that is pending
  // verification. This is used to decide whether the next variable should be
  // updated or not.
  bool oneRttWritePendingVerification{false};
  // In a key update is pending, this holds the first packet number sent in the
  // current (updated) phase. The peer must acknowledge this packet in the same
  // phase, responding in a different phase is a protocol violation. Once the
  // packet is acked, this value will be cleared.
  OptionalIntegral<PacketNum> oneRttWritePendingVerificationPacketNumber;

  // Write cipher for packets with initial keys.
  std::unique_ptr<Aead> initialWriteCipher;

  // Write cipher for packets with handshake keys.
  std::unique_ptr<Aead> handshakeWriteCipher;

  // Time at which the connection started.
  // TODO(bschlinker): For clients, this should be set when connect starts.
  TimePoint connectionTime;

  // The received active_connection_id_limit transport parameter from the peer.
  uint64_t peerActiveConnectionIdLimit{0};

  // The destination connection id used in client's initial packet.
  Optional<ConnectionId> clientChosenDestConnectionId;

  // The source connection id used in client's initial packet.
  Optional<ConnectionId> clientConnectionId;

  // The current server chosen connection id.
  Optional<ConnectionId> serverConnectionId;

  // Connection ids issued by self.
  std::vector<ConnectionIdData> selfConnectionIds;

  // Connection ids issued by peer - to be used as destination ids.
  std::vector<ConnectionIdData> peerConnectionIds;

  // Connection ids to be unbinded soon (server only)
  Optional<SmallVec<ConnectionId, 5>> connIdsRetiringSoon;

  // ConnectionIdAlgo implementation to encode and decode ConnectionId with
  // various info, such as routing related info.
  ConnectionIdAlgo* connIdAlgo{nullptr};

  // Negotiated version.
  Optional<QuicVersion> version;

  // Original advertised version. Only meaningful to clients.
  // TODO: move to client only conn state.
  Optional<QuicVersion> originalVersion;

  // Original address used by the peer when first establishing the connection.
  folly::SocketAddress originalPeerAddress;

  // Current peer address.
  folly::SocketAddress peerAddress;

  // Local address. INADDR_ANY if not set.
  Optional<folly::SocketAddress> localAddress;

  // Local error on the connection.
  Optional<QuicError> localConnectionError;

  // Error sent on the connection by the peer.
  Optional<QuicError> peerConnectionError;

  // Supported versions in order of preference. Only meaningful to clients.
  // TODO: move to client only conn state.
  std::vector<QuicVersion> supportedVersions;

  // The endpoint attempts to create a new self connection id with sequence
  // number and stateless reset token for itself, and if successful, returns it
  // and updates the connection's state to ensure its peer can use it.
  virtual Optional<ConnectionIdData> createAndAddNewSelfConnId() {
    return std::nullopt;
  }

  uint64_t nextSelfConnectionIdSequence{0};

  struct PendingEvents {
    Resets resets;
    Optional<PathChallengeFrame> pathChallenge;

    FrameList frames;

    std::vector<KnobFrame> knobs;

    // Number of probing packets to send after PTO
    EnumArray<PacketNumberSpace, uint8_t> numProbePackets{};

    [[nodiscard]] bool anyProbePackets() const {
      return numProbePackets[PacketNumberSpace::Initial] +
          numProbePackets[PacketNumberSpace::Handshake] +
          numProbePackets[PacketNumberSpace::AppData];
    }

    // true: schedule timeout if not scheduled
    // false: cancel scheduled timeout
    bool schedulePathValidationTimeout{false};

    // If we should schedule a new Ack timeout, if it's not already scheduled
    bool scheduleAckTimeout{false};

    // Whether a connection level window update is due to send
    bool connWindowUpdate{false};

    // If there is a pending loss detection alarm update
    bool setLossDetectionAlarm{false};

    bool cancelPingTimeout{false};

    bool notifyPingReceived{false};

    // close transport when the next packet number reaches kMaxPacketNum
    bool closeTransport{false};

    // To send a ping frame
    bool sendPing{false};

    // Do we need to send data blocked frame when connection is blocked.
    bool sendDataBlocked{false};

    // Send an immediate ack frame (requesting an ack)
    bool requestImmediateAck{false};
  };

  PendingEvents pendingEvents;

  LossState lossState;

  // This contains the ack and packet number related states for all three
  // packet number spaces.
  AckStates ackStates;
  // Number of ack frames sent on connection across all packet number spaces.
  uint64_t numAckFramesSent{0};

  // Number of flow control frames send on connection (both stream and
  // connection wide).
  uint64_t numWindowUpdateFramesSent{0};

  uint64_t numPingFramesSent{0};

  uint64_t eagainOrEwouldblockCount{0};
  uint64_t enobufsCount{0};

  struct ConnectionFlowControlState {
    // The size of the connection flow control window.
    uint64_t windowSize{0};
    // The max data we have advertised to the peer.
    uint64_t advertisedMaxOffset{0};
    // The max data the peer has advertised on the connection.
    // This is set to 0 initially so that we can't send any data until we know
    // the peer's flow control offset.
    uint64_t peerAdvertisedMaxOffset{0};
    // The sum of the min(read offsets) of all the streams on the conn.
    uint64_t sumCurReadOffset{0};
    // The sum of the max(offset) observed on all the streams on the conn.
    uint64_t sumMaxObservedOffset{0};
    // The sum of write offsets of all the streams, only including the offsets
    // written on the wire.
    uint64_t sumCurWriteOffset{0};
    // The sum of length of data in all the stream buffers.
    uint64_t sumCurStreamBufferLen{0};
    // The following are advertised by the peer, and are set to zero initially
    // so that we cannot send any data until we know the peer values.
    // The initial max stream offset for peer-initiated bidirectional streams.
    uint64_t peerAdvertisedInitialMaxStreamOffsetBidiLocal{0};
    // The initial max stream offset for local-initiated bidirectional streams.
    uint64_t peerAdvertisedInitialMaxStreamOffsetBidiRemote{0};
    // The initial max stream offset for unidirectional streams.
    uint64_t peerAdvertisedInitialMaxStreamOffsetUni{0};
    // Time at which the last flow control update was sent by the transport.
    Optional<TimePoint> timeOfLastFlowControlUpdate;
  };

  // Current state of flow control.
  ConnectionFlowControlState flowControlState;

  struct PendingWriteBatch {
    std::unique_ptr<folly::IOBuf> buf;
    // More fields will be needed here for other batch writer types.
  };

  // A write batch that was attempted but did not succeed.
  // This is only used by the SinglePacketBackpressureBatchWriter.
  PendingWriteBatch pendingWriteBatch_;

  // The outstanding path challenge
  Optional<PathChallengeFrame> outstandingPathValidation;

  // Settings for transports.
  TransportSettings transportSettings;

  // Value of the negotiated ack delay exponent.
  uint64_t peerAckDelayExponent{kDefaultAckDelayExponent};

  // The value of the peer's min_ack_delay, for creating ACK_FREQUENCY and
  // IMMEDIATE_ACK frames.
  OptionalMicros peerMinAckDelay;

  // Idle timeout advertised by the peer. Initially sets it to the maximum value
  // until the handshake sets the timeout.
  std::chrono::milliseconds peerIdleTimeout{kMaxIdleTimeout};

  // The max UDP packet size we will be sending, limited by both the received
  // max_packet_size in Transport Parameters and PMTU
  uint64_t udpSendPacketLen{kDefaultUDPSendPacketLen};

  // Peer-advertised max UDP payload size, stored as an opportunistic value to
  // use when receiving the forciblySetUdpPayloadSize transport knob param
  uint64_t peerMaxUdpPayloadSize{kDefaultUDPSendPacketLen};

  struct PacketSchedulingState {
    StreamId nextScheduledControlStream{0};
  };

  PacketSchedulingState schedulingState;

  // QLogger for this connection
  std::shared_ptr<QLogger> qLogger;

  // Track stats for various server events
  QuicTransportStatsCallback* statsCallback{nullptr};

  // Debug information. Currently only used to debug busy loop of Transport
  // WriteLooper.
  struct WriteDebugState {
    bool needsWriteLoopDetect{false};
    uint64_t currentEmptyLoopCount{0};
    WriteDataReason writeDataReason{WriteDataReason::NO_WRITE};
    NoWriteReason noWriteReason{NoWriteReason::WRITE_OK};
    std::string schedulerName;
  };

  struct ReadDebugState {
    uint64_t loopCount{0};
    NoReadReason noReadReason{NoReadReason::READ_OK};
  };

  WriteDebugState writeDebugState;
  ReadDebugState readDebugState;

  std::shared_ptr<LoopDetectorCallback> loopDetectorCallback;

  // Measure rtt between pathchallenge & path response frame
  // Use this measured rtt as init rtt (from Transport Settings)
  TimePoint pathChallengeStartTime;

  /**
   * Eerie data app params functions.
   */
  std::function<bool(const Optional<std::string>&, const BufPtr&)>
      earlyDataAppParamsValidator;
  std::function<BufPtr()> earlyDataAppParamsGetter;

  /**
   * Selects a previously unused peer-issued connection id to use.
   * If there are no available ids return false and don't change anything.
   * Return true if replacement succeeds.
   */
  bool retireAndSwitchPeerConnectionIds();

  // SocketObserverContainer
  //
  // Stored as a weak_ptr to ensure that delayed destruction of
  // QuicConnectionStateBase does not prevent the SocketObserverContainer
  // from being destroyed.
  std::weak_ptr<SocketObserverContainer> observerContainer;

  /**
   * Returns the SocketObserverContainer or nullptr if not available.
   */
  SocketObserverContainer* getSocketObserverContainer() const {
    if (const auto observerContainerLocked = observerContainer.lock()) {
      return observerContainerLocked.get();
    }
    return nullptr;
  }

  // Recent ACK events, for use in processCallbacksAfterNetworkData.
  // Holds the ACK events generated during the last round of ACK processing.
  std::vector<AckEvent> lastProcessedAckEvents;

  // Type of node owning this connection (client or server).
  QuicNodeType nodeType;

  // Whether or not we received a new packet before a write.
  bool receivedNewPacketBeforeWrite{false};

  // Whether we've set the transporot parameters from transportSettings yet.
  bool transportParametersEncoded{false};

  // Whether a connection can be paced based on its handshake and close states.
  // For example, we may not want to pace a connection that's still handshaking.
  bool canBePaced{false};

  // Tracking of application limited time.
  AppLimitedTracker appLimitedTracker;

  // Monotonically increasing counter that is incremented each time there is a
  // write on this socket (writeSocketData() is called), This is used to
  // identify specific outstanding packets (based on writeCount and packetNum)
  // in the Observers, to construct Write Blocks
  uint64_t writeCount{0};

  // Number of DSR packets sent by this connection.
  uint64_t dsrPacketCount{0};

  // Whether we successfully used 0-RTT keys in this connection.
  bool usedZeroRtt{false};

  // Number of probe packets that were writableBytesLimited
  uint64_t numProbesWritableBytesLimited{0};

  struct DatagramState {
    uint32_t maxReadFrameSize{kDefaultMaxDatagramFrameSize};
    uint32_t maxWriteFrameSize{kDefaultMaxDatagramFrameSize};
    uint32_t maxReadBufferSize{kDefaultMaxDatagramsBuffered};
    uint32_t maxWriteBufferSize{kDefaultMaxDatagramsBuffered};
    // Buffers Incoming Datagrams
    CircularDeque<ReadDatagram> readBuffer;
    // Buffers Outgoing Datagrams
    CircularDeque<BufQueue> writeBuffer;
  };

  DatagramState datagramState;

  // Peer max stream groups advertised.
  OptionalIntegral<uint64_t> peerAdvertisedMaxStreamGroups;

  // Sequence number to use for the next ACK_FREQUENCY frame
  uint64_t nextAckFrequencyFrameSequenceNumber{0};

  // GSO supported on conn.
  Optional<bool> gsoSupported;

  Optional<AckReceiveTimestampsConfig> maybePeerAckReceiveTimestampsConfig;

  bool peerAdvertisedReliableStreamResetSupport{false};

  bool peerAdvertisedKnobFrameSupport{false};

  ExtendedAckFeatureMaskType peerAdvertisedExtendedAckFeatures{0};

  // Negotiated ACK related config. These don't change throughout the connection
  // so cache them once we've receive the relevant transport parameters.
  bool negotiatedAckReceiveTimestampSupport{false};
  ExtendedAckFeatureMaskType negotiatedExtendedAckFeatures{0};

  // Retransmission policies map.
  UnorderedMap<StreamGroupId, QuicStreamGroupRetransmissionPolicy>
      retransmissionPolicies;

  struct SocketCmsgsState {
    Optional<folly::SocketCmsgMap> additionalCmsgs;
    // The write count which this SocketCmsgs state is intended for.
    // This is used to make sure this cmsgs list does not end up used
    // for multiple writes.
    uint64_t targetWriteCount;
  };

  SocketCmsgsState socketCmsgsState;

  ECNState ecnState{ECNState::NotAttempted};
  std::shared_ptr<EcnL4sTracker> ecnL4sTracker;

  union TosHeader {
    uint8_t value{0};

    struct components {
      unsigned int ecn : 2;
      unsigned int dscp : 6;
    } fields;
  };

  TosHeader socketTos;

  // Number of QUIC initial packets received.
  uint16_t initialPacketsReceived{0};

  // Number of QUIC unique crypto frame received with initial package.
  uint16_t uniqueInitialCryptoFramesReceived{0};

  // In priming mode data is written here instead of on the network
  std::vector<std::unique_ptr<folly::IOBuf>> primingData;
};

std::ostream& operator<<(std::ostream& os, const QuicConnectionStateBase& st);

struct AckStateVersion {
  uint64_t initialAckStateVersion{kDefaultIntervalSetVersion};
  uint64_t handshakeAckStateVersion{kDefaultIntervalSetVersion};
  uint64_t appDataAckStateVersion{kDefaultIntervalSetVersion};

  AckStateVersion(
      uint64_t initialVersion,
      uint64_t handshakeVersion,
      uint64_t appDataVersion);

  AckStateVersion() = default;

  bool operator==(const AckStateVersion& other) const;
  bool operator!=(const AckStateVersion& other) const;
};

using LossVisitor = std::function<quic::Expected<void, QuicError>(
    QuicConnectionStateBase& conn,
    RegularQuicWritePacket& packet,
    bool processed)>;

} // namespace quic

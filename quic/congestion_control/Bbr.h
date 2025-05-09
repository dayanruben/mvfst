/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/Bandwidth.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/congestion_control/third_party/windowed_filter.h>
#include <quic/state/StateData.h>
#include <quic/state/TransportSettings.h>
#include <chrono>

namespace quic {

// Cwnd and pacing gain during STARTUP
constexpr float kStartupGain = 2.885f; // 2/ln(2)
// Cwnd gain during ProbeBw
constexpr float kProbeBwGain = 2.0f;
// The expected of bandwidth growth in each round trip time during STARTUP
constexpr float kExpectedStartupGrowth = 1.25f;
// How many rounds of rtt to stay in STARTUP when the bandwidth isn't growing as
// fast as kExpectedStartupGrowth
constexpr uint8_t kStartupSlowGrowRoundLimit = 3;
// Default number of pacing cycles
constexpr uint8_t kNumOfCycles = 8;
// Default pacing cycles
constexpr std::array<float, kNumOfCycles> kPacingGainCycles =
    {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0};
// During ProbeRtt, we need to stay in low inflight condition for at least
// kProbeRttDuration.
constexpr std::chrono::milliseconds kProbeRttDuration{200};
// The cwnd gain to use when ccaConfig.largeProbeRttCwnd is set.
constexpr float kLargeProbeRttCwndGain = 0.75f;

// Bandwidth WindowFilter length, in unit of RTT. This value is from Chromium
// code. I don't know why.
constexpr uint8_t bandwidthWindowLength(const uint8_t numOfCycles) {
  return numOfCycles + 2;
}

// RTT Sampler default expiration
constexpr std::chrono::seconds kDefaultRttSamplerExpiration{10};
// 64K, used in sendQuantum calculation:
constexpr uint64_t k64K = 64 * 1024;

// TODO: rate based startup mode
// TODO: send extra bandwidth probers when pipe isn't sufficiently full
class BbrCongestionController : public CongestionController {
 public:
  /**
   * A class to collect RTT samples, tracks the minimal one among them, and
   * expire the min rtt sample after some period of time.
   */
  class MinRttSampler {
   public:
    virtual ~MinRttSampler() = default;
    virtual std::chrono::microseconds minRtt() const = 0;

    /**
     * Returns: true iff we have min rtt sample and it has expired.
     */
    virtual bool minRttExpired() const = 0;

    /**
     * rttSample: current rtt sample
     * sampledTime: the time point this sample is collected
     *
     * return: whether min rtt is updated by the new sample
     */
    virtual bool newRttSample(
        std::chrono::microseconds rttSample,
        TimePoint sampledTime) noexcept = 0;

    /**
     * Mark timestamp as the minrtt time stamp. Min rtt will expire at
     * timestampe + expiration_duration.
     */
    virtual void timestampMinRtt(TimePoint timestamp) noexcept = 0;
  };

  class BandwidthSampler {
   public:
    virtual ~BandwidthSampler() = default;

    virtual Bandwidth getBandwidth() const = 0;

    [[nodiscard]] virtual Bandwidth getLatestSample() const = 0;

    virtual void onPacketAcked(
        const CongestionController::AckEvent&,
        uint64_t roundTripCounter) = 0;

    virtual void onAppLimited() = 0;
    virtual bool isAppLimited() const = 0;
    virtual void setWindowLength(const uint64_t windowLength) noexcept = 0;
  };

  explicit BbrCongestionController(QuicConnectionStateBase& conn);
  explicit BbrCongestionController(
      QuicConnectionStateBase& conn,
      uint64_t cwndBytes,
      std::chrono::microseconds minRtt);

  // TODO: these should probably come in as part of a builder. but I'm not sure
  // if the sampler interface is here to stay atm, so bear with me
  void setRttSampler(std::unique_ptr<MinRttSampler> sampler) noexcept;
  void setBandwidthSampler(std::unique_ptr<BandwidthSampler> sampler) noexcept;

  enum class BbrState : uint8_t {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
  };

  enum class RecoveryState : uint8_t {
    NOT_RECOVERY = 0,
    CONSERVATIVE = 1,
    GROWTH = 2,
  };

  void onRemoveBytesFromInflight(uint64_t bytesToRemove) override;
  void onPacketSent(const OutstandingPacketWrapper&) override;
  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE,
      const LossEvent* FOLLY_NULLABLE) override;

  void onPacketAckOrLoss(Optional<AckEvent> ack, Optional<LossEvent> loss) {
    onPacketAckOrLoss(
        ack.has_value() ? &ack.value() : nullptr,
        loss.has_value() ? &loss.value() : nullptr);
  }

  uint64_t getWritableBytes() const noexcept override;

  uint64_t getCongestionWindow() const noexcept override;

  [[nodiscard]] Optional<Bandwidth> getBandwidth() const noexcept override;

  CongestionControlType type() const noexcept override;
  void setAppIdle(bool idle, TimePoint eventTime) noexcept override;
  void setAppLimited() override;

  void setExperimental(bool experimental) override;

  bool isAppLimited() const noexcept override;

  void getStats(CongestionControllerStats& stats) const override;

  // TODO: some of these do not have to be in public API.
  bool inRecovery() const noexcept;
  BbrState state() const noexcept;

 protected:
  [[nodiscard]] virtual Bandwidth bandwidth() const noexcept;

  std::unique_ptr<MinRttSampler> minRttSampler_;
  std::unique_ptr<BandwidthSampler> bandwidthSampler_;

  float cwndGain_{kStartupGain};
  float pacingGain_{kStartupGain};
  // Whether we have found the bottleneck link bandwidth
  bool btlbwFound_{false};

  QuicConnectionStateBase& conn_;
  BbrState state_{BbrState::Startup};
  RecoveryState recoveryState_{RecoveryState::NOT_RECOVERY};

 private:
  /* prevInflightBytes: the inflightBytes value before the current
   *                    onPacketAckOrLoss invocation.
   * hasLoss: whether current onPacketAckOrLoss has loss.
   */
  void
  onPacketAcked(const AckEvent& ack, uint64_t prevInflightBytes, bool hasLoss);
  void onPacketLoss(const LossEvent&, uint64_t ackedBytes);
  void updatePacing() noexcept;

  /**
   * Update the ack aggregation states
   *
   * return: the excessive bytes from ack aggregation.
   *
   * Ack Aggregation: starts when ack arrival rate is slower than estimated
   * bandwidth, lasts until it's faster than estimated bandwidth.
   */
  uint64_t updateAckAggregation(const AckEvent& ack);
  /**
   * Check if we have found the bottleneck link bandwidth with the current ack.
   */
  void detectBottleneckBandwidth(bool);

  bool shouldExitStartup() noexcept;
  bool shouldExitDrain() noexcept;
  bool shouldProbeRtt(TimePoint ackTime) noexcept;
  void transitToDrain() noexcept;
  void transitToProbeBw(TimePoint congestionEventTime);
  void transitToProbeRtt() noexcept;
  void transitToStartup() noexcept;

  // Pick a random pacing cycle except 1
  size_t pickRandomCycle();

  // Special handling of AckEvent when connection is in ProbeRtt state
  void handleAckInProbeRtt(bool newRoundTrip, TimePoint ackTime) noexcept;
  /**
   * Special handling of AckEvent when connection is in ProbeBw state.
   *
   * prevInflightBytes: the inflightBytes value before the current
   *                    onPacketAckOrLoss invocation.
   * hasLoss: whether the current onpacketAckOrLoss has loss.
   */
  void handleAckInProbeBw(
      TimePoint ackTime,
      uint64_t prevInflightBytes,
      bool hasLoss) noexcept;

  /*
   * Return if we are at the start of a new round trip.
   */
  bool updateRoundTripCounter(TimePoint largestAckedSentTime) noexcept;
  void updateRecoveryWindowWithAck(uint64_t bytesAcked) noexcept;

  uint64_t calculateTargetCwnd(float gain) const noexcept;
  void updateCwnd(uint64_t ackedBytes, uint64_t excessiveBytes) noexcept;
  std::chrono::microseconds minRtt() const noexcept;

  bool isExperimental_{false};
  // Number of round trips the connection has witnessed
  uint64_t roundTripCounter_{0};
  // When a packet with send time later than endOfRoundTrip_ is acked, the
  // current round strip is ended.
  TimePoint endOfRoundTrip_;
  // When a packet with send time later than endOfRecovery_ is acked, the
  // connection is no longer in recovery
  Optional<TimePoint> endOfRecovery_;
  // Cwnd in bytes
  uint64_t cwnd_;
  // Initial cwnd in bytes
  uint64_t initialCwnd_;
  // Congestion window when the connection is in recovery
  uint64_t recoveryWindow_;
  // Number of bytes we expect to send over one RTT when paced write.
  uint64_t pacingWindow_{0};

  // ProbeBw parameters
  uint64_t numOfCycles_{kNumOfCycles};
  std::vector<float> pacingGainCycles_;

  uint64_t sendQuantum_{0};

  Bandwidth previousStartupBandwidth_;

  // Counter of continuous round trips in STARTUP that bandwidth isn't growing
  // fast enough
  uint8_t slowStartupRoundCounter_{0};

  // Current cycle index in kPacingGainCycles
  size_t pacingCycleIndex_{0};
  // The starting time of this pacing cycle. The cycle index will proceed by 1
  // when we are one minrtt away from this time point.
  TimePoint cycleStart_;

  // Once in ProbeRtt state, we cannot exit ProbeRtt before at least we spend
  // some duration with low inflight bytes. earliestTimeToExitProbeRtt_ is that
  // time point.
  Optional<TimePoint> earliestTimeToExitProbeRtt_;
  // We also cannot exit ProbeRtt if are not at least at the low inflight bytes
  // mode for one RTT round. probeRttRound_ tracks that.
  Optional<uint64_t> probeRttRound_;

  WindowedFilter<
      uint64_t /* ack bytes count */,
      MaxFilter<uint64_t>,
      uint64_t /* roundtrip count */,
      uint64_t /* roundtrip count */>
      maxAckHeightFilter_;
  Optional<TimePoint> ackAggregationStartTime_;
  uint64_t aggregatedAckBytes_{0};

  bool appLimitedSinceProbeRtt_{false};
  // The connection was very inactive and we are leaving that.
  bool exitingQuiescene_{false};

  // The last max ACK delay requested, so we don't end up sending
  // them too frequently.
  Optional<std::chrono::milliseconds> lastMaxAckDelay_;
  Optional<uint32_t> lastAckThreshold_;

  friend std::ostream& operator<<(
      std::ostream& os,
      const BbrCongestionController& bbr);
};

std::ostream& operator<<(std::ostream& os, const BbrCongestionController& bbr);

std::string bbrStateToString(BbrCongestionController::BbrState state);

std::string bbrRecoveryStateToString(
    BbrCongestionController::RecoveryState recoveryState);
} // namespace quic

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/CongestionController.h>
#include <quic/congestion_control/third_party/windowed_filter.h>
#include <quic/state/AckEvent.h>
#include <quic/state/StateData.h>

namespace quic {

using namespace std::chrono_literals;
constexpr std::chrono::microseconds kCopa2MinRttWindowLength{10s};
constexpr std::chrono::microseconds kCopa2ProbeRttInterval{8s};

class Copa2 : public CongestionController {
 public:
  explicit Copa2(QuicConnectionStateBase& conn);
  void onRemoveBytesFromInflight(uint64_t) override;
  void onPacketSent(const OutstandingPacketWrapper& packet) override;
  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE,
      const LossEvent* FOLLY_NULLABLE) override;

  void onPacketAckOrLoss(Optional<AckEvent> ack, Optional<LossEvent> loss) {
    onPacketAckOrLoss(
        ack.has_value() ? &ack.value() : nullptr,
        loss.has_value() ? &loss.value() : nullptr);
  }

  [[nodiscard]] uint64_t getWritableBytes() const noexcept override;
  [[nodiscard]] uint64_t getCongestionWindow() const noexcept override;
  [[nodiscard]] CongestionControlType type() const noexcept override;

  void setAppIdle(bool, TimePoint) noexcept override;
  void setAppLimited() override;
  [[nodiscard]] bool isAppLimited() const noexcept override;

  [[nodiscard]] bool inLossyMode() const noexcept;
  [[nodiscard]] bool inProbeRtt() const noexcept;
  [[nodiscard]] uint64_t getBytesInFlight() const noexcept;

  void getStats(CongestionControllerStats& stats) const override;

 private:
  void onPacketLoss(const LossEvent&);
  void onPacketAcked(const AckEvent&);
  void manageLossyMode(Optional<TimePoint> sentTime);

  QuicConnectionStateBase& conn_;
  uint64_t cwndBytes_;

  // In packets
  uint64_t alphaParam_{10};
  // Loss rate we are willing to tolerate. Actual loss rate will be 2 *
  // lossTolaranceParam_ + alpha/BDP
  double lossToleranceParam_{0.05};

  // To get the min RTT over 10 seconds
  WindowedFilter<
      std::chrono::microseconds,
      MinFilter<std::chrono::microseconds>,
      uint64_t,
      uint64_t>
      minRTTFilter_;

  // Updates happen in cycles.
  Optional<TimePoint> cycleStartTime_;
  bool appLimitedInCycle_{false};
  uint64_t bytesAckedInCycle_{0};

  // We calculate loss rates over enough time that we can get a
  // reliable estimate. We ensure the period includes at-least 1 RTT
  // and an opportunity to lose 2 packets and still exceed the loss tolerance
  uint64_t numAckedInLossCycle_{0};
  uint64_t numLostInLossCycle_{0};
  TimePoint lossCycleStartTime_{Clock::now()};
  bool lossyMode_{false};

  // Whether we are currently in probe RTT
  bool probeRtt_{false};
  // Last time we entered probe RTT
  TimePoint lastProbeRtt_{Clock::now()};

  // Are we currently app limited?
  bool appLimited_{false};
  // When a packet with a send time later than appLimitedExitTarget_ is acked,
  // an app-limited connection is considered no longer app-limited.
  TimePoint appLimitedExitTarget_;
};

} // namespace quic

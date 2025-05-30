/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/TransportSettingsFunctions.h>

namespace quic {

void populateAckFrequencyConfig(
    const folly::dynamic& srcAckFrequencyConfigDyn,
    CongestionControlConfig& dstCcaConfig) {
  if (!dstCcaConfig.ackFrequencyConfig.has_value()) {
    dstCcaConfig.ackFrequencyConfig =
        CongestionControlConfig::AckFrequencyConfig();
  }
  // Parse known boolean fields
  const std::array<std::pair<std::string_view, bool&>, 1> boolFields = {{
      {"useSmallThresholdDuringStartup",
       dstCcaConfig.ackFrequencyConfig->useSmallThresholdDuringStartup},
  }};

  for (const auto& [name, field] : boolFields) {
    if (auto val = srcAckFrequencyConfigDyn.get_ptr(name)) {
      field = val->asBool();
    }
  }

  // Parse known uint64 fields
  const std::array<std::pair<std::string_view, uint64_t&>, 2> uint64Fields = {{
      {"ackElicitingThreshold",
       dstCcaConfig.ackFrequencyConfig->ackElicitingThreshold},
      {"reorderingThreshold",
       dstCcaConfig.ackFrequencyConfig->reorderingThreshold},
  }};

  for (const auto& [name, field] : uint64Fields) {
    if (auto val = srcAckFrequencyConfigDyn.get_ptr(name)) {
      field = folly::to<uint64_t>(val->asString());
    }
  }

  // Parse known uint32 fields
  const std::array<std::pair<std::string_view, uint32_t&>, 1> uint32Fields = {{
      {"minRttDivisor", dstCcaConfig.ackFrequencyConfig->minRttDivisor},
  }};

  for (const auto& [name, field] : uint32Fields) {
    if (auto val = srcAckFrequencyConfigDyn.get_ptr(name)) {
      field = folly::to<uint32_t>(val->asString());
    }
  }
}

// Parses the JSON string into a CongestionControlConfig.
//  - Fields not present in the JSON string will use their default values
//  - Additional fields in the JSON string will be ignored
//  - Throws if parsing fails or fields have a wrong type
quic::CongestionControlConfig parseCongestionControlConfig(
    const std::string& ccaConfigJson) {
  const folly::dynamic ccaConfigDyn = folly::parseJson(ccaConfigJson);
  quic::CongestionControlConfig ccaConfig;

  // Parse known boolean fields
  const std::array<std::pair<std::string_view, bool&>, 17> boolFields = {{
      {"conservativeRecovery", ccaConfig.conservativeRecovery},
      {"largeProbeRttCwnd", ccaConfig.largeProbeRttCwnd},
      {"enableAckAggregationInStartup",
       ccaConfig.enableAckAggregationInStartup},
      {"probeRttDisabledIfAppLimited", ccaConfig.probeRttDisabledIfAppLimited},
      {"drainToTarget", ccaConfig.drainToTarget},
      {"additiveIncreaseAfterHystart", ccaConfig.additiveIncreaseAfterHystart},
      {"onlyGrowCwndWhenLimited", ccaConfig.onlyGrowCwndWhenLimited},
      {"leaveHeadroomForCwndLimited", ccaConfig.leaveHeadroomForCwndLimited},
      {"ignoreInflightHi", ccaConfig.ignoreInflightLongTerm},
      {"ignoreLoss", ccaConfig.ignoreShortTerm},
      {"enableRecoveryInStartup", ccaConfig.enableRecoveryInStartup},
      {"enableRecoveryInProbeStates", ccaConfig.enableRecoveryInProbeStates},
      {"exitStartupOnLoss", ccaConfig.exitStartupOnLoss},
      {"enableRenoCoexistence", ccaConfig.enableRenoCoexistence},
      {"paceInitCwnd", ccaConfig.paceInitCwnd},
      {"ignoreInflightLongTerm", ccaConfig.ignoreInflightLongTerm},
      {"ignoreShortTerm", ccaConfig.ignoreShortTerm},
  }};

  for (const auto& [name, field] : boolFields) {
    if (auto val = ccaConfigDyn.get_ptr(name)) {
      field = val->asBool();
    }
  }

  // Parse optional float fields
  const std::array<std::pair<std::string_view, float&>, 4> floatFields = {
      {{"overrideCruisePacingGain", ccaConfig.overrideCruisePacingGain},
       {"overrideCruiseCwndGain", ccaConfig.overrideCruiseCwndGain},
       {"overrideStartupPacingGain", ccaConfig.overrideStartupPacingGain},
       {"overrideBwShortBeta", ccaConfig.overrideBwShortBeta}}};

  for (const auto& [name, field] : floatFields) {
    if (auto val = ccaConfigDyn.get_ptr(name)) {
      field = static_cast<float>(val->asDouble());
    }
  }

  // Parse ack frequency config if present
  if (auto ackFrequencyConfigDyn = ccaConfigDyn.get_ptr("ackFrequencyConfig")) {
    populateAckFrequencyConfig(*ackFrequencyConfigDyn, ccaConfig);
  }

  return ccaConfig;
}

// Same as parse function but returns std::nullopt on error instead of throwing.
Optional<quic::CongestionControlConfig> tryParseCongestionControlConfig(
    const std::string& ccaConfigJson) {
  try {
    quic::CongestionControlConfig ccaConfig;
    ccaConfig = parseCongestionControlConfig(ccaConfigJson);
    return ccaConfig;
  } catch (const std::exception&) {
    return std::nullopt;
  }
  folly::assume_unreachable();
}
} // namespace quic

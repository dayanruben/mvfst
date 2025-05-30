/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/json/json.h> // @manual=//folly:dynamic
#include <glog/logging.h>
#include <quic/QuicConstants.h>
#include <quic/common/TransportKnobs.h>

namespace quic {

namespace {

constexpr uint64_t kKnobFractionMax = 100;

bool compareTransportKnobParam(
    const TransportKnobParam& lhs,
    const TransportKnobParam& rhs) {
  // Sort param by id, then value
  if (lhs.id != rhs.id) {
    return lhs.id < rhs.id;
  }
  return lhs.val < rhs.val;
}

} // namespace

Optional<TransportKnobParams> parseTransportKnobs(
    const std::string& serializedParams) {
  TransportKnobParams knobParams;
  try {
    // leave numbers as strings so that we can use uint64_t number space
    // (JSON only supports int64; numbers larger than this will trigger throw)
    folly::json::serialization_opts opts;
    opts.parse_numbers_as_strings = true;
    folly::dynamic params = folly::parseJson(serializedParams, opts);
    for (const auto& id : params.keys()) {
      auto paramId = static_cast<uint64_t>(id.asInt());
      auto val = params[id];
      switch (val.type()) {
        case folly::dynamic::Type::BOOL:
          knobParams.push_back({paramId, static_cast<uint64_t>(val.asInt())});
          continue;
        case folly::dynamic::Type::STRING: {
          /*
           * try to parse as an integer first, unless known to be string knob
           * we parse manually to enable us to support uint64_t
           */
          switch (paramId) {
            case TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED:
              knobParams.push_back({paramId, val.asString()});
              continue; // triggers next loop iteration
            case TransportKnobParamId::CC_ALGORITHM_KNOB:
            case TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB:
            case TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB:
            case TransportKnobParamId::ACK_FREQUENCY_POLICY:
            case TransportKnobParamId::CC_CONFIG:
            case TransportKnobParamId::NO_OP:
              break;
            default:
              if (const auto expectAsInt =
                      folly::tryTo<uint64_t>(val.asString())) {
                knobParams.push_back({paramId, expectAsInt.value()});
                continue; // triggers next loop iteration
              }
              return std::nullopt; // error parsing integer parameter
          }

          /*
           * set cc algorithm
           * expected format: string, all lower case, name of cc algorithm
           */
          if (paramId ==
              static_cast<uint64_t>(TransportKnobParamId::CC_ALGORITHM_KNOB)) {
            std::optional<CongestionControlType> cctype =
                congestionControlStrToType(val.asString());
            if (cctype) {
              knobParams.push_back(
                  {paramId, static_cast<uint64_t>(cctype.value())});
            } else {
              LOG(ERROR) << "unknown cc type " << val;
              return std::nullopt;
            }
            /*
             * set rtt factor used in cc algs like bbr or copa
             * expressed as a fraction (see
             * quic/congestion_control/TokenlessPacer.cpp) expected format:
             * string, "{numerator}/{denominator}" numerator and denominator
             * must both be in the range (0,MAX]
             */
          } else if (
              paramId ==
                  static_cast<uint64_t>(
                      TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB) ||
              paramId ==
                  static_cast<uint64_t>(
                      TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB)) {
            auto s = val.asString();
            uint64_t factor = 0;
            auto pos = s.find('/');
            if (pos == std::string::npos) {
              LOG(ERROR)
                  << "rtt factor knob expected format {numerator}/{denominator}";
              return std::nullopt;
            }
            uint64_t numerator =
                folly::tryTo<int>(s.substr(0, pos)).value_or(kKnobFractionMax);
            uint64_t denominator =
                folly::tryTo<int>(s.substr(pos + 1, s.length()))
                    .value_or(kKnobFractionMax);
            if (numerator <= 0 || denominator <= 0 ||
                numerator >= kKnobFractionMax ||
                denominator >= kKnobFractionMax) {
              LOG(ERROR)
                  << "rtt factor knob numerator and denominator must be ints in range (0,"
                  << kKnobFractionMax << "]";
              return std::nullopt;
            }
            // transport knobs must be a single int, so we pack numerator and
            // denominator into a single int here and unpack in the handler
            factor = numerator * kKnobFractionMax + denominator;
            knobParams.push_back({paramId, factor});
          } else if (paramId == TransportKnobParamId::NO_OP) {
            // No further processing needed. Ignore this knob parameter.
            VLOG(4) << "Skipping over noop transport knob";
            continue;
          } else if (paramId == TransportKnobParamId::ACK_FREQUENCY_POLICY) {
            knobParams.push_back({paramId, val.asString()});
          } else if (paramId == TransportKnobParamId::CC_CONFIG) {
            knobParams.push_back({paramId, val.asString()});
          } else {
            LOG(ERROR)
                << "string param type is not valid for this knob with id= "
                << TransportKnobParamId::_from_integral(paramId);
            return std::nullopt;
          }
          continue;
        }
        default:
          // Quic transport knob param values cannot be of type ARRAY, NULLT or
          // OBJECT
          LOG(ERROR) << "Invalid transport knob param value type" << val.type();
          return std::nullopt;
      }
    }
  } catch (const std::exception& e) {
    LOG(ERROR) << "fail to parse knobs: " << e.what();
    return std::nullopt;
  }

  std::sort(knobParams.begin(), knobParams.end(), compareTransportKnobParam);
  return knobParams;
}

} // namespace quic

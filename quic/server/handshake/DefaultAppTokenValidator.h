/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/server/State.h>

#include <folly/io/IOBuf.h>
#include <quic/common/Optional.h>

#include <memory>
#include <string>

namespace fizz::server {
struct ResumptionState;
} // namespace fizz::server

namespace quic {
struct QuicServerConnectionState;

class DefaultAppTokenValidator : public fizz::server::AppTokenValidator {
 public:
  explicit DefaultAppTokenValidator(QuicServerConnectionState* conn);

  bool validate(const fizz::server::ResumptionState&) const override;

 private:
  QuicServerConnectionState* conn_;
};

} // namespace quic

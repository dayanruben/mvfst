/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/Aead.h>
#include <fizz/protocol/Types.h>
#include <quic/QuicConstants.h>
#include <quic/handshake/Aead.h>

#include <memory>
#include <utility>

namespace quic {

class FizzAead final : public Aead {
 public:
  static std::unique_ptr<FizzAead> wrap(
      std::unique_ptr<fizz::Aead> fizzAeadIn) {
    if (!fizzAeadIn) {
      return nullptr;
    }

    return std::unique_ptr<FizzAead>(new FizzAead(std::move(fizzAeadIn)));
  }

  [[nodiscard]] Optional<TrafficKey> getKey() const override;

  /**
   * Forward calls to fizz::Aead, catching any exceptions and converting them to
   * quic::Expected.
   */
  quic::Expected<BufPtr, QuicError> inplaceEncrypt(
      BufPtr&& plaintext,
      const Buf* associatedData,
      uint64_t seqNum) const override {
    try {
      BufPtr ret;
      fizz::Error err;
      FIZZ_THROW_ON_ERROR(
          fizzAead->inplaceEncrypt(
              ret, err, std::move(plaintext), associatedData, seqNum),
          err);
      return ret;
    } catch (const std::exception& ex) {
      return quic::make_unexpected(
          QuicError(TransportErrorCode::INTERNAL_ERROR, ex.what()));
    }
  }

  BufPtr decrypt(
      BufPtr&& ciphertext,
      const Buf* associatedData,
      uint64_t seqNum) const override {
    fizz::Aead::AeadOptions options;
    options.bufferOpt = fizz::Aead::BufferOption::AllowInPlace;
    BufPtr ret;
    fizz::Error err;
    FIZZ_THROW_ON_ERROR(
        fizzAead->decrypt(
            ret, err, std::move(ciphertext), associatedData, seqNum, options),
        err);
    return ret;
  }

  Optional<BufPtr> tryDecrypt(
      BufPtr&& ciphertext,
      const Buf* associatedData,
      uint64_t seqNum) const override {
    fizz::Aead::AeadOptions options;
    options.bufferOpt = fizz::Aead::BufferOption::AllowInPlace;
    folly::Optional<BufPtr> result;
    fizz::Error err;
    FIZZ_THROW_ON_ERROR(
        fizzAead->tryDecrypt(
            result,
            err,
            std::move(ciphertext),
            associatedData,
            seqNum,
            options),
        err);
    if (result.has_value()) {
      return Optional<BufPtr>(std::move(result.value()));
    } else {
      return Optional<BufPtr>();
    }
  }

  [[nodiscard]] size_t getCipherOverhead() const override {
    return fizzAead->getCipherOverhead();
  }

 private:
  std::unique_ptr<fizz::Aead> fizzAead;

  explicit FizzAead(std::unique_ptr<fizz::Aead> fizzAeadIn)
      : fizzAead(std::move(fizzAeadIn)) {}
};

EncryptionLevel getEncryptionLevelFromFizz(
    const fizz::EncryptionLevel encryptionLevel);

} // namespace quic

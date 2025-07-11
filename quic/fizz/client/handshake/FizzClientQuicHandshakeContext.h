/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/client/AsyncFizzClient.h>
#include <fizz/client/ECHPolicy.h>
#include <quic/client/handshake/ClientHandshakeFactory.h>

#include <quic/fizz/client/handshake/QuicPskCache.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>

#include <fizz/client/FizzClientContext.h>
#include <fizz/protocol/DefaultCertificateVerifier.h>
#include <memory>

namespace quic {

class FizzClientHandshake;

class FizzClientQuicHandshakeContext
    : public ClientHandshakeFactory,
      public std::enable_shared_from_this<FizzClientQuicHandshakeContext> {
 public:
  std::unique_ptr<ClientHandshake>
      makeClientHandshake(QuicClientConnectionState* conn) && override;

  const std::shared_ptr<const fizz::client::FizzClientContext>& getContext()
      const {
    return context_;
  }

  const std::shared_ptr<const fizz::CertificateVerifier>&
  getCertificateVerifier() const {
    return verifier_;
  }

  folly::Optional<QuicCachedPsk> getPsk(const Optional<std::string>& hostname);
  void putPsk(
      const Optional<std::string>& hostname,
      QuicCachedPsk quicCachedPsk);
  void removePsk(const Optional<std::string>& hostname);

  Optional<std::vector<fizz::ech::ParsedECHConfig>> getECHConfigs(
      const std::string& sni) const;

  void setECHRetryCallback(
      std::shared_ptr<fizz::client::ECHRetryCallback> callback) {
    echRetryCallback_ = callback;
  }

  uint16_t getChloPaddingBytes() const {
    return chloPaddingBytes_;
  }

 private:
  /**
   * We make the constructor private so that users have to use the Builder
   * facility. This ensures that
   *   - This will ALWAYS be managed by a shared_ptr, which the implementation
   * expects.
   *   - We can enforce that the internal state of FizzClientContext is always
   * sane.
   */
  FizzClientQuicHandshakeContext(
      std::shared_ptr<const fizz::client::FizzClientContext> context,
      std::shared_ptr<const fizz::CertificateVerifier> verifier,
      std::shared_ptr<QuicPskCache> pskCache,
      std::shared_ptr<fizz::client::ECHPolicy> echPolicy,
      std::shared_ptr<fizz::client::ECHRetryCallback> echRetryCallback,
      uint16_t chloPaddingBytes);

  FizzClientQuicHandshakeContext(
      std::shared_ptr<const fizz::client::FizzClientContext> context,
      std::shared_ptr<const fizz::CertificateVerifier> verifier,
      std::shared_ptr<QuicPskCache> pskCache,
      std::unique_ptr<FizzCryptoFactory> cryptoFactory,
      std::shared_ptr<fizz::client::ECHPolicy> echPolicy,
      std::shared_ptr<fizz::client::ECHRetryCallback> echRetryCallback,
      uint16_t chloPaddingBytes);

  std::shared_ptr<const fizz::client::FizzClientContext> context_;
  std::shared_ptr<const fizz::CertificateVerifier> verifier_;
  std::shared_ptr<QuicPskCache> pskCache_;
  std::shared_ptr<fizz::client::ECHPolicy> echPolicy_;
  std::shared_ptr<fizz::client::ECHRetryCallback> echRetryCallback_;
  std::unique_ptr<FizzCryptoFactory> cryptoFactory_;
  uint16_t chloPaddingBytes_{0};

 public:
  class Builder {
   public:
    Builder&& setFizzClientContext(
        std::shared_ptr<const fizz::client::FizzClientContext> context) && {
      context_ = std::move(context);
      return std::move(*this);
    }

    Builder&& setCertificateVerifier(
        std::shared_ptr<const fizz::CertificateVerifier> verifier) && {
      verifier_ = std::move(verifier);
      return std::move(*this);
    }

    Builder&& setPskCache(std::shared_ptr<QuicPskCache> pskCache) && {
      pskCache_ = std::move(pskCache);
      return std::move(*this);
    }

    Builder&& setECHPolicy(
        std::shared_ptr<fizz::client::ECHPolicy> echPolicy) && {
      echPolicy_ = std::move(echPolicy);
      return std::move(*this);
    }

    Builder&& setECHRetryCallback(
        std::shared_ptr<fizz::client::ECHRetryCallback> echRetryCallback) && {
      echRetryCallback_ = std::move(echRetryCallback);
      return std::move(*this);
    }

    Builder&& setCryptoFactory(std::unique_ptr<FizzCryptoFactory> factory) && {
      cryptoFactory_ = std::move(factory);
      return std::move(*this);
    }

    Builder&& setChloPaddingBytes(uint16_t chloPaddingBytes) && {
      chloPaddingBytes_ = chloPaddingBytes;
      return std::move(*this);
    }

    std::shared_ptr<FizzClientQuicHandshakeContext> build() &&;

   private:
    std::shared_ptr<const fizz::client::FizzClientContext> context_;
    std::shared_ptr<const fizz::CertificateVerifier> verifier_;
    std::shared_ptr<QuicPskCache> pskCache_;
    std::shared_ptr<fizz::client::ECHPolicy> echPolicy_;
    std::shared_ptr<fizz::client::ECHRetryCallback> echRetryCallback_;
    std::unique_ptr<FizzCryptoFactory> cryptoFactory_;
    uint16_t chloPaddingBytes_{0};
  };
};

} // namespace quic

/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <fizz/crypto/Utils.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>

#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/FizzPacketNumberCipher.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic {

quic::Expected<BufPtr, QuicError> FizzCryptoFactory::makeInitialTrafficSecret(
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  auto deriver =
      fizzFactory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto connIdRange = quic::ByteRange(
      clientDestinationConnId.data(), clientDestinationConnId.size());
  folly::StringPiece salt = getQuicVersionSalt(version);
  auto initialSecret = deriver->hkdfExtract(salt, connIdRange);
  auto trafficSecret = deriver->expandLabel(
      ByteRange(initialSecret.data(), initialSecret.size()),
      label,
      BufHelpers::create(0),
      fizz::Sha256::HashLen);
  return trafficSecret;
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
FizzCryptoFactory::makeInitialAead(
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  auto trafficSecretResult =
      makeInitialTrafficSecret(label, clientDestinationConnId, version);
  if (!trafficSecretResult.has_value()) {
    return quic::make_unexpected(trafficSecretResult.error());
  }
  auto& trafficSecret = trafficSecretResult.value();

  auto deriver =
      fizzFactory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto aead = fizzFactory_->makeAead(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto key = deriver->expandLabel(
      trafficSecret->coalesce(),
      kQuicKeyLabel,
      BufHelpers::create(0),
      aead->keyLength());
  auto iv = deriver->expandLabel(
      trafficSecret->coalesce(),
      kQuicIVLabel,
      BufHelpers::create(0),
      aead->ivLength());

  fizz::TrafficKey trafficKey;
  trafficKey.key = std::move(key);
  trafficKey.iv = std::move(iv);
  aead->setKey(std::move(trafficKey));
  return FizzAead::wrap(std::move(aead));
}

quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
FizzCryptoFactory::makePacketNumberCipher(ByteRange baseSecret) const {
  auto pnCipherResult =
      makePacketNumberCipher(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  if (!pnCipherResult.has_value()) {
    return quic::make_unexpected(pnCipherResult.error());
  }
  auto pnCipher = std::move(pnCipherResult.value());

  auto deriver =
      fizzFactory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto pnKey = deriver->expandLabel(
      baseSecret, kQuicPNLabel, BufHelpers::create(0), pnCipher->keyLength());
  auto setKeyResult = pnCipher->setKey(pnKey->coalesce());
  if (!setKeyResult.has_value()) {
    return quic::make_unexpected(setKeyResult.error());
  }
  return pnCipher;
}

quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
FizzCryptoFactory::makePacketNumberCipher(fizz::CipherSuite cipher) const {
  switch (cipher) {
    case fizz::CipherSuite::TLS_AES_128_GCM_SHA256:
      return std::make_unique<Aes128PacketNumberCipher>();
    case fizz::CipherSuite::TLS_AES_256_GCM_SHA384:
      return std::make_unique<Aes256PacketNumberCipher>();
    default:
      return quic::make_unexpected(QuicError(
          TransportErrorCode::INTERNAL_ERROR,
          "Packet number cipher not implemented"));
  }
}

std::function<bool(ByteRange, ByteRange)>
FizzCryptoFactory::getCryptoEqualFunction() const {
  return fizz::CryptoUtils::equal;
}
} // namespace quic

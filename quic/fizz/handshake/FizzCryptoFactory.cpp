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

BufPtr FizzCryptoFactory::makeInitialTrafficSecret(
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  auto deriver =
      fizzFactory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto connIdRange = folly::range(clientDestinationConnId);
  folly::StringPiece salt = getQuicVersionSalt(version);
  auto initialSecret = deriver->hkdfExtract(salt, connIdRange);
  auto trafficSecret = deriver->expandLabel(
      folly::range(initialSecret),
      label,
      BufHelpers::create(0),
      fizz::Sha256::HashLen);
  return trafficSecret;
}

std::unique_ptr<Aead> FizzCryptoFactory::makeInitialAead(
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  auto trafficSecret =
      makeInitialTrafficSecret(label, clientDestinationConnId, version);
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

  fizz::TrafficKey trafficKey = {std::move(key), std::move(iv)};
  aead->setKey(std::move(trafficKey));
  return FizzAead::wrap(std::move(aead));
}

std::unique_ptr<PacketNumberCipher> FizzCryptoFactory::makePacketNumberCipher(
    ByteRange baseSecret) const {
  auto pnCipher =
      makePacketNumberCipher(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto deriver =
      fizzFactory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto pnKey = deriver->expandLabel(
      baseSecret, kQuicPNLabel, BufHelpers::create(0), pnCipher->keyLength());
  pnCipher->setKey(pnKey->coalesce());
  return pnCipher;
}

std::unique_ptr<PacketNumberCipher> FizzCryptoFactory::makePacketNumberCipher(
    fizz::CipherSuite cipher) const {
  switch (cipher) {
    case fizz::CipherSuite::TLS_AES_128_GCM_SHA256:
      return std::make_unique<Aes128PacketNumberCipher>();
    case fizz::CipherSuite::TLS_AES_256_GCM_SHA384:
      return std::make_unique<Aes256PacketNumberCipher>();
    default:
      throw std::runtime_error("Packet number cipher not implemented");
  }
}

std::function<bool(ByteRange, ByteRange)>
FizzCryptoFactory::getCryptoEqualFunction() const {
  return fizz::CryptoUtils::equal;
}
} // namespace quic

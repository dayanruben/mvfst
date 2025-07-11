/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Unit.h>
#include <folly/portability/GMock.h>
#include <quic/QuicException.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/common/Expected.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/handshake/Aead.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic::test {

// Forward declaration
std::array<uint8_t, kStatelessResetTokenSecretLength> getRandSecret();
std::unique_ptr<folly::IOBuf> getProtectionKey();

class MockPacketNumberCipher : public PacketNumberCipher {
 public:
  virtual ~MockPacketNumberCipher() = default;

  MOCK_METHOD((quic::Expected<void, QuicError>), setKey, (ByteRange key));
  MOCK_METHOD(
      (quic::Expected<HeaderProtectionMask, QuicError>),
      mask,
      (ByteRange),
      (const));
  MOCK_METHOD(size_t, keyLength, (), (const));
  MOCK_METHOD(const BufPtr&, getKey, (), (const));

  void setDefaultKey() {
    packetProtectionKey_ = getProtectionKey();
    ON_CALL(*this, getKey())
        .WillByDefault(testing::ReturnRef(packetProtectionKey_));
  }

 private:
  BufPtr packetProtectionKey_;
};

class MockAead : public Aead {
 public:
  MOCK_METHOD(size_t, getCipherOverhead, (), (const));

  MOCK_METHOD(Optional<TrafficKey>, getKey, (), (const));
  MOCK_METHOD(
      (quic::Expected<std::unique_ptr<folly::IOBuf>, QuicError>),
      _inplaceEncrypt,
      (std::unique_ptr<folly::IOBuf> & plaintext,
       const folly::IOBuf* associatedData,
       uint64_t seqNum),
      (const));

  quic::Expected<std::unique_ptr<folly::IOBuf>, QuicError> inplaceEncrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return _inplaceEncrypt(plaintext, associatedData, seqNum);
  }

  MOCK_METHOD(
      std::unique_ptr<folly::IOBuf>,
      _decrypt,
      (std::unique_ptr<folly::IOBuf> & ciphertext,
       const folly::IOBuf* associatedData,
       uint64_t seqNum),
      (const));

  std::unique_ptr<folly::IOBuf> decrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return _decrypt(ciphertext, associatedData, seqNum);
  }

  MOCK_METHOD(
      Optional<std::unique_ptr<folly::IOBuf>>,
      _tryDecrypt,
      (std::unique_ptr<folly::IOBuf> & ciphertext,
       const folly::IOBuf* associatedData,
       uint64_t seqNum),
      (const));

  Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return _tryDecrypt(ciphertext, associatedData, seqNum);
  }

  void setDefaults() {
    using namespace testing;
    ON_CALL(*this, _inplaceEncrypt(_, _, _))
        .WillByDefault(InvokeWithoutArgs(
            []() -> quic::Expected<std::unique_ptr<folly::IOBuf>, QuicError> {
              return folly::IOBuf::copyBuffer("ciphertext");
            }));
    ON_CALL(*this, _decrypt(_, _, _)).WillByDefault(InvokeWithoutArgs([]() {
      return folly::IOBuf::copyBuffer("plaintext");
    }));
    ON_CALL(*this, _tryDecrypt(_, _, _)).WillByDefault(InvokeWithoutArgs([]() {
      return folly::IOBuf::copyBuffer("plaintext");
    }));
  }
};

} // namespace quic::test

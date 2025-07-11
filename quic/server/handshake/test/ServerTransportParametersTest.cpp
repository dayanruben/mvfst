/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/QuicConstants.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/handshake/ServerTransportParametersExtension.h>

#include <fizz/protocol/test/TestUtil.h>

using namespace fizz;
using namespace fizz::test;

namespace quic::test {

static ClientHello getClientHello(QuicVersion version) {
  auto chlo = TestMessages::clientHello();

  ClientTransportParameters clientParams;
  auto paramResult =
      encodeIntegerParameter(static_cast<TransportParameterId>(0xffff), 0xffff);
  CHECK(!paramResult.hasError()) << "Failed to encode integer parameter";
  clientParams.parameters.emplace_back(std::move(paramResult.value()));

  chlo.extensions.push_back(encodeExtension(clientParams, version));

  return chlo;
}

TEST(ServerTransportParametersTest, TestGetExtensions) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createZeroLength(),
      conn);
  auto extensions = ext.getExtensions(getClientHello(QuicVersion::MVFST));

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getServerExtension(extensions, QuicVersion::MVFST);
  EXPECT_TRUE(serverParams.has_value());
}

TEST(ServerTransportParametersTest, TestGetExtensionsMissingClientParams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createZeroLength(),
      conn);
  EXPECT_THROW(ext.getExtensions(TestMessages::clientHello()), FizzException);
}

TEST(ServerTransportParametersTest, TestQuicV1RejectDraftExtensionNumber) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::QUIC_V1,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createZeroLength(),
      conn);
  EXPECT_THROW(
      ext.getExtensions(getClientHello(QuicVersion::MVFST)), FizzException);
  EXPECT_NO_THROW(ext.getExtensions(getClientHello(QuicVersion::QUIC_V1)));
}

TEST(ServerTransportParametersTest, TestQuicV1RejectDuplicateExtensions) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::QUIC_V1,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xfb, 0xfa, 0xf9, 0xf8}),
      conn);

  auto chlo = getClientHello(QuicVersion::QUIC_V1);
  ClientTransportParameters duplicateClientParams;
  auto paramResult =
      encodeIntegerParameter(static_cast<TransportParameterId>(0xffff), 0xffff);
  CHECK(!paramResult.hasError()) << "Failed to encode integer parameter";
  duplicateClientParams.parameters.emplace_back(std::move(paramResult.value()));
  chlo.extensions.push_back(
      encodeExtension(duplicateClientParams, QuicVersion::QUIC_V1));

  EXPECT_THROW(ext.getExtensions(chlo), FizzException);
}

TEST(ServerTransportParametersTest, TestQuicV1Fields) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::QUIC_V1,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xfb, 0xfa, 0xf9, 0xf8}),
      conn);
  auto extensions = ext.getExtensions(getClientHello(QuicVersion::QUIC_V1));

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getServerExtension(extensions, QuicVersion::QUIC_V1);
  EXPECT_TRUE(serverParams.has_value());
  auto quicTransportParams = serverParams.value().parameters;
  auto hasInitialSourceCid = std::any_of(
      quicTransportParams.cbegin(),
      quicTransportParams.cend(),
      [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::initial_source_connection_id;
      });
  EXPECT_TRUE(hasInitialSourceCid);
  auto hasOriginalDestCid = std::any_of(
      quicTransportParams.cbegin(),
      quicTransportParams.cend(),
      [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::original_destination_connection_id;
      });
  EXPECT_TRUE(hasOriginalDestCid);
}

TEST(ServerTransportParametersTest, TestMvfstFields) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      /*disableMigration=*/true,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      generateStatelessResetToken(),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId::createAndMaybeCrash(
          std::vector<uint8_t>{0xfb, 0xfa, 0xf9, 0xf8}),
      conn);
  auto extensions = ext.getExtensions(getClientHello(QuicVersion::MVFST));

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getServerExtension(extensions, QuicVersion::MVFST);
  EXPECT_TRUE(serverParams.has_value());
  auto quicTransportParams = serverParams.value().parameters;
  auto hasInitialSourceCid = std::any_of(
      quicTransportParams.cbegin(),
      quicTransportParams.cend(),
      [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::initial_source_connection_id;
      });
  EXPECT_FALSE(hasInitialSourceCid);
  auto hasOriginalDestCid = std::any_of(
      quicTransportParams.cbegin(),
      quicTransportParams.cend(),
      [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::original_destination_connection_id;
      });
  EXPECT_FALSE(hasOriginalDestCid);
}

} // namespace quic::test

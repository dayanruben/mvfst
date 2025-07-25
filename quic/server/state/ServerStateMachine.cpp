/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/server/handshake/AppToken.h>
#include <quic/server/handshake/TokenGenerator.h>
#include <quic/server/state/ServerStateMachine.h>

#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/BufUtil.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/state/DatagramHandlers.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicTransportStatsCallback.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamSendHandlers.h>

namespace quic {
using namespace std::chrono_literals;

namespace {
constexpr size_t kConnIdEncodingRetryLimit = 32;

bool maybeNATRebinding(
    const folly::SocketAddress& newPeerAddress,
    const folly::SocketAddress& oldPeerAddress) {
  auto& newIPAddr = newPeerAddress.getIPAddress();
  auto& oldIPAddr = oldPeerAddress.getIPAddress();

  // Port changed
  if (newIPAddr == oldIPAddr) {
    return true;
  }

  return newIPAddr.isV4() && oldIPAddr.isV4() &&
      newIPAddr.inSubnet(oldIPAddr, 24);
}

CongestionAndRttState moveCurrentCongestionAndRttState(
    QuicServerConnectionState& conn) {
  CongestionAndRttState state;
  state.peerAddress = conn.peerAddress;
  state.recordTime = Clock::now();
  state.congestionController = std::move(conn.congestionController);
  state.srtt = conn.lossState.srtt;
  state.lrtt = conn.lossState.lrtt;
  state.rttvar = conn.lossState.rttvar;
  state.mrtt = conn.lossState.mrtt;
  return state;
}

void resetCongestionAndRttState(QuicServerConnectionState& conn) {
  CHECK(conn.congestionControllerFactory)
      << "CongestionControllerFactory is not set.";
  conn.congestionController =
      conn.congestionControllerFactory->makeCongestionController(
          conn, conn.transportSettings.defaultCongestionController);
  conn.lossState.srtt = 0us;
  conn.lossState.lrtt = 0us;
  conn.lossState.rttvar = 0us;
  conn.lossState.mrtt = kDefaultMinRtt;
}

void recoverOrResetCongestionAndRttState(
    QuicServerConnectionState& conn,
    const folly::SocketAddress& peerAddress) {
  auto& lastState = conn.migrationState.lastCongestionAndRtt;
  if (lastState && lastState->peerAddress == peerAddress &&
      (Clock::now() - lastState->recordTime <=
       kTimeToRetainLastCongestionAndRttState)) {
    // recover from matched non-stale state
    conn.congestionController = std::move(lastState->congestionController);
    conn.lossState.srtt = lastState->srtt;
    conn.lossState.lrtt = lastState->lrtt;
    conn.lossState.rttvar = lastState->rttvar;
    conn.lossState.mrtt = lastState->mrtt;
    conn.migrationState.lastCongestionAndRtt.reset();
  } else {
    resetCongestionAndRttState(conn);
  }
}

void maybeSetExperimentalSettings(QuicServerConnectionState& conn) {
  // no-op versions
  if (conn.version == QuicVersion::MVFST_EXPERIMENTAL) {
  } else if (conn.version == QuicVersion::MVFST_EXPERIMENTAL2) {
  } else if (conn.version == QuicVersion::MVFST_EXPERIMENTAL3) {
  } else if (conn.version == QuicVersion::MVFST_EXPERIMENTAL4) {
  } else if (conn.version == QuicVersion::MVFST_EXPERIMENTAL5) {
    conn.transportSettings.sendAckOnlyInitial = true;
  }
}

/**
 * Only certain frames are allowed/disallowed in unprotected (initial,
 * handshake) and zero-rtt packets.
 */
bool isUnprotectedPacketFrameInvalid(const QuicFrame& quicFrame) {
  switch (quicFrame.type()) {
    case QuicFrame::Type::PaddingFrame:
    case QuicFrame::Type::ReadAckFrame:
    case QuicFrame::Type::ConnectionCloseFrame:
    case QuicFrame::Type::ReadCryptoFrame:
    case QuicFrame::Type::PingFrame:
      return false;
    case QuicFrame::Type::RstStreamFrame:
    case QuicFrame::Type::MaxDataFrame:
    case QuicFrame::Type::MaxStreamDataFrame:
    case QuicFrame::Type::DataBlockedFrame:
    case QuicFrame::Type::StreamDataBlockedFrame:
    case QuicFrame::Type::StreamsBlockedFrame:
    case QuicFrame::Type::ReadStreamFrame:
    case QuicFrame::Type::ReadNewTokenFrame:
    case QuicFrame::Type::DatagramFrame:
    case QuicFrame::Type::NoopFrame:
    case QuicFrame::Type::ImmediateAckFrame:
    case QuicFrame::Type::QuicSimpleFrame:
      return true;
  }
  folly::assume_unreachable();
}

bool isZeroRttPacketSimpleFrameInvalid(const QuicSimpleFrame& quicSimpleFrame) {
  switch (quicSimpleFrame.type()) {
    case QuicSimpleFrame::Type::HandshakeDoneFrame:
    case QuicSimpleFrame::Type::RetireConnectionIdFrame:
    case QuicSimpleFrame::Type::PathResponseFrame:
    case QuicSimpleFrame::Type::AckFrequencyFrame:
      return true;
    case QuicSimpleFrame::Type::StopSendingFrame:
    case QuicSimpleFrame::Type::PathChallengeFrame:
    case QuicSimpleFrame::Type::NewConnectionIdFrame:
    case QuicSimpleFrame::Type::MaxStreamsFrame:
    case QuicSimpleFrame::Type::KnobFrame:
    case QuicSimpleFrame::Type::NewTokenFrame:
      return false;
  }
  folly::assume_unreachable();
}

bool isZeroRttPacketFrameInvalid(const QuicFrame& quicFrame) {
  switch (quicFrame.type()) {
    case QuicFrame::Type::ReadAckFrame:
    case QuicFrame::Type::ReadCryptoFrame:
    case QuicFrame::Type::ReadNewTokenFrame:
    case QuicFrame::Type::ImmediateAckFrame:
      return true;
    case QuicFrame::Type::PingFrame:
    case QuicFrame::Type::ConnectionCloseFrame:
    case QuicFrame::Type::PaddingFrame:
    case QuicFrame::Type::RstStreamFrame:
    case QuicFrame::Type::MaxDataFrame:
    case QuicFrame::Type::MaxStreamDataFrame:
    case QuicFrame::Type::DataBlockedFrame:
    case QuicFrame::Type::StreamDataBlockedFrame:
    case QuicFrame::Type::StreamsBlockedFrame:
    case QuicFrame::Type::ReadStreamFrame:
    case QuicFrame::Type::DatagramFrame:
    case QuicFrame::Type::NoopFrame:
      return false;
    case QuicFrame::Type::QuicSimpleFrame:
      return isZeroRttPacketSimpleFrameInvalid(*quicFrame.asQuicSimpleFrame());
  }
  folly::assume_unreachable();
}
} // namespace

quic::Expected<void, QuicError> processClientInitialParams(
    QuicServerConnectionState& conn,
    const ClientTransportParameters& clientParams) {
  auto preferredAddressResult = getIntegerParameter(
      TransportParameterId::preferred_address, clientParams.parameters);
  if (preferredAddressResult.hasError()) {
    return quic::make_unexpected(preferredAddressResult.error());
  }
  auto preferredAddress = preferredAddressResult.value();

  auto origConnIdResult = getIntegerParameter(
      TransportParameterId::original_destination_connection_id,
      clientParams.parameters);
  if (origConnIdResult.hasError()) {
    return quic::make_unexpected(origConnIdResult.error());
  }
  auto origConnId = origConnIdResult.value();

  auto statelessResetTokenResult = getIntegerParameter(
      TransportParameterId::stateless_reset_token, clientParams.parameters);
  if (statelessResetTokenResult.hasError()) {
    return quic::make_unexpected(statelessResetTokenResult.error());
  }
  auto statelessResetToken = statelessResetTokenResult.value();

  auto retrySourceConnIdResult = getIntegerParameter(
      TransportParameterId::retry_source_connection_id,
      clientParams.parameters);
  if (retrySourceConnIdResult.hasError()) {
    return quic::make_unexpected(retrySourceConnIdResult.error());
  }
  auto retrySourceConnId = retrySourceConnIdResult.value();

  auto maxDataResult = getIntegerParameter(
      TransportParameterId::initial_max_data, clientParams.parameters);
  if (maxDataResult.hasError()) {
    return quic::make_unexpected(maxDataResult.error());
  }
  auto maxData = maxDataResult.value();

  auto maxStreamDataBidiLocalResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      clientParams.parameters);
  if (maxStreamDataBidiLocalResult.hasError()) {
    return quic::make_unexpected(maxStreamDataBidiLocalResult.error());
  }
  auto maxStreamDataBidiLocal = maxStreamDataBidiLocalResult.value();

  auto maxStreamDataBidiRemoteResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote,
      clientParams.parameters);
  if (maxStreamDataBidiRemoteResult.hasError()) {
    return quic::make_unexpected(maxStreamDataBidiRemoteResult.error());
  }
  auto maxStreamDataBidiRemote = maxStreamDataBidiRemoteResult.value();

  auto maxStreamDataUniResult = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni,
      clientParams.parameters);
  if (maxStreamDataUniResult.hasError()) {
    return quic::make_unexpected(maxStreamDataUniResult.error());
  }
  auto maxStreamDataUni = maxStreamDataUniResult.value();

  auto maxStreamsBidiResult = getIntegerParameter(
      TransportParameterId::initial_max_streams_bidi, clientParams.parameters);
  if (maxStreamsBidiResult.hasError()) {
    return quic::make_unexpected(maxStreamsBidiResult.error());
  }
  auto maxStreamsBidi = maxStreamsBidiResult.value();

  auto maxStreamsUniResult = getIntegerParameter(
      TransportParameterId::initial_max_streams_uni, clientParams.parameters);
  if (maxStreamsUniResult.hasError()) {
    return quic::make_unexpected(maxStreamsUniResult.error());
  }
  auto maxStreamsUni = maxStreamsUniResult.value();

  auto idleTimeoutResult = getIntegerParameter(
      TransportParameterId::idle_timeout, clientParams.parameters);
  if (idleTimeoutResult.hasError()) {
    return quic::make_unexpected(idleTimeoutResult.error());
  }
  auto idleTimeout = idleTimeoutResult.value();

  auto ackDelayExponentResult = getIntegerParameter(
      TransportParameterId::ack_delay_exponent, clientParams.parameters);
  if (ackDelayExponentResult.hasError()) {
    return quic::make_unexpected(ackDelayExponentResult.error());
  }
  auto ackDelayExponent = ackDelayExponentResult.value();

  auto packetSizeResult = getIntegerParameter(
      TransportParameterId::max_packet_size, clientParams.parameters);
  if (packetSizeResult.hasError()) {
    return quic::make_unexpected(packetSizeResult.error());
  }
  auto packetSize = packetSizeResult.value();

  auto activeConnectionIdLimitResult = getIntegerParameter(
      TransportParameterId::active_connection_id_limit,
      clientParams.parameters);
  if (activeConnectionIdLimitResult.hasError()) {
    return quic::make_unexpected(activeConnectionIdLimitResult.error());
  }
  auto activeConnectionIdLimit = activeConnectionIdLimitResult.value();

  auto minAckDelayResult = getIntegerParameter(
      TransportParameterId::min_ack_delay, clientParams.parameters);
  if (minAckDelayResult.hasError()) {
    return quic::make_unexpected(minAckDelayResult.error());
  }
  auto minAckDelay = minAckDelayResult.value();

  auto maxAckDelayResult = getIntegerParameter(
      TransportParameterId::max_ack_delay, clientParams.parameters);
  if (maxAckDelayResult.hasError()) {
    return quic::make_unexpected(maxAckDelayResult.error());
  }
  auto maxAckDelay = maxAckDelayResult.value();

  auto maxDatagramFrameSizeResult = getIntegerParameter(
      TransportParameterId::max_datagram_frame_size, clientParams.parameters);
  if (maxDatagramFrameSizeResult.hasError()) {
    return quic::make_unexpected(maxDatagramFrameSizeResult.error());
  }
  auto maxDatagramFrameSize = maxDatagramFrameSizeResult.value();

  auto peerAdvertisedMaxStreamGroupsResult = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::stream_groups_enabled),
      clientParams.parameters);
  if (peerAdvertisedMaxStreamGroupsResult.hasError()) {
    return quic::make_unexpected(peerAdvertisedMaxStreamGroupsResult.error());
  }
  auto peerAdvertisedMaxStreamGroups =
      peerAdvertisedMaxStreamGroupsResult.value();

  auto isAckReceiveTimestampsEnabledResult = getIntegerParameter(
      TransportParameterId::ack_receive_timestamps_enabled,
      clientParams.parameters);
  if (isAckReceiveTimestampsEnabledResult.hasError()) {
    return quic::make_unexpected(isAckReceiveTimestampsEnabledResult.error());
  }
  auto isAckReceiveTimestampsEnabled =
      isAckReceiveTimestampsEnabledResult.value();

  auto maxReceiveTimestampsPerAckResult = getIntegerParameter(
      TransportParameterId::max_receive_timestamps_per_ack,
      clientParams.parameters);
  if (maxReceiveTimestampsPerAckResult.hasError()) {
    return quic::make_unexpected(maxReceiveTimestampsPerAckResult.error());
  }
  auto maxReceiveTimestampsPerAck = maxReceiveTimestampsPerAckResult.value();

  auto receiveTimestampsExponentResult = getIntegerParameter(
      TransportParameterId::receive_timestamps_exponent,
      clientParams.parameters);
  if (receiveTimestampsExponentResult.hasError()) {
    return quic::make_unexpected(receiveTimestampsExponentResult.error());
  }
  auto receiveTimestampsExponent = receiveTimestampsExponentResult.value();

  if (conn.version == QuicVersion::QUIC_V1 ||
      conn.version == QuicVersion::QUIC_V1_ALIAS ||
      conn.version == QuicVersion::QUIC_V1_ALIAS2 ||
      conn.version == QuicVersion::MVFST_PRIMING) {
    auto initialSourceConnIdResult = getConnIdParameter(
        TransportParameterId::initial_source_connection_id,
        clientParams.parameters);
    if (initialSourceConnIdResult.hasError()) {
      return quic::make_unexpected(initialSourceConnIdResult.error());
    }
    auto initialSourceConnId = initialSourceConnIdResult.value();
    if (!initialSourceConnId ||
        initialSourceConnId.value() !=
            conn.readCodec->getClientConnectionId()) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "Initial CID does not match."));
    }
  }
  auto knobFrameSupportedResult = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::knob_frames_supported),
      clientParams.parameters);
  if (knobFrameSupportedResult.hasError()) {
    return quic::make_unexpected(knobFrameSupportedResult.error());
  }
  auto knobFrameSupported = knobFrameSupportedResult.value();

  auto extendedAckFeaturesResult = getIntegerParameter(
      static_cast<TransportParameterId>(
          TransportParameterId::extended_ack_features),
      clientParams.parameters);
  if (extendedAckFeaturesResult.hasError()) {
    return quic::make_unexpected(extendedAckFeaturesResult.error());
  }
  auto extendedAckFeatures = extendedAckFeaturesResult.value();

  auto reliableResetTpIter = findParameter(
      clientParams.parameters,
      static_cast<TransportParameterId>(
          TransportParameterId::reliable_stream_reset));
  if (reliableResetTpIter != clientParams.parameters.end()) {
    if (!reliableResetTpIter->value->empty()) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "Reliable reset transport parameter must be empty"));
    }
    conn.peerAdvertisedReliableStreamResetSupport = true;
  } else {
    conn.peerAdvertisedReliableStreamResetSupport = false;
  }

  // validate that we didn't receive original connection ID, stateless
  // reset token, or preferred address.
  if (preferredAddress && *preferredAddress != 0) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "Preferred Address is received by server"));
  }

  if (origConnId && *origConnId != 0) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "OriginalDestinationConnectionId is received by server"));
  }

  if (statelessResetToken && statelessResetToken.value() != 0) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "Stateless Reset Token is received by server"));
  }

  if (retrySourceConnId && retrySourceConnId.value() != 0) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "Retry Source Connection ID is received by server"));
  }
  if (maxAckDelay && *maxAckDelay >= kMaxAckDelay) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "Max Ack Delay is greater than 2^14 "));
  }

  // TODO Validate active_connection_id_limit
  if (packetSize && *packetSize < kMinMaxUDPPayload) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        fmt::format(
            "Max packet size too small. received max_packetSize = {}",
            *packetSize)));
  }

  VLOG(10) << "Client advertised flow control ";
  VLOG(10) << "conn=" << maxData.value_or(0);
  VLOG(10) << " stream bidi local=" << maxStreamDataBidiLocal.value_or(0)
           << " ";
  VLOG(10) << " stream bidi remote=" << maxStreamDataBidiRemote.value_or(0)
           << " ";
  VLOG(10) << " stream uni=" << maxStreamDataUni.value_or(0) << " ";
  VLOG(10) << conn;
  conn.flowControlState.peerAdvertisedMaxOffset = maxData.value_or(0);
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
      maxStreamDataBidiLocal.value_or(0);
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
      maxStreamDataBidiRemote.value_or(0);
  conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
      maxStreamDataUni.value_or(0);

  auto maxBidiStreamsResult =
      conn.streamManager->setMaxLocalBidirectionalStreams(
          maxStreamsBidi.value_or(0));
  if (!maxBidiStreamsResult) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "Failed to set max local bidirectional streams"));
  }

  auto maxUniStreamsResult =
      conn.streamManager->setMaxLocalUnidirectionalStreams(
          maxStreamsUni.value_or(0));
  if (!maxUniStreamsResult) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "Failed to set max local unidirectional streams"));
  }

  conn.peerIdleTimeout = std::chrono::milliseconds(idleTimeout.value_or(0));
  conn.peerIdleTimeout = timeMin(conn.peerIdleTimeout, kMaxIdleTimeout);
  if (ackDelayExponent && *ackDelayExponent > kMaxAckDelayExponent) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        "ack_delay_exponent too large"));
  }
  conn.peerAckDelayExponent =
      ackDelayExponent.value_or(kDefaultAckDelayExponent);
  if (minAckDelay.has_value()) {
    conn.peerMinAckDelay = std::chrono::microseconds(minAckDelay.value());
  }
  if (maxDatagramFrameSize.has_value()) {
    if (maxDatagramFrameSize.value() > 0 &&
        maxDatagramFrameSize.value() <= kMaxDatagramPacketOverhead) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "max_datagram_frame_size too small"));
    }
    conn.datagramState.maxWriteFrameSize = maxDatagramFrameSize.value();
  }

  // Default to max because we can probe PMTU now, and this will be the upper
  // limit
  uint64_t maxUdpPayloadSize = kDefaultMaxUDPPayload;
  if (packetSize) {
    maxUdpPayloadSize = std::min(*packetSize, maxUdpPayloadSize);
    conn.peerMaxUdpPayloadSize = maxUdpPayloadSize;
    if (conn.transportSettings.canIgnorePathMTU) {
      *packetSize = std::min<uint64_t>(*packetSize, kDefaultMaxUDPPayload);
      conn.udpSendPacketLen = *packetSize;
    }
  }

  conn.peerActiveConnectionIdLimit =
      activeConnectionIdLimit.value_or(kDefaultActiveConnectionIdLimit);

  if (peerAdvertisedMaxStreamGroups) {
    conn.peerAdvertisedMaxStreamGroups = *peerAdvertisedMaxStreamGroups;
  }
  if (isAckReceiveTimestampsEnabled.has_value() &&
      isAckReceiveTimestampsEnabled.value() == 1) {
    if (maxReceiveTimestampsPerAck.has_value() &&
        receiveTimestampsExponent.has_value()) {
      conn.maybePeerAckReceiveTimestampsConfig = {
          std::min(
              static_cast<uint8_t>(maxReceiveTimestampsPerAck.value()),
              static_cast<uint8_t>(
                  conn.transportSettings.maxReceiveTimestampsPerAckStored)),
          std::max(
              static_cast<uint8_t>(receiveTimestampsExponent.value()),
              static_cast<uint8_t>(0))};
    }
  }

  conn.peerAdvertisedKnobFrameSupport = knobFrameSupported.value_or(0) > 0;
  conn.peerAdvertisedExtendedAckFeatures = extendedAckFeatures.value_or(0);

  return {};
}

quic::Expected<void, QuicError> updateHandshakeState(
    QuicServerConnectionState& conn) {
  // Zero RTT read cipher is available after chlo is processed with the
  // condition that early data attempt is accepted.
  auto handshakeLayer = conn.serverHandshakeLayer;
  auto zeroRttReadCipherResult = handshakeLayer->getZeroRttReadCipher();
  if (zeroRttReadCipherResult.hasError()) {
    return quic::make_unexpected(zeroRttReadCipherResult.error());
  }
  auto zeroRttReadCipher = std::move(zeroRttReadCipherResult.value());

  auto zeroRttHeaderCipherResult = handshakeLayer->getZeroRttReadHeaderCipher();
  if (zeroRttHeaderCipherResult.hasError()) {
    return quic::make_unexpected(zeroRttHeaderCipherResult.error());
  }
  auto zeroRttHeaderCipher = std::move(zeroRttHeaderCipherResult.value());

  // One RTT write cipher is available at Fizz layer after chlo is processed.
  // However, the cipher is only exported to QUIC if early data attempt is
  // accepted. Otherwise, the cipher will be available after cfin is
  // processed.
  auto oneRttWriteCipherResult = handshakeLayer->getFirstOneRttWriteCipher();
  if (oneRttWriteCipherResult.hasError()) {
    return quic::make_unexpected(oneRttWriteCipherResult.error());
  }
  auto oneRttWriteCipher = std::move(oneRttWriteCipherResult.value());

  // One RTT read cipher is available after cfin is processed.
  auto oneRttReadCipherResult = handshakeLayer->getFirstOneRttReadCipher();
  if (oneRttReadCipherResult.hasError()) {
    return quic::make_unexpected(oneRttReadCipherResult.error());
  }
  auto oneRttReadCipher = std::move(oneRttReadCipherResult.value());

  auto oneRttWriteHeaderCipherResult =
      handshakeLayer->getOneRttWriteHeaderCipher();
  if (oneRttWriteHeaderCipherResult.hasError()) {
    return quic::make_unexpected(oneRttWriteHeaderCipherResult.error());
  }
  auto oneRttWriteHeaderCipher =
      std::move(oneRttWriteHeaderCipherResult.value());

  auto oneRttReadHeaderCipherResult =
      handshakeLayer->getOneRttReadHeaderCipher();
  if (oneRttReadHeaderCipherResult.hasError()) {
    return quic::make_unexpected(oneRttReadHeaderCipherResult.error());
  }
  auto oneRttReadHeaderCipher = std::move(oneRttReadHeaderCipherResult.value());

  if (zeroRttReadCipher) {
    conn.usedZeroRtt = true;
    if (conn.qLogger) {
      conn.qLogger->addTransportStateUpdate(kDerivedZeroRttReadCipher);
    }
    conn.readCodec->setZeroRttReadCipher(std::move(zeroRttReadCipher));
  }
  if (zeroRttHeaderCipher) {
    conn.readCodec->setZeroRttHeaderCipher(std::move(zeroRttHeaderCipher));
  }
  if (oneRttWriteHeaderCipher) {
    conn.oneRttWriteHeaderCipher = std::move(oneRttWriteHeaderCipher);
  }
  if (oneRttReadHeaderCipher) {
    conn.readCodec->setOneRttHeaderCipher(std::move(oneRttReadHeaderCipher));
  }

  if (oneRttWriteCipher) {
    if (conn.qLogger) {
      conn.qLogger->addTransportStateUpdate(kDerivedOneRttWriteCipher);
    }
    if (conn.oneRttWriteCipher) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::CRYPTO_ERROR, "Duplicate 1-rtt write cipher"));
    }
    conn.oneRttWriteCipher = std::move(oneRttWriteCipher);
    conn.oneRttWritePhase = ProtectionType::KeyPhaseZero;

    updatePacingOnKeyEstablished(conn);

    // We negotiate the transport parameters whenever we have the 1-RTT write
    // keys available.
    auto clientParams = handshakeLayer->getClientTransportParams();
    if (!clientParams) {
      return quic::make_unexpected(QuicError(
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
          "No client transport params"));
    }
    auto result = processClientInitialParams(conn, *clientParams);
    if (result.hasError()) {
      return result;
    }
    updateNegotiatedAckFeatures(conn);
  }
  if (oneRttReadCipher) {
    if (conn.qLogger) {
      conn.qLogger->addTransportStateUpdate(kDerivedOneRttReadCipher);
    }
    // Clear limit because CFIN is received at this point
    conn.isClientAddrVerified = true;
    conn.writableBytesLimit.reset();
    conn.readCodec->setOneRttReadCipher(std::move(oneRttReadCipher));
    auto nextOneRttReadCipherResult = handshakeLayer->getNextOneRttReadCipher();
    if (nextOneRttReadCipherResult.hasError()) {
      return quic::make_unexpected(nextOneRttReadCipherResult.error());
    }
    conn.readCodec->setNextOneRttReadCipher(
        std::move(nextOneRttReadCipherResult.value()));
  }
  auto handshakeReadCipherResult = handshakeLayer->getHandshakeReadCipher();
  if (handshakeReadCipherResult.hasError()) {
    return quic::make_unexpected(handshakeReadCipherResult.error());
  }
  auto handshakeReadCipher = std::move(handshakeReadCipherResult.value());

  auto handshakeReadHeaderCipherResult =
      handshakeLayer->getHandshakeReadHeaderCipher();
  if (handshakeReadHeaderCipherResult.hasError()) {
    return quic::make_unexpected(handshakeReadHeaderCipherResult.error());
  }
  auto handshakeReadHeaderCipher =
      std::move(handshakeReadHeaderCipherResult.value());

  if (handshakeReadCipher) {
    CHECK(handshakeReadHeaderCipher);
    conn.readCodec->setHandshakeReadCipher(std::move(handshakeReadCipher));
    conn.readCodec->setHandshakeHeaderCipher(
        std::move(handshakeReadHeaderCipher));
  }
  if (handshakeLayer->isHandshakeDone()) {
    CHECK(conn.oneRttWriteCipher);
    if (!conn.sentHandshakeDone) {
      sendSimpleFrame(conn, HandshakeDoneFrame());
      conn.sentHandshakeDone = true;
      maybeUpdateTransportFromAppToken(
          conn, conn.serverHandshakeLayer->getAppToken());
    }

    if (!conn.sentNewTokenFrame &&
        conn.transportSettings.retryTokenSecret.has_value()) {
      // Create NewToken struct – defaults timestamp to now
      NewToken token(conn.peerAddress.getIPAddress());

      // Encrypt two tuple -> (clientIp, curTimeInMs)
      TokenGenerator generator(conn.transportSettings.retryTokenSecret.value());
      auto encryptedToken = generator.encryptToken(token);
      CHECK(encryptedToken.has_value());

      sendSimpleFrame(conn, NewTokenFrame(std::move(encryptedToken.value())));
      QUIC_STATS(conn.statsCallback, onNewTokenIssued);

      conn.sentNewTokenFrame = true;
    }
  }
  return {};
}

bool validateAndUpdateSourceToken(
    QuicServerConnectionState& conn,
    std::vector<folly::IPAddress> sourceAddresses) {
  DCHECK(conn.peerAddress.isInitialized());
  bool foundMatch = false;
  for (int ii = sourceAddresses.size() - 1; ii >= 0; --ii) {
    // TODO T33014230 subnet matching
    if (conn.peerAddress.getIPAddress() == sourceAddresses[ii]) {
      foundMatch = true;
      // If peer address is found in the token, move the element to the end
      // of vector to increase its favorability.
      sourceAddresses.erase(sourceAddresses.begin() + ii);
      sourceAddresses.push_back(conn.peerAddress.getIPAddress());
      conn.isClientAddrVerified = true;
    }
  }
  conn.sourceTokenMatching = foundMatch;
  bool acceptZeroRtt =
      (conn.transportSettings.zeroRttSourceTokenMatchingPolicy !=
       ZeroRttSourceTokenMatchingPolicy::ALWAYS_REJECT) &&
      foundMatch;

  if (!foundMatch) {
    // Add peer address to token for next resumption
    if (sourceAddresses.size() >= kMaxNumTokenSourceAddresses) {
      sourceAddresses.erase(sourceAddresses.begin());
    }
    sourceAddresses.push_back(conn.peerAddress.getIPAddress());

    switch (conn.transportSettings.zeroRttSourceTokenMatchingPolicy) {
      case ZeroRttSourceTokenMatchingPolicy::ALWAYS_REJECT:
      case ZeroRttSourceTokenMatchingPolicy::REJECT_IF_NO_EXACT_MATCH:
        acceptZeroRtt = false;
        break;
      case ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH:
        acceptZeroRtt = true;
        conn.writableBytesLimit =
            conn.transportSettings.limitedCwndInMss * conn.udpSendPacketLen;
        break;
    }
  }
  // Save the source token so that it can be written to client via NST later
  conn.tokenSourceAddresses = std::move(sourceAddresses);

  return acceptZeroRtt;
}

void updateWritableByteLimitOnRecvPacket(QuicServerConnectionState& conn) {
  // When we receive a packet we increase the limit again. The reasoning this is
  // that a peer can do the same by opening a new connection.
  if (conn.writableBytesLimit) {
    conn.writableBytesLimit = *conn.writableBytesLimit +
        conn.transportSettings.limitedCwndInMss * conn.udpSendPacketLen;
  } else if (
      !conn.isClientAddrVerified &&
      conn.transportSettings.enableWritableBytesLimit) {
    conn.writableBytesLimit =
        conn.transportSettings.limitedCwndInMss * conn.udpSendPacketLen;
  }
}

void maybeUpdateTransportFromAppToken(
    QuicServerConnectionState& conn,
    const Optional<BufPtr>& tokenBuf) {
  if (!tokenBuf) {
    return;
  }
  auto appToken = decodeAppToken(*tokenBuf.value());
  if (!appToken) {
    VLOG(10) << "Failed to decode app token";
    return;
  }
  auto& params = appToken->transportParams.parameters;
  auto maybeCwndHintBytesResult =
      getIntegerParameter(TransportParameterId::cwnd_hint_bytes, params);
  if (maybeCwndHintBytesResult.hasError()) {
    return;
  }
  auto maybeCwndHintBytes = maybeCwndHintBytesResult.value();
  if (maybeCwndHintBytes) {
    QUIC_STATS(conn.statsCallback, onCwndHintBytesSample, *maybeCwndHintBytes);

    // Only use the cwndHint if the source address is included in the token
    DCHECK(conn.peerAddress.isInitialized());
    auto addressMatches =
        std::find(
            appToken->sourceAddresses.begin(),
            appToken->sourceAddresses.end(),
            conn.peerAddress.getIPAddress()) != appToken->sourceAddresses.end();
    if (addressMatches) {
      conn.maybeCwndHintBytes = maybeCwndHintBytes;
    }
  }
}

quic::Expected<void, QuicError> onConnectionMigration(
    QuicServerConnectionState& conn,
    const folly::SocketAddress& newPeerAddress,
    bool isIntentional) {
  if (conn.migrationState.numMigrations >=
      conn.transportSettings.maxNumMigrationsAllowed) {
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(
          0,
          PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)._to_string());
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::PEER_ADDRESS_CHANGE);
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INVALID_MIGRATION, "Too many migrations"));
  }

  bool hasPendingPathChallenge = conn.pendingEvents.pathChallenge.has_value();
  // Clear any pending path challenge frame that is not sent
  conn.pendingEvents.pathChallenge.reset();

  auto& previousPeerAddresses = conn.migrationState.previousPeerAddresses;
  auto it = std::find(
      previousPeerAddresses.begin(),
      previousPeerAddresses.end(),
      newPeerAddress);
  if (it == previousPeerAddresses.end()) {
    ++conn.migrationState.numMigrations;
    // send new path challenge
    conn.pendingEvents.pathChallenge.emplace(folly::Random::secureRand64());

    // If we are already in the middle of a migration reset
    // the available bytes in the rate-limited window, but keep the
    // window.
    conn.pathValidationLimiter =
        std::make_unique<PendingPathRateLimiter>(conn.udpSendPacketLen);
  } else {
    previousPeerAddresses.erase(it);
  }

  // At this point, path validation scheduled, writable bytes limit set
  // However if this is NAT rebinding, keep congestion state unchanged
  bool isNATRebinding = maybeNATRebinding(newPeerAddress, conn.peerAddress);

  // Cancel current path validation if any
  if (hasPendingPathChallenge || conn.outstandingPathValidation) {
    conn.pendingEvents.schedulePathValidationTimeout = false;
    conn.outstandingPathValidation.reset();

    // Only change congestion & rtt state if not NAT rebinding
    if (!isNATRebinding) {
      recoverOrResetCongestionAndRttState(conn, newPeerAddress);
    }
  } else {
    // Only add validated addresses to previousPeerAddresses
    conn.migrationState.previousPeerAddresses.push_back(conn.peerAddress);

    // Only change congestion & rtt state if not NAT rebinding
    if (!isNATRebinding) {
      // Current peer address is validated,
      // remember its congestion state and rtt stats
      CongestionAndRttState state = moveCurrentCongestionAndRttState(conn);
      recoverOrResetCongestionAndRttState(conn, newPeerAddress);
      conn.migrationState.lastCongestionAndRtt = std::move(state);
    }
  }

  if (conn.qLogger) {
    conn.qLogger->addConnectionMigrationUpdate(isIntentional);
  }
  conn.peerAddress = newPeerAddress;
  return {};
}

quic::Expected<void, QuicError> onServerReadData(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData) {
  switch (conn.state) {
    case ServerState::Open:
      return onServerReadDataFromOpen(conn, readData);
    case ServerState::Closed:
      return onServerReadDataFromClosed(conn, readData);
  }
  folly::assume_unreachable();
}

static void handleCipherUnavailable(
    CipherUnavailable* originalData,
    QuicServerConnectionState& conn,
    size_t packetSize,
    ServerEvents::ReadData& readData) {
  if (!originalData->packet || originalData->packet->empty()) {
    VLOG(10) << "drop because no data " << conn;
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(packetSize, kNoData);
    }
    QUIC_STATS(
        conn.statsCallback, onPacketDropped, PacketDropReason::EMPTY_DATA);
    return;
  }
  if (originalData->protectionType != ProtectionType::ZeroRtt &&
      originalData->protectionType != ProtectionType::KeyPhaseZero) {
    VLOG(10) << "drop because unexpected protection level " << conn;
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(packetSize, kUnexpectedProtectionLevel);
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::UNEXPECTED_PROTECTION_LEVEL);
    return;
  }

  size_t combinedSize =
      (conn.pendingZeroRttData ? conn.pendingZeroRttData->size() : 0) +
      (conn.pendingOneRttData ? conn.pendingOneRttData->size() : 0);
  if (combinedSize >= conn.transportSettings.maxPacketsToBuffer) {
    VLOG(10) << "drop because max buffered " << conn;
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(packetSize, kMaxBuffered);
    }
    QUIC_STATS(
        conn.statsCallback, onPacketDropped, PacketDropReason::MAX_BUFFERED);
    return;
  }

  auto& pendingData = originalData->protectionType == ProtectionType::ZeroRtt
      ? conn.pendingZeroRttData
      : conn.pendingOneRttData;
  if (pendingData) {
    if (conn.qLogger) {
      conn.qLogger->addPacketBuffered(originalData->protectionType, packetSize);
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::PARSE_ERROR_PACKET_BUFFERED);
    ServerEvents::ReadData pendingReadData;
    pendingReadData.peer = readData.peer;
    pendingReadData.udpPacket = ReceivedUdpPacket(
        std::move(originalData->packet),
        readData.udpPacket.timings,
        readData.udpPacket.tosValue);
    pendingData->emplace_back(std::move(pendingReadData));
    VLOG(10) << "Adding pending data to "
             << toString(originalData->protectionType)
             << " buffer size=" << pendingData->size() << " " << conn;
  } else {
    VLOG(10) << "drop because " << toString(originalData->protectionType)
             << " buffer no longer available " << conn;
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(packetSize, kBufferUnavailable);
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::BUFFER_UNAVAILABLE);
    return;
  }
}

quic::Expected<void, QuicError> onServerReadDataFromOpen(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData) {
  CHECK_EQ(conn.state, ServerState::Open);

  if (readData.udpPacket.buf.empty()) {
    return {};
  }
  bool firstPacketFromPeer = false;
  if (!conn.readCodec) {
    firstPacketFromPeer = true;
    Cursor cursor(readData.udpPacket.buf.front());
    auto initialByte = cursor.readBE<uint8_t>();
    auto parsedLongHeader = parseLongHeaderInvariant(initialByte, cursor);
    if (!parsedLongHeader) {
      VLOG(4) << "Could not parse initial packet header";
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(
            0,
            PacketDropReason(PacketDropReason::PARSE_ERROR_LONG_HEADER_INITIAL)
                ._to_string());
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::PARSE_ERROR_LONG_HEADER_INITIAL);
      return {};
    }
    QuicVersion version = parsedLongHeader->invariant.version;
    if (version == QuicVersion::VERSION_NEGOTIATION) {
      VLOG(4) << "Server dropping VN packet";
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(
            0,
            PacketDropReason(PacketDropReason::INVALID_PACKET_VN)._to_string());
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::INVALID_PACKET_VN);
      return {};
    }

    const auto& clientConnectionId = parsedLongHeader->invariant.srcConnId;
    const auto& initialDestinationConnectionId =
        parsedLongHeader->invariant.dstConnId;

    if (initialDestinationConnectionId.size() < kDefaultConnectionIdSize) {
      VLOG(4) << "Initial connectionid too small";
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(
            0,
            PacketDropReason(PacketDropReason::INITIAL_CONNID_SMALL)
                ._to_string());
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::INITIAL_CONNID_SMALL);
      return quic::make_unexpected(QuicError(
          TransportErrorCode::PROTOCOL_VIOLATION,
          "Initial destination connectionid too small"));
    }

    CHECK(conn.connIdAlgo) << "ConnectionIdAlgo is not set.";
    CHECK(!conn.serverConnectionId.has_value());
    CHECK(conn.serverConnIdParams);

    auto newServerConnIdData = conn.createAndAddNewSelfConnId();
    CHECK(newServerConnIdData.has_value());
    conn.serverConnectionId = newServerConnIdData->connId;

    auto customTransportParams = getSupportedExtTransportParams(conn);

    QUIC_STATS(conn.statsCallback, onStatelessReset);
    conn.serverHandshakeLayer->accept(
        std::make_shared<ServerTransportParametersExtension>(
            version,
            conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
            conn.transportSettings
                .advertisedInitialBidiLocalStreamFlowControlWindow,
            conn.transportSettings
                .advertisedInitialBidiRemoteStreamFlowControlWindow,
            conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
            conn.transportSettings.advertisedInitialMaxStreamsBidi,
            conn.transportSettings.advertisedInitialMaxStreamsUni,
            conn.transportSettings.disableMigration,
            conn.transportSettings.idleTimeout,
            conn.transportSettings.ackDelayExponent,
            conn.transportSettings.maxRecvPacketSize,
            *newServerConnIdData->token,
            conn.serverConnectionId.value(),
            initialDestinationConnectionId,
            conn,
            customTransportParams));
    conn.transportParametersEncoded = true;
    const CryptoFactory& cryptoFactory =
        conn.serverHandshakeLayer->getCryptoFactory();
    conn.readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
    conn.readCodec->setConnectionStatsCallback(conn.statsCallback);
    auto clientInitialCipherResult = cryptoFactory.getClientInitialCipher(
        initialDestinationConnectionId, version);
    if (clientInitialCipherResult.hasError()) {
      return quic::make_unexpected(clientInitialCipherResult.error());
    }
    conn.readCodec->setInitialReadCipher(
        std::move(clientInitialCipherResult.value()));
    conn.readCodec->setClientConnectionId(clientConnectionId);
    conn.readCodec->setServerConnectionId(*conn.serverConnectionId);
    if (conn.qLogger) {
      conn.qLogger->setScid(conn.serverConnectionId);
      conn.qLogger->setDcid(initialDestinationConnectionId);
    }
    conn.readCodec->setCodecParameters(CodecParameters(
        conn.peerAckDelayExponent,
        version,
        conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer,
        conn.transportSettings.advertisedExtendedAckFeatures));
    auto serverInitialCipherResult = cryptoFactory.getServerInitialCipher(
        initialDestinationConnectionId, version);
    if (serverInitialCipherResult.hasError()) {
      return quic::make_unexpected(serverInitialCipherResult.error());
    }
    conn.initialWriteCipher = std::move(serverInitialCipherResult.value());

    auto clientInitialHeaderCipherResult =
        cryptoFactory.makeClientInitialHeaderCipher(
            initialDestinationConnectionId, version);
    if (clientInitialHeaderCipherResult.hasError()) {
      return quic::make_unexpected(clientInitialHeaderCipherResult.error());
    }
    conn.readCodec->setInitialHeaderCipher(
        std::move(clientInitialHeaderCipherResult.value()));

    auto serverInitialHeaderCipherResult =
        cryptoFactory.makeServerInitialHeaderCipher(
            initialDestinationConnectionId, version);
    if (serverInitialHeaderCipherResult.hasError()) {
      return quic::make_unexpected(serverInitialHeaderCipherResult.error());
    }
    conn.initialHeaderCipher =
        std::move(serverInitialHeaderCipherResult.value());
    conn.peerAddress = conn.originalPeerAddress;
  }
  BufQueue& udpData = readData.udpPacket.buf;
  uint64_t processedPacketsTotal = 0;
  for (uint16_t processedPackets = 0;
       !udpData.empty() && processedPackets < kMaxNumCoalescedPackets;
       processedPackets++) {
    size_t dataSize = udpData.chainLength();
    auto parsedPacket = conn.readCodec->parsePacket(udpData, conn.ackStates);
    size_t packetSize = dataSize - udpData.chainLength();

    switch (parsedPacket.type()) {
      case CodecResult::Type::CIPHER_UNAVAILABLE: {
        handleCipherUnavailable(
            parsedPacket.cipherUnavailable(), conn, packetSize, readData);
        break;
      }
      case CodecResult::Type::RETRY: {
        VLOG(10) << "drop because the server is not supposed to "
                 << "receive a retry " << conn;
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(packetSize, kRetry);
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::UNEXPECTED_RETRY);
        break;
      }
      case CodecResult::Type::STATELESS_RESET: {
        VLOG(10) << "drop because reset " << conn;
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(packetSize, kReset);
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::UNEXPECTED_RESET);
        return {};
      }
      case CodecResult::Type::NOTHING: {
        VLOG(10) << "drop no data, reason: "
                 << parsedPacket.nothing()->reason._to_string() << " " << conn;
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(
              packetSize, parsedPacket.nothing()->reason._to_string());
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            parsedPacket.nothing()->reason);
        if (firstPacketFromPeer) {
          return quic::make_unexpected(QuicError(
              LocalErrorCode::CONNECTION_ABANDONED,
              "Failed to decrypt first packet from peer"));
        }
        break;
      }
      case CodecResult::Type::CODEC_ERROR: {
        return quic::make_unexpected(parsedPacket.codecError()->error);
      }
      case CodecResult::Type::REGULAR_PACKET:
        break;
    }

    RegularQuicPacket* regularOptional = parsedPacket.regularPacket();
    if (!regularOptional) {
      // We were unable to parse the packet, drop for now. All the drop reasons
      // should have already been logged into QLogger and QuicTrace inside the
      // previous switch-case block. All stats have already been updated.
      VLOG(10) << "Not able to parse QUIC packet " << conn;
      continue;
    }
    if (regularOptional->frames.empty()) {
      // This packet had a pareseable header (most probably short header)
      // but no data. This is a protocol violation so we return an error.
      // This drop has not been recorded in the switch-case block above
      // so we record it here.
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(
            packetSize,
            PacketDropReason(PacketDropReason::PROTOCOL_VIOLATION)
                ._to_string());
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::PROTOCOL_VIOLATION);
      return quic::make_unexpected(QuicError(
          TransportErrorCode::PROTOCOL_VIOLATION, "Packet has no frames"));
    }

    auto protectionLevel = regularOptional->header.getProtectionType();
    auto encryptionLevel = protectionTypeToEncryptionLevel(protectionLevel);

    auto packetNum = regularOptional->header.getPacketSequenceNum();
    auto packetNumberSpace = regularOptional->header.getPacketNumberSpace();

    auto& regularPacket = *regularOptional;

    bool isProtectedPacket = protectionLevel == ProtectionType::ZeroRtt ||
        protectionLevel == ProtectionType::KeyPhaseZero ||
        protectionLevel == ProtectionType::KeyPhaseOne;

    bool isZeroRttPacket = protectionLevel == ProtectionType::ZeroRtt;

    bool isQuicInitialPacket =
        regularPacket.header.getHeaderForm() == HeaderForm::Long &&
        regularPacket.header.asLong()->getHeaderType() ==
            LongHeader::Types::Initial;

    if (isQuicInitialPacket) {
      ++conn.initialPacketsReceived;
    }

    if (!isProtectedPacket || isZeroRttPacket) {
      auto isFrameInvalidFn = !isProtectedPacket
          ? isUnprotectedPacketFrameInvalid
          : isZeroRttPacketFrameInvalid;
      for (auto& quicFrame : regularPacket.frames) {
        bool isFrameInvalid = isFrameInvalidFn(quicFrame);
        if (isFrameInvalid) {
          QUIC_STATS(
              conn.statsCallback,
              onPacketDropped,
              PacketDropReason::PROTOCOL_VIOLATION);
          if (conn.qLogger) {
            conn.qLogger->addPacketDrop(
                packetSize,
                PacketDropReason(PacketDropReason::PROTOCOL_VIOLATION)
                    ._to_string());
          }
          return quic::make_unexpected(QuicError(
              TransportErrorCode::PROTOCOL_VIOLATION,
              "Invalid frame received"));
        }
      }
    }

    CHECK(conn.clientConnectionId);
    if (conn.qLogger) {
      conn.qLogger->addPacket(regularPacket, packetSize);
    }

    if (!conn.version) {
      LongHeader* longHeader = regularPacket.header.asLong();
      if (!longHeader) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "Invalid packet type (expected LongHeader)"));
      }
      conn.version = longHeader->getVersion();
      maybeSetExperimentalSettings(conn);
    }

    if (conn.peerAddress != readData.peer) {
      QUIC_STATS(conn.statsCallback, onPeerAddressChanged);
      auto migrationDenied = (encryptionLevel != EncryptionLevel::AppData) ||
          conn.transportSettings.disableMigration;
      if (migrationDenied) {
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(
              packetSize,
              PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)
                  ._to_string());
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::PEER_ADDRESS_CHANGE);
        if (!conn.transportSettings.closeIfMigrationDuringHandshake) {
          continue;
        }
        const char* errMsg = encryptionLevel != EncryptionLevel::AppData
            ? "Migration not allowed during handshake"
            : "Migration disabled";
        return quic::make_unexpected(
            QuicError(TransportErrorCode::INVALID_MIGRATION, errMsg));
      }
    }

    auto& ackState = getAckState(conn, packetNumberSpace);
    uint64_t distanceFromExpectedPacketNum =
        addPacketToAckState(conn, ackState, packetNum, readData.udpPacket);
    if (distanceFromExpectedPacketNum > 0) {
      QUIC_STATS(conn.statsCallback, onOutOfOrderPacketReceived);
    }
    DCHECK(hasReceivedUdpPackets(conn));

    bool pktHasRetransmittableData = false;
    bool pktHasCryptoData = false;
    bool isNonProbingPacket = false;
    bool handshakeConfirmedThisLoop = false;

    AckedPacketVisitor ackedPacketVisitor =
        [&](const OutstandingPacketWrapper& outstandingPacket) {
          return maybeVerifyPendingKeyUpdate(
              conn, outstandingPacket, regularPacket);
        };
    AckedFrameVisitor ackedFrameVisitor = [&](const OutstandingPacketWrapper&,
                                              const QuicWriteFrame& packetFrame)
        -> quic::Expected<void, QuicError> {
      switch (packetFrame.type()) {
        case QuicWriteFrame::Type::WriteStreamFrame: {
          const WriteStreamFrame& frame = *packetFrame.asWriteStreamFrame();
          VLOG(4) << "Server received ack for stream=" << frame.streamId
                  << " offset=" << frame.offset << " fin=" << frame.fin
                  << " len=" << frame.len << " " << conn;
          auto ackedStream =
              conn.streamManager->getStream(frame.streamId).value_or(nullptr);
          if (ackedStream) {
            auto result = sendAckSMHandler(*ackedStream, frame);
            if (result.hasError()) {
              return quic::make_unexpected(result.error());
            }
          }
          break;
        }
        case QuicWriteFrame::Type::WriteCryptoFrame: {
          const WriteCryptoFrame& frame = *packetFrame.asWriteCryptoFrame();
          auto cryptoStream =
              getCryptoStream(*conn.cryptoState, encryptionLevel);
          processCryptoStreamAck(*cryptoStream, frame.offset, frame.len);
          break;
        }
        case QuicWriteFrame::Type::RstStreamFrame: {
          const RstStreamFrame& frame = *packetFrame.asRstStreamFrame();
          VLOG(4) << "Server received ack for reset stream=" << frame.streamId
                  << " " << conn;
          auto stream =
              conn.streamManager->getStream(frame.streamId).value_or(nullptr);
          if (stream) {
            auto result = sendRstAckSMHandler(*stream, frame.reliableSize);
            if (result.hasError()) {
              return quic::make_unexpected(result.error());
            }
          }
          break;
        }
        case QuicWriteFrame::Type::WriteAckFrame: {
          const WriteAckFrame& frame = *packetFrame.asWriteAckFrame();
          DCHECK(!frame.ackBlocks.empty());
          VLOG(4) << "Server received ack for largestAcked="
                  << frame.ackBlocks.front().end << " " << conn;
          commonAckVisitorForAckFrame(ackState, frame);
          break;
        }
        case QuicWriteFrame::Type::PingFrame:
          conn.pendingEvents.cancelPingTimeout = true;
          break;
        case QuicWriteFrame::Type::QuicSimpleFrame: {
          const QuicSimpleFrame& frame = *packetFrame.asQuicSimpleFrame();
          // ACK of HandshakeDone is a server-specific behavior.
          if (frame.asHandshakeDoneFrame()) {
            // Call handshakeConfirmed outside of the packet
            // processing loop to avoid a re-entrancy.
            handshakeConfirmedThisLoop = true;
          }
          break;
        }
        default: {
          break;
        }
      }
      return {};
    };

    for (auto& quicFrame : regularPacket.frames) {
      switch (quicFrame.type()) {
        case QuicFrame::Type::ReadAckFrame: {
          VLOG(10) << "Server received ack frame packet=" << packetNum << " "
                   << conn;
          isNonProbingPacket = true;
          ReadAckFrame& ackFrame = *quicFrame.asReadAckFrame();

          if (ackFrame.frameType == FrameType::ACK_EXTENDED &&
              !conn.transportSettings.advertisedExtendedAckFeatures) {
            return quic::make_unexpected(QuicError(
                TransportErrorCode::PROTOCOL_VIOLATION,
                "Received unexpected ACK_EXTENDED frame"));
          } else if (
              ackFrame.frameType == FrameType::ACK_RECEIVE_TIMESTAMPS &&
              !conn.transportSettings
                   .maybeAckReceiveTimestampsConfigSentToPeer) {
            return quic::make_unexpected(QuicError(
                TransportErrorCode::PROTOCOL_VIOLATION,
                "Received unexpected ACK_RECEIVE_TIMESTAMPS frame"));
          }
          auto result = processAckFrame(
              conn,
              packetNumberSpace,
              ackFrame,
              ackedPacketVisitor,
              ackedFrameVisitor,
              markPacketLoss,
              readData.udpPacket.timings.receiveTimePoint);

          if (result.hasError()) {
            return quic::make_unexpected(result.error());
          }
          conn.lastProcessedAckEvents.emplace_back(std::move(result.value()));
          break;
        }
        case QuicFrame::Type::RstStreamFrame: {
          RstStreamFrame& frame = *quicFrame.asRstStreamFrame();
          if (frame.reliableSize.has_value()) {
            return quic::make_unexpected(QuicError(
                TransportErrorCode::PROTOCOL_VIOLATION,
                "Reliable resets not supported"));
          }
          VLOG(10) << "Server received reset stream=" << frame.streamId << " "
                   << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          auto streamResult = conn.streamManager->getStream(frame.streamId);
          if (streamResult.hasError()) {
            return quic::make_unexpected(streamResult.error());
          }
          auto& stream = streamResult.value();

          if (!stream) {
            break;
          }
          auto result = receiveRstStreamSMHandler(*stream, frame);
          if (result.hasError()) {
            return quic::make_unexpected(result.error());
          }
          break;
        }
        case QuicFrame::Type::ReadCryptoFrame: {
          pktHasRetransmittableData = true;
          pktHasCryptoData = true;
          isNonProbingPacket = true;
          ReadCryptoFrame& cryptoFrame = *quicFrame.asReadCryptoFrame();
          VLOG(10) << "Server received crypto data offset="
                   << cryptoFrame.offset
                   << " len=" << cryptoFrame.data->computeChainDataLength()
                   << " currentReadOffset="
                   << getCryptoStream(*conn.cryptoState, encryptionLevel);
          auto cryptoStream =
              getCryptoStream(*conn.cryptoState, encryptionLevel);
          auto readBufferSize = cryptoStream->readBuffer.size();
          auto result = appendDataToReadBuffer(
              *cryptoStream,
              StreamBuffer(
                  std::move(cryptoFrame.data), cryptoFrame.offset, false));
          if (result.hasError()) {
            return quic::make_unexpected(result.error());
          }
          if (isQuicInitialPacket &&
              readBufferSize != cryptoStream->readBuffer.size()) {
            ++conn.uniqueInitialCryptoFramesReceived;
            conn.cryptoState->lastInitialCryptoFrameReceivedTimePoint =
                Clock::now();
          }
          break;
        }
        case QuicFrame::Type::ReadStreamFrame: {
          ReadStreamFrame& frame = *quicFrame.asReadStreamFrame();
          VLOG(10) << "Server received stream data for stream="
                   << frame.streamId << ", offset=" << frame.offset
                   << " len=" << frame.data->computeChainDataLength()
                   << " fin=" << frame.fin << " " << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          auto streamResult = conn.streamManager->getStream(
              frame.streamId, frame.streamGroupId);
          if (streamResult.hasError()) {
            return quic::make_unexpected(streamResult.error());
          }
          auto& stream = streamResult.value();

          if (stream) {
            auto result =
                receiveReadStreamFrameSMHandler(*stream, std::move(frame));
            if (result.hasError()) {
              return quic::make_unexpected(result.error());
            }
          }
          break;
        }
        case QuicFrame::Type::MaxDataFrame: {
          MaxDataFrame& connWindowUpdate = *quicFrame.asMaxDataFrame();
          VLOG(10) << "Server received max data offset="
                   << connWindowUpdate.maximumData << " " << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          handleConnWindowUpdate(conn, connWindowUpdate, packetNum);
          break;
        }
        case QuicFrame::Type::MaxStreamDataFrame: {
          MaxStreamDataFrame& streamWindowUpdate =
              *quicFrame.asMaxStreamDataFrame();
          VLOG(10) << "Server received max stream data stream="
                   << streamWindowUpdate.streamId
                   << " offset=" << streamWindowUpdate.maximumData << " "
                   << conn;
          if (isReceivingStream(conn.nodeType, streamWindowUpdate.streamId)) {
            return quic::make_unexpected(QuicError(
                TransportErrorCode::STREAM_STATE_ERROR,
                "Received MaxStreamDataFrame for receiving stream."));
          }
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          auto streamResult =
              conn.streamManager->getStream(streamWindowUpdate.streamId);
          if (streamResult.hasError()) {
            return quic::make_unexpected(streamResult.error());
          }
          auto& stream = streamResult.value();
          if (stream) {
            handleStreamWindowUpdate(
                *stream, streamWindowUpdate.maximumData, packetNum);
          }
          break;
        }
        case QuicFrame::Type::DataBlockedFrame: {
          VLOG(10) << "Server received blocked " << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          handleConnBlocked(conn);
          break;
        }
        case QuicFrame::Type::StreamDataBlockedFrame: {
          StreamDataBlockedFrame& blocked =
              *quicFrame.asStreamDataBlockedFrame();
          VLOG(10) << "Server received blocked stream=" << blocked.streamId
                   << " " << conn;
          pktHasRetransmittableData = true;
          isNonProbingPacket = true;
          auto streamResult = conn.streamManager->getStream(blocked.streamId);
          if (streamResult.hasError()) {
            return quic::make_unexpected(streamResult.error());
          }
          auto& stream = streamResult.value();
          if (stream) {
            handleStreamBlocked(*stream);
          }
          break;
        }
        case QuicFrame::Type::StreamsBlockedFrame: {
          StreamsBlockedFrame& blocked = *quicFrame.asStreamsBlockedFrame();
          // peer wishes to open a stream, but is unable to due to the maximum
          // stream limit set by us
          // TODO implement the handler
          isNonProbingPacket = true;
          VLOG(10) << "Server received streams blocked limit="
                   << blocked.streamLimit << ", " << conn;

          break;
        }
        case QuicFrame::Type::ConnectionCloseFrame: {
          isNonProbingPacket = true;
          ConnectionCloseFrame& connFrame = *quicFrame.asConnectionCloseFrame();
          auto errMsg = fmt::format(
              "Server closed by peer reason={}", connFrame.reasonPhrase);
          VLOG(4) << errMsg << " " << conn;
          // we want to deliver app callbacks with the peer supplied error,
          // but send a NO_ERROR to the peer.
          if (conn.qLogger) {
            conn.qLogger->addTransportStateUpdate(getPeerClose(errMsg));
          }
          conn.peerConnectionError =
              QuicError(QuicErrorCode(connFrame.errorCode), std::move(errMsg));
          if (getSendConnFlowControlBytesWire(conn) == 0 &&
              conn.flowControlState.sumCurStreamBufferLen) {
            VLOG(2) << "Client gives up a flow control blocked connection";
          }
          return {};
        }
        case QuicFrame::Type::PingFrame:
          isNonProbingPacket = true;
          // Ping isn't retransmittable data. But we would like to ack them
          // early.
          pktHasRetransmittableData = true;
          conn.pendingEvents.notifyPingReceived = true;
          break;
        case QuicFrame::Type::PaddingFrame:
          break;
        case QuicFrame::Type::QuicSimpleFrame: {
          auto dstConnId =
              regularPacket.header.getHeaderForm() == HeaderForm::Short
              ? regularPacket.header.asShort()->getConnectionId()
              : regularPacket.header.asLong()->getDestinationConnId();
          pktHasRetransmittableData = true;
          QuicSimpleFrame& simpleFrame = *quicFrame.asQuicSimpleFrame();
          auto simpleResult = updateSimpleFrameOnPacketReceived(
              conn, simpleFrame, dstConnId, readData.peer != conn.peerAddress);
          if (simpleResult.hasError()) {
            return quic::make_unexpected(simpleResult.error());
          }
          isNonProbingPacket |= simpleResult.value();
          break;
        }
        case QuicFrame::Type::DatagramFrame: {
          DatagramFrame& frame = *quicFrame.asDatagramFrame();
          VLOG(10) << "Server received datagram data: " << " len="
                   << frame.length;
          // Datagram isn't retransmittable. But we would like to ack them
          // early. So, make Datagram frames count towards ack policy
          pktHasRetransmittableData = true;
          handleDatagram(
              conn, frame, readData.udpPacket.timings.receiveTimePoint);
          break;
        }
        case QuicFrame::Type::ImmediateAckFrame: {
          if (!conn.transportSettings.minAckDelay.has_value()) {
            return quic::make_unexpected(QuicError(
                TransportErrorCode::PROTOCOL_VIOLATION,
                "Received IMMEDIATE_ACK frame without announcing min_ack_delay"));
          }
          // Send an ACK from any packet number space.
          if (conn.ackStates.initialAckState) {
            conn.ackStates.initialAckState->needsToSendAckImmediately = true;
          }
          if (conn.ackStates.handshakeAckState) {
            conn.ackStates.handshakeAckState->needsToSendAckImmediately = true;
          }
          conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
          break;
        }
        default: {
          break;
        }
      }
    }

    if (handshakeConfirmedThisLoop) {
      handshakeConfirmed(conn);
    }

    maybeScheduleAckForCongestionFeedback(readData.udpPacket, ackState);
    auto keyUpdateResult = maybeHandleIncomingKeyUpdate(conn);
    if (keyUpdateResult.hasError()) {
      return quic::make_unexpected(keyUpdateResult.error());
    }

    // Update writable limit before processing the handshake data. This is so
    // that if we haven't decided whether or not to validate the peer, we
    // won't increase the limit.
    updateWritableByteLimitOnRecvPacket(conn);

    if (conn.peerAddress != readData.peer) {
      // TODO use new conn id, make sure the other endpoint has new conn id
      if (isNonProbingPacket) {
        if (packetNum == ackState.largestRecvdPacketNum) {
          ShortHeader* shortHeader = regularPacket.header.asShort();
          bool intentionalMigration = false;
          if (shortHeader &&
              shortHeader->getConnectionId() != conn.serverConnectionId) {
            intentionalMigration = true;
          }
          auto migrationResult =
              onConnectionMigration(conn, readData.peer, intentionalMigration);
          if (migrationResult.hasError()) {
            return quic::make_unexpected(migrationResult.error());
          }
        }
      } else {
        // Server will need to response with PathResponse to the new address
        // while not updating peerAddress to new address
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(
              packetSize,
              PacketDropReason(PacketDropReason::PEER_ADDRESS_CHANGE)
                  ._to_string());
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::PEER_ADDRESS_CHANGE);
        return quic::make_unexpected(QuicError(
            TransportErrorCode::INVALID_MIGRATION,
            "Probing not supported yet"));
      }
    }

    auto data = readDataFromCryptoStream(
        *getCryptoStream(*conn.cryptoState, encryptionLevel));
    if (data) {
      auto handshakeResult = conn.serverHandshakeLayer->doHandshake(
          std::move(data), encryptionLevel);
      if (handshakeResult.hasError()) {
        return quic::make_unexpected(handshakeResult.error());
      }
      auto handshakeStateResult = updateHandshakeState(conn);
      if (handshakeStateResult.hasError()) {
        if (conn.qLogger) {
          conn.qLogger->addPacketDrop(
              packetSize,
              PacketDropReason(PacketDropReason::TRANSPORT_PARAMETER_ERROR)
                  ._to_string());
        }
        QUIC_STATS(
            conn.statsCallback,
            onPacketDropped,
            PacketDropReason::TRANSPORT_PARAMETER_ERROR);
        return quic::make_unexpected(handshakeStateResult.error());
      }
    }
    updateAckSendStateOnRecvPacket(
        conn,
        ackState,
        distanceFromExpectedPacketNum,
        pktHasRetransmittableData,
        pktHasCryptoData,
        packetNumberSpace == PacketNumberSpace::Initial);
    if (encryptionLevel == EncryptionLevel::Handshake &&
        conn.initialWriteCipher) {
      conn.initialWriteCipher.reset();
      conn.initialHeaderCipher.reset();
      conn.readCodec->setInitialReadCipher(nullptr);
      conn.readCodec->setInitialHeaderCipher(nullptr);
      implicitAckCryptoStream(conn, EncryptionLevel::Initial);
    }
    processedPacketsTotal++;
  }
  if (processedPacketsTotal > 0) {
    QUIC_STATS(conn.statsCallback, onPacketsProcessed, processedPacketsTotal);
  }
  VLOG_IF(4, !udpData.empty())
      << "Leaving " << udpData.chainLength()
      << " bytes unprocessed after attempting to process "
      << kMaxNumCoalescedPackets << " packets.";

  return {};
}

quic::Expected<void, QuicError> onServerReadDataFromClosed(
    QuicServerConnectionState& conn,
    ServerEvents::ReadData& readData) {
  CHECK_EQ(conn.state, ServerState::Closed);
  BufQueue& udpData = readData.udpPacket.buf;
  auto packetSize = udpData.empty() ? 0 : udpData.chainLength();
  if (!conn.readCodec) {
    // drop data. We closed before we even got the first packet. This is
    // normally not possible but might as well.
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(
          packetSize,
          PacketDropReason(PacketDropReason::SERVER_STATE_CLOSED)._to_string());
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::SERVER_STATE_CLOSED);
    return {};
  }

  if (conn.peerConnectionError) {
    // We already got a peer error. We can ignore any further peer errors.
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(
          packetSize,
          PacketDropReason(PacketDropReason::SERVER_STATE_CLOSED)._to_string());
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::SERVER_STATE_CLOSED);
    return {};
  }
  auto parsedPacket = conn.readCodec->parsePacket(udpData, conn.ackStates);
  switch (parsedPacket.type()) {
    case CodecResult::Type::CIPHER_UNAVAILABLE: {
      VLOG(10) << "drop cipher unavailable " << conn;
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(packetSize, kCipherUnavailable);
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::CIPHER_UNAVAILABLE);
      break;
    }
    case CodecResult::Type::RETRY: {
      VLOG(10) << "drop because the server is not supposed to "
               << "receive a retry " << conn;
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(packetSize, kRetry);
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::UNEXPECTED_RETRY);
      break;
    }
    case CodecResult::Type::STATELESS_RESET: {
      VLOG(10) << "drop because reset " << conn;
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(packetSize, kReset);
      }
      QUIC_STATS(
          conn.statsCallback,
          onPacketDropped,
          PacketDropReason::UNEXPECTED_RESET);
      break;
    }
    case CodecResult::Type::NOTHING: {
      VLOG(10) << "drop no data, reason: "
               << parsedPacket.nothing()->reason._to_string() << " " << conn;
      if (conn.qLogger) {
        conn.qLogger->addPacketDrop(
            packetSize, parsedPacket.nothing()->reason._to_string());
      }
      QUIC_STATS(
          conn.statsCallback, onPacketDropped, parsedPacket.nothing()->reason);
      break;
    }
    case CodecResult::Type::CODEC_ERROR: {
      return quic::make_unexpected(parsedPacket.codecError()->error);
    }
    case CodecResult::Type::REGULAR_PACKET:
      break;
  }
  auto regularOptional = parsedPacket.regularPacket();
  if (!regularOptional) {
    // We were unable to parse the packet, drop for now.
    // Packet drop has already been added to qlog and stats
    VLOG(10) << "Not able to parse QUIC packet " << conn;
    return {};
  }
  if (regularOptional->frames.empty()) {
    // This packet had a pareseable header (most probably short header)
    // but no data. This is a protocol violation so we throw an exception.
    // This drop has not been recorded in the switch-case block above
    // so we record it here.
    if (conn.qLogger) {
      conn.qLogger->addPacketDrop(
          packetSize,
          PacketDropReason(PacketDropReason::PROTOCOL_VIOLATION)._to_string());
    }
    QUIC_STATS(
        conn.statsCallback,
        onPacketDropped,
        PacketDropReason::PROTOCOL_VIOLATION);
    return quic::make_unexpected(QuicError(
        TransportErrorCode::PROTOCOL_VIOLATION, "Packet has no frames"));
  }

  auto& regularPacket = *regularOptional;
  auto packetNum = regularPacket.header.getPacketSequenceNum();
  auto pnSpace = regularPacket.header.getPacketNumberSpace();
  if (conn.qLogger) {
    conn.qLogger->addPacket(regularPacket, packetSize);
  }

  // TODO: Should we honor a key update from the peer on a closed connection?

  // Only process the close frames in the packet
  for (auto& quicFrame : regularPacket.frames) {
    switch (quicFrame.type()) {
      case QuicFrame::Type::ConnectionCloseFrame: {
        ConnectionCloseFrame& connFrame = *quicFrame.asConnectionCloseFrame();
        auto errMsg = fmt::format(
            "Server closed by peer reason={}", connFrame.reasonPhrase);
        VLOG(4) << errMsg << " " << conn;
        if (conn.qLogger) {
          conn.qLogger->addTransportStateUpdate(getPeerClose(errMsg));
        }
        // we want to deliver app callbacks with the peer supplied error,
        // but send a NO_ERROR to the peer.
        conn.peerConnectionError =
            QuicError(QuicErrorCode(connFrame.errorCode), std::move(errMsg));
        break;
      }
      default:
        break;
    }
  }

  // We only need to set the largest received packet number in order to
  // determine whether or not we need to send a new close.
  auto& largestRecvdPacketNum =
      getAckState(conn, pnSpace).largestRecvdPacketNum;
  largestRecvdPacketNum =
      std::max<PacketNum>(largestRecvdPacketNum.value_or(packetNum), packetNum);
  return {};
}

void onServerClose(QuicServerConnectionState& conn) {
  switch (conn.state) {
    case ServerState::Open:
      onServerCloseOpenState(conn);
      return;
    case ServerState::Closed:
      return;
  }
}

void onServerCloseOpenState(QuicServerConnectionState& conn) {
  conn.state = ServerState::Closed;
}

Optional<ConnectionIdData>
QuicServerConnectionState::createAndAddNewSelfConnId() {
  // Should be set right after server transport construction.
  CHECK(connIdAlgo);
  CHECK(serverConnIdParams);

  CHECK(transportSettings.statelessResetTokenSecret);

  StatelessResetGenerator generator(
      transportSettings.statelessResetTokenSecret.value(),
      serverAddr.getFullyQualified());

  // The default connectionId algo has 36 bits of randomness.
  auto encodedCid = connIdAlgo->encodeConnectionId(*serverConnIdParams);
  size_t encodedTimes = 1;
  while (encodedCid && connIdRejector &&
         connIdRejector->rejectConnectionId(*encodedCid) &&
         encodedTimes < kConnIdEncodingRetryLimit) {
    encodedCid = connIdAlgo->encodeConnectionId(*serverConnIdParams);
    encodedTimes++;
  }
  LOG_IF(ERROR, encodedTimes == kConnIdEncodingRetryLimit)
      << "Quic CIDRejector rejected all conneectionIDs";
  if (encodedCid.hasError()) {
    return std::nullopt;
  }
  QUIC_STATS(statsCallback, onConnectionIdCreated, encodedTimes);
  auto newConnIdData =
      ConnectionIdData{*encodedCid, nextSelfConnectionIdSequence++};
  newConnIdData.token = generator.generateToken(newConnIdData.connId);
  selfConnectionIds.push_back(newConnIdData);
  return newConnIdData;
}
} // namespace quic

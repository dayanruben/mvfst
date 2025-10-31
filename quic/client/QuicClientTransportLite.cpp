/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/QuicClientTransportLite.h>

#include <folly/portability/Sockets.h>

#include <quic/QuicConstants.h>
#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/client/handshake/ClientHandshakeFactory.h>
#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/StringUtils.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/CryptoFactory.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/DatagramHandlers.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamSendHandlers.h>

namespace fsp = folly::portability::sockets;

namespace {
constexpr socklen_t kAddrLen = sizeof(sockaddr_storage);
} // namespace

namespace quic {

QuicClientTransportLite::QuicClientTransportLite(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> socket,
    std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
    size_t connectionIdSize,
    PacketNum startingPacketNum,
    bool useConnectionEndWithErrorCallback)
    : QuicClientTransportLite(
          std::move(evb),
          std::move(socket),
          std::move(handshakeFactory),
          connectionIdSize,
          useConnectionEndWithErrorCallback) {
  conn_->ackStates = AckStates(startingPacketNum);
}

QuicClientTransportLite::QuicClientTransportLite(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> socket,
    std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
    size_t connectionIdSize,
    bool useConnectionEndWithErrorCallback)
    : QuicTransportBaseLite(
          evb,
          std::move(socket),
          useConnectionEndWithErrorCallback),
      happyEyeballsConnAttemptDelayTimeout_(this) {
  DCHECK(handshakeFactory);
  auto tempConn =
      std::make_unique<QuicClientConnectionState>(std::move(handshakeFactory));
  clientConn_ = tempConn.get();
  conn_.reset(tempConn.release());

  if (connectionIdSize > kMaxConnectionIdSize) {
    LOG(ERROR) << "Source connection ID size is too large, truncating.";
    connectionIdSize = kMaxConnectionIdSize;
  }
  auto srcConnId = connectionIdSize > 0
      ? ConnectionId::createRandom(connectionIdSize).value()
      : ConnectionId::createZeroLength();
  conn_->clientConnectionId = srcConnId;
  conn_->readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);
  conn_->readCodec->setClientConnectionId(srcConnId);
  conn_->selfConnectionIds.emplace_back(
      srcConnId, conn_->nextSelfConnectionIdSequence++);
  auto randCidExpected =
      ConnectionId::createRandom(kMinInitialDestinationConnIdLength);
  CHECK(randCidExpected.has_value());
  clientConn_->initialDestinationConnectionId = randCidExpected.value();
  clientConn_->originalDestinationConnectionId =
      clientConn_->initialDestinationConnectionId;
  conn_->clientChosenDestConnectionId =
      clientConn_->initialDestinationConnectionId;
  VLOG(4) << "initial dcid: "
          << clientConn_->initialDestinationConnectionId->hex();
  if (conn_->qLogger) {
    conn_->qLogger->setDcid(conn_->clientChosenDestConnectionId);
  }

  conn_->readCodec->setCodecParameters(CodecParameters(
      conn_->peerAckDelayExponent,
      conn_->originalVersion.value(),
      conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer,
      conn_->transportSettings.advertisedExtendedAckFeatures));

  conn_->pathManager->setPathValidationCallback(this);

  VLOG(10) << "client created " << *conn_;
}

QuicClientTransportLite::~QuicClientTransportLite() {
  VLOG(10) << "Destroyed connection to server=" << conn_->peerAddress;
  // The caller probably doesn't need the conn callback after destroying the
  // transport.
  resetConnectionCallbacks();
  // Close without draining.
  closeImpl(
      QuicError(
          QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
          std::string("Closing from client destructor")),
      false /* drainConnection */);
  // closeImpl may have been called earlier with drain = true, so force close.
  closeUdpSocket();

  if (clientConn_->happyEyeballsState.secondSocket) {
    auto sock = std::move(clientConn_->happyEyeballsState.secondSocket);
    sock->pauseRead();
    (void)sock->close();
  }
}

quic::Expected<void, QuicError> QuicClientTransportLite::processUdpPacket(
    const folly::SocketAddress& localAddress,
    ReceivedUdpPacket&& udpPacket,
    const folly::SocketAddress& peerAddress) {
  // Process the arriving UDP packet, which may have coalesced QUIC packets.
  {
    BufQueue& udpData = udpPacket.buf;

    if (!conn_->version) {
      // We only check for version negotiation packets before the version
      // is negotiated.
      auto versionNegotiation =
          conn_->readCodec->tryParsingVersionNegotiation(udpData);
      if (versionNegotiation) {
        VLOG(4) << "Got version negotiation packet from peer=" << peerAddress
                << " versions=" << std::hex << versionNegotiation->versions
                << " " << *this;

        return quic::make_unexpected(QuicError(
            LocalErrorCode::NEW_VERSION_NEGOTIATED,
            "Received version negotiation packet"));
      }
    }

    for (uint16_t processedPackets = 0;
         !udpData.empty() && processedPackets < kMaxNumCoalescedPackets;
         processedPackets++) {
      auto res = processUdpPacketData(localAddress, udpPacket, peerAddress);
      if (!res.has_value()) {
        return res;
      }
    }
    VLOG_IF(4, !udpData.empty())
        << "Leaving " << udpData.chainLength()
        << " bytes unprocessed after attempting to process "
        << kMaxNumCoalescedPackets << " packets.";
  }

  // Process any deferred pending 1RTT and handshake packets if we have keys.
  if (conn_->readCodec->getOneRttReadCipher() &&
      !clientConn_->pendingOneRttData.empty()) {
    for (auto& pendingPacket : clientConn_->pendingOneRttData) {
      // The first loop should try to process any leftover data in the incoming
      // buffer.
      pendingPacket.udpPacket.buf.append(udpPacket.buf.move());

      auto res = processUdpPacketData(
          pendingPacket.localAddress,
          pendingPacket.udpPacket,
          pendingPacket.peerAddress);
      if (!res.has_value()) {
        return res;
      }
    }
    clientConn_->pendingOneRttData.clear();
  }
  if (conn_->readCodec->getHandshakeReadCipher() &&
      !clientConn_->pendingHandshakeData.empty()) {
    for (auto& pendingPacket : clientConn_->pendingHandshakeData) {
      // The first loop should try to process any leftover data in the incoming
      // buffer.
      pendingPacket.udpPacket.buf.append(udpPacket.buf.move());

      auto res = processUdpPacketData(
          pendingPacket.localAddress,
          pendingPacket.udpPacket,
          pendingPacket.peerAddress);
      if (!res.has_value()) {
        return res;
      }
    }
    clientConn_->pendingHandshakeData.clear();
  }
  return {};
}

quic::Expected<void, QuicError> QuicClientTransportLite::processUdpPacketData(
    const folly::SocketAddress& localAddress,
    ReceivedUdpPacket& udpPacket,
    const folly::SocketAddress& peerAddress) {
  auto packetSize = udpPacket.buf.chainLength();
  if (packetSize == 0) {
    return {};
  }
  auto parsedPacket = conn_->readCodec->parsePacket(
      udpPacket.buf, conn_->ackStates, conn_->clientConnectionId->size());
  StatelessReset* statelessReset = parsedPacket.statelessReset();
  if (statelessReset) {
    const auto& token = clientConn_->statelessResetToken;
    if (statelessReset->token == token) {
      VLOG(4) << "Received Stateless Reset " << *this;
      conn_->peerConnectionError = QuicError(
          QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
          toString(LocalErrorCode::CONNECTION_RESET).str());
      return quic::make_unexpected(
          QuicError(LocalErrorCode::NO_ERROR, "Stateless Reset Received"));
    }
    VLOG(4) << "Drop StatelessReset for bad connId or token " << *this;
    // Don't treat this as a fatal error, just ignore the packet.
    return {};
  }

  RetryPacket* retryPacket = parsedPacket.retryPacket();
  if (retryPacket) {
    if (conn_->qLogger) {
      conn_->qLogger->addPacket(*retryPacket, packetSize, true);
    }

    // we reject retry packet if our initial has been processed or we've rx'd a
    // prior retry packet; note that initialAckState is reset to nullptr only
    // after we've confirmed handshake.
    bool shouldRejectRetryPacket = !conn_->ackStates.initialAckState ||
        conn_->ackStates.initialAckState->largestRecvdPacketNum.has_value() ||
        !clientConn_->retryToken.empty();

    if (shouldRejectRetryPacket) {
      VLOG(4) << "Server incorrectly issued a retry packet; dropping retry "
              << *this;
      // Not a fatal error, just ignore the packet.
      return {};
    }

    const ConnectionId* originalDstConnId =
        &(*clientConn_->originalDestinationConnectionId);

    if (!clientConn_->clientHandshakeLayer->verifyRetryIntegrityTag(
            *originalDstConnId, *retryPacket)) {
      VLOG(4) << "The integrity tag in the retry packet was invalid. "
              << "Dropping bad retry packet. " << *this;
      // Not a fatal error, just ignore the packet.
      return {};
    }

    if (happyEyeballsEnabled_) {
      happyEyeballsOnDataReceived(
          *clientConn_,
          happyEyeballsConnAttemptDelayTimeout_,
          socket_,
          peerAddress);
    }
    // Set the destination connection ID to be the value from the source
    // connection id of the retry packet
    clientConn_->initialDestinationConnectionId =
        retryPacket->header.getSourceConnId();

    auto released = static_cast<QuicClientConnectionState*>(conn_.release());
    std::unique_ptr<QuicClientConnectionState> uniqueClient(released);
    auto tempConn = undoAllClientStateForRetry(std::move(uniqueClient));

    clientConn_ = tempConn.get();
    conn_.reset(tempConn.release());

    clientConn_->retryToken = retryPacket->header.getToken();

    // TODO (amsharma): add a "RetryPacket" QLog event, and log it here.
    // TODO (amsharma): verify the "original_connection_id" parameter
    // upon receiving a subsequent initial from the server.

    auto handshakeResult = startCryptoHandshake();
    if (!handshakeResult.has_value()) {
      return quic::make_unexpected(handshakeResult.error());
    }
    return {}; // Retry processed successfully
  }

  auto cipherUnavailable = parsedPacket.cipherUnavailable();
  if (cipherUnavailable && cipherUnavailable->packet &&
      !cipherUnavailable->packet->empty() &&
      (cipherUnavailable->protectionType == ProtectionType::KeyPhaseZero ||
       cipherUnavailable->protectionType == ProtectionType::Handshake) &&
      clientConn_->pendingOneRttData.size() +
              clientConn_->pendingHandshakeData.size() <
          clientConn_->transportSettings.maxPacketsToBuffer) {
    auto& pendingData =
        cipherUnavailable->protectionType == ProtectionType::KeyPhaseZero
        ? clientConn_->pendingOneRttData
        : clientConn_->pendingHandshakeData;
    pendingData.emplace_back(
        localAddress,
        ReceivedUdpPacket(
            std::move(cipherUnavailable->packet),
            udpPacket.timings,
            udpPacket.tosValue),
        peerAddress);
    if (conn_->qLogger) {
      conn_->qLogger->addPacketBuffered(
          cipherUnavailable->protectionType, packetSize);
    }
    // Packet buffered, not an error
    return {};
  }

  auto codecError = parsedPacket.codecError();
  if (codecError) {
    return quic::make_unexpected(QuicError(
        *codecError->error.code.asTransportErrorCode(),
        std::move(codecError->error.message)));
  }

  RegularQuicPacket* regularOptional = parsedPacket.regularPacket();
  if (!regularOptional) {
    VLOG(4) << "Packet parse error for " << *this;
    QUIC_STATS(
        statsCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR_CLIENT);
    if (conn_->qLogger) {
      conn_->qLogger->addPacketDrop(packetSize, kParse);
    }
    // If this was a protocol violation, we would return a codec error instead.
    // Ignore this case as something that caused a non-codec parse error.
    return {};
  }

  if (regularOptional->frames.empty()) {
    // This is either a packet that has no data (long-header parsed but no data
    // found) or a regular packet with a short header and no frames. Both are
    // protocol violations.
    LOG(ERROR) << "Packet has no frames " << *this;
    QUIC_STATS(
        conn_->statsCallback,
        onPacketDropped,
        PacketDropReason::PROTOCOL_VIOLATION);
    if (conn_->qLogger) {
      conn_->qLogger->addPacketDrop(
          packetSize,
          PacketDropReason(PacketDropReason::PROTOCOL_VIOLATION)._to_string());
    }
    return quic::make_unexpected(QuicError(
        TransportErrorCode::PROTOCOL_VIOLATION, "Packet has no frames"));
  }

  if (happyEyeballsEnabled_) {
    CHECK(socket_);
    happyEyeballsOnDataReceived(
        *clientConn_,
        happyEyeballsConnAttemptDelayTimeout_,
        socket_,
        peerAddress);
  }

  LongHeader* longHeader = regularOptional->header.asLong();
  ShortHeader* shortHeader = regularOptional->header.asShort();

  auto protectionLevel = regularOptional->header.getProtectionType();
  auto encryptionLevel = protectionTypeToEncryptionLevel(protectionLevel);

  auto packetNum = regularOptional->header.getPacketSequenceNum();
  auto pnSpace = regularOptional->header.getPacketNumberSpace();

  bool isProtectedPacket = protectionLevel == ProtectionType::KeyPhaseZero ||
      protectionLevel == ProtectionType::KeyPhaseOne;

  auto& regularPacket = *regularOptional;
  if (conn_->qLogger) {
    conn_->qLogger->addPacket(regularPacket, packetSize);
  }
  if (!isProtectedPacket) {
    for (auto& quicFrame : regularPacket.frames) {
      auto isPadding = quicFrame.asPaddingFrame();
      auto isAck = quicFrame.asReadAckFrame();
      auto isClose = quicFrame.asConnectionCloseFrame();
      auto isCrypto = quicFrame.asReadCryptoFrame();
      auto isPing = quicFrame.asPingFrame();
      // TODO: add path challenge and response
      if (!isPadding && !isAck && !isClose && !isCrypto && !isPing) {
        return quic::make_unexpected(
            QuicError(TransportErrorCode::PROTOCOL_VIOLATION, "Invalid frame"));
      }
    }
  }

  // We got a packet that was not the version negotiation packet, that means
  // that the version is now bound to the new packet.
  if (!conn_->version) {
    conn_->version = conn_->originalVersion;
  }

  if (!conn_->serverConnectionId && longHeader) {
    conn_->serverConnectionId = longHeader->getSourceConnId();
    auto& cid = conn_->peerConnectionIds.emplace_back(
        longHeader->getSourceConnId(), kInitialConnectionIdSequenceNumber);
    cid.inUse = true;
    conn_->readCodec->setServerConnectionId(*conn_->serverConnectionId);
    // TODO: JBESHAY MIGRATION - consolidate tracking the peer connection id
    // in one place.
    auto setCidRes = conn_->pathManager->setDestinationCidForPath(
        conn_->currentPathId, cid.connId);
    if (setCidRes.hasError()) {
      return quic::make_unexpected(setCidRes.error());
    }
  }

  // Error out if the connection id on the packet is not the one that is
  // expected.
  bool connidMatched = true;
  auto& destinationCidInPacket = longHeader ? longHeader->getDestinationConnId()
                                            : shortHeader->getConnectionId();

  if (std::find_if(
          conn_->selfConnectionIds.begin(),
          conn_->selfConnectionIds.end(),
          [&](const auto& cidData) {
            return cidData.connId == destinationCidInPacket;
          }) == conn_->selfConnectionIds.end()) {
    connidMatched = false;
  }
  if (!connidMatched) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::PROTOCOL_VIOLATION, "Invalid connection id"));
  }

  auto readPath = conn_->pathManager->getPath(localAddress, peerAddress);
  if (!readPath) {
    // Drop packets that are not from known peers, i.e., current, probing, or
    // migration paths.
    // This should not close the connection since these packets can be from a
    // spurious sender cloning the server's packets.
    QUIC_STATS(
        statsCallback_, onPacketDropped, PacketDropReason::PEER_ADDRESS_CHANGE);
    return {};
  }

  if (conn_->currentPathId == readPath->id &&
      destinationCidInPacket != conn_->clientConnectionId) {
    // The server is using a new CID for the current path.
    conn_->clientConnectionId = destinationCidInPacket;
    conn_->readCodec->setClientConnectionId(conn_->clientConnectionId.value());
    VLOG(4) << "The server switched its dest cid to: "
            << destinationCidInPacket.hex();
  }

  // Add the packet to the AckState associated with the packet number space.
  auto& ackState = getAckState(*conn_, pnSpace);
  auto addResult = addPacketToAckState(*conn_, ackState, packetNum, udpPacket);
  if (!addResult.has_value()) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Failed to add packet to ack state"));
  }
  uint64_t distanceFromExpectedPacketNum = addResult.value();
  if (distanceFromExpectedPacketNum > 0) {
    QUIC_STATS(conn_->statsCallback, onOutOfOrderPacketReceived);
  }

  bool pktHasRetransmittableData = false;
  bool pktHasCryptoData = false;

  AckedPacketVisitor ackedPacketVisitor =
      [&](const OutstandingPacketWrapper& outstandingPacket) {
        auto outstandingProtectionType =
            outstandingPacket.packet.header.getProtectionType();
        if (outstandingProtectionType == ProtectionType::KeyPhaseZero) {
          // If we received an ack for data that we sent in 1-rtt from
          // the server, we can assume that the server had successfully
          // derived the 1-rtt keys and hence received the client
          // finished message. We can mark the handshake as confirmed and
          // drop the handshake cipher and outstanding packets after the
          // processing loop.
          conn_->handshakeLayer->handshakeConfirmed();
        }
        return maybeVerifyPendingKeyUpdate(
            *conn_, outstandingPacket, regularPacket);
      };
  AckedFrameVisitor ackedFrameVisitor =
      [&](const OutstandingPacketWrapper& outstandingPacket,
          const QuicWriteFrame& packetFrame)
      -> quic::Expected<void, QuicError> {
    auto outstandingProtectionType =
        outstandingPacket.packet.header.getProtectionType();
    switch (packetFrame.type()) {
      case QuicWriteFrame::Type::WriteAckFrame: {
        const WriteAckFrame& frame = *packetFrame.asWriteAckFrame();
        DCHECK(!frame.ackBlocks.empty());
        VLOG(4) << "Client received ack for largestAcked="
                << frame.ackBlocks.front().end << " " << *this;
        commonAckVisitorForAckFrame(ackState, frame);
        break;
      }
      case QuicWriteFrame::Type::RstStreamFrame: {
        const RstStreamFrame& frame = *packetFrame.asRstStreamFrame();
        VLOG(4) << "Client received ack for reset frame stream="
                << frame.streamId << " " << *this;

        auto stream =
            conn_->streamManager->getStream(frame.streamId).value_or(nullptr);
        if (stream) {
          return sendRstAckSMHandler(*stream, frame.reliableSize);
        }
        break;
      }
      case QuicWriteFrame::Type::WriteStreamFrame: {
        const WriteStreamFrame& frame = *packetFrame.asWriteStreamFrame();

        auto ackedStreamResult =
            conn_->streamManager->getStream(frame.streamId);
        if (!ackedStreamResult.has_value()) {
          return quic::make_unexpected(ackedStreamResult.error());
        }
        auto& ackedStream = ackedStreamResult.value();
        VLOG(4) << "Client got ack for stream=" << frame.streamId
                << " offset=" << frame.offset << " fin=" << frame.fin
                << " data=" << frame.len
                << " closed=" << (ackedStream == nullptr) << " " << *this;
        if (ackedStream) {
          return sendAckSMHandler(*ackedStream, frame);
        }
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
        const WriteCryptoFrame& frame = *packetFrame.asWriteCryptoFrame();
        auto cryptoStream = getCryptoStream(
            *conn_->cryptoState,
            protectionTypeToEncryptionLevel(outstandingProtectionType));
        processCryptoStreamAck(*cryptoStream, frame.offset, frame.len);
        break;
      }
      case QuicWriteFrame::Type::PingFrame:
        conn_->pendingEvents.cancelPingTimeout = true;
        break;
      case QuicWriteFrame::Type::QuicSimpleFrame:
      default:
        // ignore other frames.
        break;
    }
    return {};
  };

  for (auto& quicFrame : regularPacket.frames) {
    switch (quicFrame.type()) {
      case QuicFrame::Type::ReadAckFrame: {
        VLOG(10) << "Client received ack frame in packet=" << packetNum << " "
                 << *this;
        ReadAckFrame& ackFrame = *quicFrame.asReadAckFrame();

        if (ackFrame.frameType == FrameType::ACK_EXTENDED &&
            !conn_->transportSettings.advertisedExtendedAckFeatures) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::PROTOCOL_VIOLATION,
              "Received unexpected ACK_EXTENDED frame"));
        } else if (
            ackFrame.frameType == FrameType::ACK_RECEIVE_TIMESTAMPS &&
            !conn_->transportSettings
                 .maybeAckReceiveTimestampsConfigSentToPeer) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::PROTOCOL_VIOLATION,
              "Received unexpected ACK_RECEIVE_TIMESTAMPS frame"));
        }

        auto result = processAckFrame(
            *conn_,
            pnSpace,
            ackFrame,
            ackedPacketVisitor,
            ackedFrameVisitor,
            markPacketLoss,
            udpPacket.timings.receiveTimePoint);
        if (!result.has_value()) {
          return quic::make_unexpected(result.error());
        }
        conn_->lastProcessedAckEvents.emplace_back(std::move(result.value()));
        break;
      }
      case QuicFrame::Type::RstStreamFrame: {
        RstStreamFrame& frame = *quicFrame.asRstStreamFrame();
        VLOG(10) << "Client received reset stream=" << frame.streamId << " "
                 << *this;
        if (frame.reliableSize.has_value()) {
          // We're not yet supporting the handling of RESET_STREAM_AT frames
          return quic::make_unexpected(QuicError(
              TransportErrorCode::PROTOCOL_VIOLATION,
              "Reliable resets not supported"));
        }
        pktHasRetransmittableData = true;
        auto streamResult = conn_->streamManager->getStream(frame.streamId);
        if (!streamResult.has_value()) {
          return quic::make_unexpected(streamResult.error());
        }
        auto& stream = streamResult.value();
        if (!stream) {
          break;
        }
        auto rstResult = receiveRstStreamSMHandler(*stream, frame);
        if (!rstResult.has_value()) {
          return quic::make_unexpected(rstResult.error());
        }
        break;
      }
      case QuicFrame::Type::ReadCryptoFrame: {
        pktHasRetransmittableData = true;
        pktHasCryptoData = true;
        ReadCryptoFrame& cryptoFrame = *quicFrame.asReadCryptoFrame();
        VLOG(10) << "Client received crypto data offset=" << cryptoFrame.offset
                 << " len=" << cryptoFrame.data->computeChainDataLength()
                 << " packetNum=" << packetNum << " " << *this;
        auto appendResult = appendDataToReadBuffer(
            *getCryptoStream(*conn_->cryptoState, encryptionLevel),
            StreamBuffer(
                std::move(cryptoFrame.data), cryptoFrame.offset, false));
        if (!appendResult.has_value()) {
          return quic::make_unexpected(appendResult.error());
        }
        break;
      }
      case QuicFrame::Type::ReadStreamFrame: {
        ReadStreamFrame& frame = *quicFrame.asReadStreamFrame();
        VLOG(10) << "Client received stream data for stream=" << frame.streamId
                 << " offset=" << frame.offset
                 << " len=" << frame.data->computeChainDataLength()
                 << " fin=" << frame.fin << " packetNum=" << packetNum << " "
                 << *this;
        auto streamResult = conn_->streamManager->getStream(frame.streamId);
        if (!streamResult.has_value()) {
          return quic::make_unexpected(streamResult.error());
        }
        auto& stream = streamResult.value();
        pktHasRetransmittableData = true;
        if (!stream) {
          VLOG(10) << "Could not find stream=" << frame.streamId << " "
                   << *conn_;
          break;
        }
        auto readResult =
            receiveReadStreamFrameSMHandler(*stream, std::move(frame));
        if (!readResult.has_value()) {
          return quic::make_unexpected(readResult.error());
        }
        break;
      }
      case QuicFrame::Type::ReadNewTokenFrame: {
        ReadNewTokenFrame& newTokenFrame = *quicFrame.asReadNewTokenFrame();
        std::string tokenStr = newTokenFrame.token->toString();
        VLOG(10) << "client received new token token="
                 << quic::hexlify(tokenStr);
        if (newTokenCallback_) {
          newTokenCallback_(std::move(tokenStr));
        }
        break;
      }
      case QuicFrame::Type::MaxDataFrame: {
        MaxDataFrame& connWindowUpdate = *quicFrame.asMaxDataFrame();
        VLOG(10) << "Client received max data offset="
                 << connWindowUpdate.maximumData << " " << *this;
        pktHasRetransmittableData = true;
        handleConnWindowUpdate(*conn_, connWindowUpdate, packetNum);
        break;
      }
      case QuicFrame::Type::MaxStreamDataFrame: {
        MaxStreamDataFrame& streamWindowUpdate =
            *quicFrame.asMaxStreamDataFrame();
        VLOG(10) << "Client received max stream data stream="
                 << streamWindowUpdate.streamId
                 << " offset=" << streamWindowUpdate.maximumData << " "
                 << *this;
        if (isReceivingStream(conn_->nodeType, streamWindowUpdate.streamId)) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::STREAM_STATE_ERROR,
              "Received MaxStreamDataFrame for receiving stream."));
        }
        pktHasRetransmittableData = true;
        auto streamResult =
            conn_->streamManager->getStream(streamWindowUpdate.streamId);
        if (!streamResult.has_value()) {
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
        VLOG(10) << "Client received blocked " << *this;
        pktHasRetransmittableData = true;
        handleConnBlocked(*conn_);
        break;
      }
      case QuicFrame::Type::StreamDataBlockedFrame: {
        // peer wishes to send data, but is unable to due to stream-level flow
        // control
        StreamDataBlockedFrame& blocked = *quicFrame.asStreamDataBlockedFrame();
        VLOG(10) << "Client received blocked stream=" << blocked.streamId << " "
                 << *this;
        pktHasRetransmittableData = true;
        auto streamResult = conn_->streamManager->getStream(blocked.streamId);
        if (!streamResult.has_value()) {
          return quic::make_unexpected(streamResult.error());
        }
        auto& stream = streamResult.value();
        if (stream) {
          handleStreamBlocked(*stream);
        }
        break;
      }
      case QuicFrame::Type::StreamsBlockedFrame: {
        // peer wishes to open a stream, but is unable to due to the maximum
        // stream limit set by us
        StreamsBlockedFrame& blocked = *quicFrame.asStreamsBlockedFrame();
        VLOG(10) << "Client received stream blocked limit="
                 << blocked.streamLimit << " " << *this;
        // TODO implement handler for it
        break;
      }
      case QuicFrame::Type::ConnectionCloseFrame: {
        ConnectionCloseFrame& connFrame = *quicFrame.asConnectionCloseFrame();
        auto errMsg = fmt::format(
            "Client closed by peer reason={}", connFrame.reasonPhrase);
        VLOG(4) << errMsg << " " << *this;
        // we want to deliver app callbacks with the peer supplied error,
        // but send a NO_ERROR to the peer.
        if (conn_->qLogger) {
          conn_->qLogger->addTransportStateUpdate(getPeerClose(errMsg));
        }
        conn_->peerConnectionError =
            QuicError(QuicErrorCode(connFrame.errorCode), std::move(errMsg));
        // We don't return an error here, as receiving a close triggers the
        // peer connection error path instead of the local error path.
        return {};
      }
      case QuicFrame::Type::PingFrame:
        // Ping isn't retransmittable. But we would like to ack them early.
        // So, make Ping frames count towards ack policy
        pktHasRetransmittableData = true;
        conn_->pendingEvents.notifyPingReceived = true;
        break;
      case QuicFrame::Type::PaddingFrame:
        break;
      case QuicFrame::Type::QuicSimpleFrame: {
        QuicSimpleFrame& simpleFrame = *quicFrame.asQuicSimpleFrame();
        pktHasRetransmittableData = true;
        auto updateResult = updateSimpleFrameOnPacketReceived(
            *conn_,
            readPath->id,
            simpleFrame,
            longHeader ? longHeader->getDestinationConnId()
                       : shortHeader->getConnectionId());
        if (!updateResult.has_value()) {
          return quic::make_unexpected(updateResult.error());
        }
        break;
      }
      case QuicFrame::Type::DatagramFrame: {
        DatagramFrame& frame = *quicFrame.asDatagramFrame();
        VLOG(10) << "Client received datagram data: " << "len=" << frame.length
                 << " " << *this;
        // Datagram isn't retransmittable. But we would like to ack them early.
        // So, make Datagram frames count towards ack policy
        pktHasRetransmittableData = true;
        handleDatagram(*conn_, frame, udpPacket.timings.receiveTimePoint);
        break;
      }
      case QuicFrame::Type::ImmediateAckFrame: {
        if (!conn_->transportSettings.minAckDelay.has_value()) {
          // We do not accept IMMEDIATE_ACK frames. This is a protocol
          // violation.
          return quic::make_unexpected(QuicError(
              TransportErrorCode::PROTOCOL_VIOLATION,
              "Received IMMEDIATE_ACK frame without announcing min_ack_delay"));
        }
        // Send an ACK from any packet number space.
        if (conn_->ackStates.initialAckState) {
          conn_->ackStates.initialAckState->needsToSendAckImmediately = true;
        }
        if (conn_->ackStates.handshakeAckState) {
          conn_->ackStates.handshakeAckState->needsToSendAckImmediately = true;
        }
        conn_->ackStates.appDataAckState.needsToSendAckImmediately = true;
        break;
      }
      default:
        break;
    }
  }

  auto handshakeLayer = clientConn_->clientHandshakeLayer;
  if (handshakeLayer->getPhase() == ClientHandshake::Phase::Established &&
      hasInitialOrHandshakeCiphers(*conn_)) {
    handshakeConfirmed(*conn_);
  }

  maybeScheduleAckForCongestionFeedback(udpPacket, ackState);
  if (auto handleKeyUpdate = maybeHandleIncomingKeyUpdate(*conn_);
      !handleKeyUpdate.has_value()) {
    return quic::make_unexpected(handleKeyUpdate.error());
  }

  // Try reading bytes off of crypto, and performing a handshake.
  auto cryptoData = readDataFromCryptoStream(
      *getCryptoStream(*conn_->cryptoState, encryptionLevel));
  if (cryptoData) {
    bool hadOneRttKey = conn_->oneRttWriteCipher != nullptr;
    auto handshakeResult =
        handshakeLayer->doHandshake(std::move(cryptoData), encryptionLevel);
    if (!handshakeResult.has_value()) {
      return quic::make_unexpected(handshakeResult.error());
    }
    bool oneRttKeyDerivationTriggered = false;
    if (!hadOneRttKey && conn_->oneRttWriteCipher) {
      oneRttKeyDerivationTriggered = true;
      updatePacingOnKeyEstablished(*conn_);
    }
    if (conn_->oneRttWriteCipher && conn_->readCodec->getOneRttReadCipher()) {
      clientConn_->zeroRttWriteCipher.reset();
      clientConn_->zeroRttWriteHeaderCipher.reset();
    }
    if (!clientConn_->zeroRttRejected.has_value()) {
      clientConn_->zeroRttRejected = handshakeLayer->getZeroRttRejected();
      if (clientConn_->zeroRttRejected.has_value() &&
          *clientConn_->zeroRttRejected) {
        if (conn_->qLogger) {
          conn_->qLogger->addTransportStateUpdate(kZeroRttRejected);
        }
        QUIC_STATS(conn_->statsCallback, onZeroRttRejected);
        handshakeLayer->removePsk(hostname_);
        if (!handshakeLayer->getCanResendZeroRtt().value_or(false)) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
              "Zero-rtt attempted but the early parameters do not match the handshake parameters"));
        }
      } else if (clientConn_->zeroRttRejected.has_value()) {
        if (conn_->qLogger) {
          conn_->qLogger->addTransportStateUpdate(kZeroRttAccepted);
        }
        QUIC_STATS(conn_->statsCallback, onZeroRttAccepted);
        conn_->usedZeroRtt = true;
      }
    }
    // We should get transport parameters if we've derived 1-rtt keys and 0-rtt
    // was rejected, or we have derived 1-rtt keys and 0-rtt was never
    // attempted.
    if (oneRttKeyDerivationTriggered) {
      const auto& serverParams = handshakeLayer->getServerTransportParams();
      if (!serverParams) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            "No server transport params"));
      }
      if ((clientConn_->zeroRttRejected.has_value() &&
           *clientConn_->zeroRttRejected) ||
          !clientConn_->zeroRttRejected.has_value()) {
        auto originalPeerMaxOffset =
            conn_->flowControlState.peerAdvertisedMaxOffset;
        auto originalPeerInitialStreamOffsetBidiLocal =
            conn_->flowControlState
                .peerAdvertisedInitialMaxStreamOffsetBidiLocal;
        auto originalPeerInitialStreamOffsetBidiRemote =
            conn_->flowControlState
                .peerAdvertisedInitialMaxStreamOffsetBidiRemote;
        auto originalPeerInitialStreamOffsetUni =
            conn_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni;
        VLOG(10) << "Client negotiated transport params " << *this;
        auto maxStreamsBidi = getIntegerParameter(
            TransportParameterId::initial_max_streams_bidi,
            serverParams->parameters);
        if (!maxStreamsBidi.has_value()) {
          return quic::make_unexpected(maxStreamsBidi.error());
        }

        auto maxStreamsUni = getIntegerParameter(
            TransportParameterId::initial_max_streams_uni,
            serverParams->parameters);
        if (!maxStreamsUni.has_value()) {
          return quic::make_unexpected(maxStreamsUni.error());
        }

        auto processResult = processServerInitialParams(
            *clientConn_, serverParams.value(), packetNum);
        if (!processResult.has_value()) {
          return quic::make_unexpected(processResult.error());
        }

        cacheServerInitialParams(
            *clientConn_,
            conn_->flowControlState.peerAdvertisedMaxOffset,
            conn_->flowControlState
                .peerAdvertisedInitialMaxStreamOffsetBidiLocal,
            conn_->flowControlState
                .peerAdvertisedInitialMaxStreamOffsetBidiRemote,
            conn_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
            maxStreamsBidi.value().value_or(0),
            maxStreamsUni.value().value_or(0),
            conn_->peerAdvertisedKnobFrameSupport,
            conn_->maybePeerAckReceiveTimestampsConfig.has_value(),
            conn_->maybePeerAckReceiveTimestampsConfig
                ? conn_->maybePeerAckReceiveTimestampsConfig
                      ->maxReceiveTimestampsPerAck
                : 0,
            conn_->maybePeerAckReceiveTimestampsConfig
                ? conn_->maybePeerAckReceiveTimestampsConfig
                      ->receiveTimestampsExponent
                : 3,
            conn_->peerAdvertisedReliableStreamResetSupport,
            conn_->peerAdvertisedExtendedAckFeatures);

        if (clientConn_->zeroRttRejected.has_value() &&
            *clientConn_->zeroRttRejected) {
          // verify that the new flow control parameters are >= the original
          // transport parameters that were use. This is the easy case. If the
          // flow control decreases then we are just screwed and we need to have
          // the app retry the connection. The other parameters can be updated.
          // TODO: implement undo transport state on retry.
          if (originalPeerMaxOffset >
                  conn_->flowControlState.peerAdvertisedMaxOffset ||
              originalPeerInitialStreamOffsetBidiLocal >
                  conn_->flowControlState
                      .peerAdvertisedInitialMaxStreamOffsetBidiLocal ||
              originalPeerInitialStreamOffsetBidiRemote >
                  conn_->flowControlState
                      .peerAdvertisedInitialMaxStreamOffsetBidiRemote ||

              originalPeerInitialStreamOffsetUni >
                  conn_->flowControlState
                      .peerAdvertisedInitialMaxStreamOffsetUni) {
            return quic::make_unexpected(QuicError(
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                "Rejection of zero rtt parameters unsupported"));
          }
        }
      }
      updateNegotiatedAckFeatures(*conn_);

      // TODO This sucks, but manually update the max packet size until we fix
      // 0-rtt transport parameters.
      if (conn_->transportSettings.canIgnorePathMTU &&
          clientConn_->zeroRttRejected.has_value() &&
          !*clientConn_->zeroRttRejected) {
        auto updatedPacketSize = getIntegerParameter(
            TransportParameterId::max_packet_size, serverParams->parameters);
        uint64_t newPacketSize = !updatedPacketSize.has_value()
            ? kDefaultUDPSendPacketLen
            : updatedPacketSize.value().value_or(kDefaultUDPSendPacketLen);
        newPacketSize =
            std::max<uint64_t>(newPacketSize, kDefaultUDPSendPacketLen);
        newPacketSize =
            std::min<uint64_t>(newPacketSize, kDefaultMaxUDPPayload);
        conn_->udpSendPacketLen = newPacketSize;
      }

      // TODO this is another bandaid. Explicitly set the stateless reset token
      // or else conns that use 0-RTT won't be able to parse stateless resets.
      if (!clientConn_->statelessResetToken) {
        auto statelessResetTokenResult =
            getStatelessResetTokenParameter(serverParams->parameters);
        if (statelessResetTokenResult.has_value()) {
          clientConn_->statelessResetToken = statelessResetTokenResult.value();
        }
      }
      if (clientConn_->statelessResetToken) {
        conn_->readCodec->setStatelessResetToken(
            clientConn_->statelessResetToken.value());
        auto& cryptoFactory = handshakeLayer->getCryptoFactory();
        conn_->readCodec->setCryptoEqual(
            cryptoFactory.getCryptoEqualFunction());
      }
    }

    if (clientConn_->zeroRttRejected.has_value() &&
        *clientConn_->zeroRttRejected) {
      // TODO: Make sure the alpn is the same, if not then do a full undo of the
      // state.
      clientConn_->zeroRttWriteCipher.reset();
      clientConn_->zeroRttWriteHeaderCipher.reset();
      auto result = markZeroRttPacketsLost(*conn_, markPacketLoss);
      if (!result.has_value()) {
        return result;
      }
    }
  }
  updateAckSendStateOnRecvPacket(
      *conn_,
      ackState,
      distanceFromExpectedPacketNum,
      pktHasRetransmittableData,
      pktHasCryptoData);
  if (encryptionLevel == EncryptionLevel::Handshake &&
      conn_->initialWriteCipher) {
    conn_->initialWriteCipher.reset();
    conn_->initialHeaderCipher.reset();
    conn_->readCodec->setInitialReadCipher(nullptr);
    conn_->readCodec->setInitialHeaderCipher(nullptr);
    implicitAckCryptoStream(*conn_, EncryptionLevel::Initial);
  }

  return {};
}

quic::Expected<void, QuicError> QuicClientTransportLite::onReadData(
    const folly::SocketAddress& localAddress,
    ReceivedUdpPacket&& udpPacket,
    const folly::SocketAddress& peerAddress) {
  if (closeState_ == CloseState::CLOSED) {
    // If we are closed, then we shouldn't process new network data.
    QUIC_STATS(
        statsCallback_, onPacketDropped, PacketDropReason::CLIENT_STATE_CLOSED);
    if (conn_->qLogger) {
      conn_->qLogger->addPacketDrop(0, kAlreadyClosed);
    }
    return {};
  }
  bool waitingForFirstPacket = !hasReceivedUdpPackets(*conn_);
  auto res = processUdpPacket(localAddress, std::move(udpPacket), peerAddress);
  if (!res.has_value()) {
    return res;
  }
  if (connSetupCallback_ && waitingForFirstPacket &&
      hasReceivedUdpPackets(*conn_)) {
    connSetupCallback_->onFirstPeerPacketProcessed();
  }
  if (!transportReadyNotified_ && hasWriteCipher()) {
    transportReadyNotified_ = true;
    connSetupCallback_->onTransportReady();

    // This is a new connection. Update QUIC Stats
    QUIC_STATS(statsCallback_, onNewConnection);
  }

  // Checking connSetupCallback_ because application will start to write data
  // in onTransportReady, if the write fails, QuicSocket can be closed
  // and connSetupCallback_ is set nullptr.
  if (connSetupCallback_ && !replaySafeNotified_ && conn_->oneRttWriteCipher) {
    replaySafeNotified_ = true;
    // We don't need this any more. Also unset it so that we don't allow random
    // middleboxes to shutdown our connection once we have crypto keys.
    auto result = socket_->setErrMessageCallback(nullptr);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
    connSetupCallback_->onReplaySafe();
    if (connSetupCallback_) {
      connSetupCallback_->onFullHandshakeDone();
    }
  }

  auto sendKnobsResult = maybeSendTransportKnobs();
  if (!sendKnobsResult.has_value()) {
    return sendKnobsResult;
  }

  auto issueCidResult = maybeIssueConnectionIds();
  if (!sendKnobsResult.has_value()) {
    return issueCidResult;
  }

  return {};
}

QuicSocketLite::WriteResult QuicClientTransportLite::writeBufMeta(
    StreamId /* id */,
    const BufferMeta& /* data */,
    bool /* eof */,
    ByteEventCallback* /* cb */) {
  return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
}

QuicSocketLite::WriteResult
QuicClientTransportLite::setDSRPacketizationRequestSender(
    StreamId /* id */,
    std::unique_ptr<DSRPacketizationRequestSender> /* sender */) {
  return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
}

quic::Expected<void, QuicError> QuicClientTransportLite::writeData() {
  QuicVersion version = conn_->version.value_or(*conn_->originalVersion);
  const ConnectionId& srcConnId = *conn_->clientConnectionId;
  const ConnectionId& destConnId = conn_->serverConnectionId.value_or(
      *clientConn_->initialDestinationConnectionId);

  if (closeState_ == CloseState::CLOSED) {
    auto rtt = clientConn_->lossState.srtt == 0us
        ? clientConn_->transportSettings.initialRtt
        : clientConn_->lossState.srtt;
    if (clientConn_->lastCloseSentTime &&
        Clock::now() - *clientConn_->lastCloseSentTime < rtt) {
      return {};
    }
    clientConn_->lastCloseSentTime = Clock::now();
    if (clientConn_->clientHandshakeLayer->getPhase() ==
            ClientHandshake::Phase::Established &&
        conn_->oneRttWriteCipher) {
      CHECK(conn_->oneRttWriteHeaderCipher);
      writeShortClose(
          *socket_,
          *conn_,
          destConnId,
          conn_->localConnectionError,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher);
    }
    if (conn_->handshakeWriteCipher) {
      CHECK(conn_->handshakeWriteHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId,
          destConnId,
          LongHeader::Types::Handshake,
          conn_->localConnectionError,
          *conn_->handshakeWriteCipher,
          *conn_->handshakeWriteHeaderCipher,
          version);
    }
    if (conn_->initialWriteCipher) {
      CHECK(conn_->initialHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId,
          destConnId,
          LongHeader::Types::Initial,
          conn_->localConnectionError,
          *conn_->initialWriteCipher,
          *conn_->initialHeaderCipher,
          version);
    }
    return {};
  }

  uint64_t packetLimit =
      (isConnectionPaced(*conn_)
           ? conn_->pacer->updateAndGetWriteBatchSize(Clock::now())
           : conn_->transportSettings.writeConnectionDataPacketsLimit);
  // At the end of this function, clear out any probe packets credit we didn't
  // use.
  SCOPE_EXIT {
    conn_->pendingEvents.numProbePackets = {};
  };
  if (conn_->initialWriteCipher) {
    const std::string& token = clientConn_->retryToken.empty()
        ? clientConn_->newToken
        : clientConn_->retryToken;
    auto result =
        handleInitialWriteDataCommon(srcConnId, destConnId, packetLimit, token);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
    packetLimit -= result->packetsWritten;
    if (!packetLimit && !conn_->pendingEvents.anyProbePackets()) {
      return {};
    }
  }
  if (conn_->handshakeWriteCipher) {
    auto result =
        handleHandshakeWriteDataCommon(srcConnId, destConnId, packetLimit);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
    packetLimit -= result->packetsWritten;
    if (!packetLimit && !conn_->pendingEvents.anyProbePackets()) {
      return {};
    }
  }
  if (clientConn_->zeroRttWriteCipher && !conn_->oneRttWriteCipher) {
    CHECK(clientConn_->zeroRttWriteHeaderCipher);
    auto result = writeZeroRttDataToSocket(
        *socket_,
        *conn_,
        srcConnId /* src */,
        destConnId /* dst */,
        *clientConn_->zeroRttWriteCipher,
        *clientConn_->zeroRttWriteHeaderCipher,
        version,
        packetLimit);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
    packetLimit -= *result;
  }
  if (!packetLimit && !conn_->pendingEvents.anyProbePackets()) {
    return {};
  }
  if (conn_->oneRttWriteCipher) {
    CHECK(clientConn_->oneRttWriteHeaderCipher);
    auto result = writeQuicDataExceptCryptoStreamToSocket(
        *socket_,
        *conn_,
        srcConnId,
        destConnId,
        *conn_->oneRttWriteCipher,
        *conn_->oneRttWriteHeaderCipher,
        version,
        packetLimit);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }

    auto pathValidationResult = writePathValidationDataForAlternatePaths(
        *socket_,
        *conn_,
        srcConnId /* src - not used since these are short header packets */,
        destConnId /* dst */,
        *conn_->oneRttWriteCipher,
        *conn_->oneRttWriteHeaderCipher,
        version,
        packetLimit); // TODO: jbeshay MIGRATION - is packet limit needed here?
    if (!pathValidationResult.has_value()) {
      return quic::make_unexpected(pathValidationResult.error());
    }
  }
  return maybeInitiateKeyUpdate(*conn_);
}

quic::Expected<void, QuicError>
QuicClientTransportLite::startCryptoHandshake() {
  auto self = this->shared_from_this();
  setIdleTimer();
  // We need to update the flow control settings every time we start a crypto
  // handshake. This is so that we can reset the flow control settings when
  // we go through version negotiation as well.
  updateFlowControlStateWithSettings(
      conn_->flowControlState, conn_->transportSettings);

  auto handshakeLayer = clientConn_->clientHandshakeLayer;
  auto& cryptoFactory = handshakeLayer->getCryptoFactory();

  auto version = conn_->originalVersion.value();
  auto initialWriteCipherResult = cryptoFactory.getClientInitialCipher(
      *clientConn_->initialDestinationConnectionId, version);
  if (!initialWriteCipherResult.has_value()) {
    return quic::make_unexpected(initialWriteCipherResult.error());
  }
  conn_->initialWriteCipher = std::move(initialWriteCipherResult.value());

  auto serverInitialCipherResult = cryptoFactory.getServerInitialCipher(
      *clientConn_->initialDestinationConnectionId, version);
  if (!serverInitialCipherResult.has_value()) {
    return quic::make_unexpected(serverInitialCipherResult.error());
  }
  conn_->readCodec->setInitialReadCipher(
      std::move(serverInitialCipherResult.value()));

  auto serverHeaderCipherResult = cryptoFactory.makeServerInitialHeaderCipher(
      *clientConn_->initialDestinationConnectionId, version);
  if (!serverHeaderCipherResult.has_value()) {
    return quic::make_unexpected(serverHeaderCipherResult.error());
  }
  conn_->readCodec->setInitialHeaderCipher(
      std::move(serverHeaderCipherResult.value()));

  auto clientHeaderCipherResult = cryptoFactory.makeClientInitialHeaderCipher(
      *clientConn_->initialDestinationConnectionId, version);
  if (!clientHeaderCipherResult.has_value()) {
    return quic::make_unexpected(clientHeaderCipherResult.error());
  }
  conn_->initialHeaderCipher = std::move(clientHeaderCipherResult.value());

  customTransportParameters_ = getSupportedExtTransportParams(*conn_);
  if (conn_->transportSettings.clientDirectEncapConfig) {
    auto maybeEncodedDirectEncapParam = encodeIntegerParameter(
        TransportParameterId::client_direct_encap,
        conn_->transportSettings.clientDirectEncapConfig.value());
    // The encoding should succeed because *clientDirectEncapConfig is a uint8_t
    CHECK(maybeEncodedDirectEncapParam)
        << "Failed to encode direct encap param";
    customTransportParameters_.push_back(*maybeEncodedDirectEncapParam);
  }

  auto paramsExtension = std::make_shared<ClientTransportParametersExtension>(
      conn_->originalVersion.value(),
      conn_->transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn_->transportSettings
          .advertisedInitialBidiLocalStreamFlowControlWindow,
      conn_->transportSettings
          .advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn_->transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn_->transportSettings.advertisedInitialMaxStreamsBidi,
      conn_->transportSettings.advertisedInitialMaxStreamsUni,
      conn_->transportSettings.idleTimeout,
      conn_->transportSettings.ackDelayExponent,
      conn_->transportSettings.maxRecvPacketSize,
      conn_->transportSettings.selfActiveConnectionIdLimit,
      conn_->clientConnectionId.value(),
      customTransportParameters_);
  conn_->transportParametersEncoded = true;
  auto connectResult =
      handshakeLayer->connect(hostname_, std::move(paramsExtension));
  if (!connectResult.has_value()) {
    return quic::make_unexpected(connectResult.error());
  }

  auto writeResult = writeSocketData();
  if (!writeResult.has_value()) {
    return quic::make_unexpected(writeResult.error());
  }

  if (!transportReadyNotified_ && clientConn_->zeroRttWriteCipher) {
    transportReadyNotified_ = true;
    runOnEvbAsync([](auto self) {
      auto clientPtr = dynamic_cast<QuicClientTransportLite*>(self.get());
      if (clientPtr->connSetupCallback_) {
        clientPtr->connSetupCallback_->onTransportReady();
      }
    });
  } else if (clientConn_->transportSettings.isPriming) {
    auto clientPtr = dynamic_cast<QuicClientTransportLite*>(self.get());
    if (clientPtr->connSetupCallback_) {
      clientPtr->connSetupCallback_->onConnectionSetupError(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          "Priming error: Zero-RTT not available"));
    }
  }

  return {};
}

bool QuicClientTransportLite::hasWriteCipher() const {
  return clientConn_->oneRttWriteCipher || clientConn_->zeroRttWriteCipher;
}

bool QuicClientTransportLite::hasZeroRttWriteCipher() const {
  return clientConn_->zeroRttWriteCipher != nullptr;
}

std::shared_ptr<QuicTransportBaseLite> QuicClientTransportLite::sharedGuard() {
  return shared_from_this();
}

std::shared_ptr<QuicClientTransportLite>
QuicClientTransportLite::sharedGuardClient() {
  return shared_from_this();
}

bool QuicClientTransportLite::isTLSResumed() const {
  return clientConn_->clientHandshakeLayer->isTLSResumed();
}

void QuicClientTransportLite::errMessage(
    [[maybe_unused]] const cmsghdr& cmsg) noexcept {
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  if ((cmsg.cmsg_level == SOL_IP && cmsg.cmsg_type == IP_RECVERR) ||
      (cmsg.cmsg_level == SOL_IPV6 && cmsg.cmsg_type == IPV6_RECVERR)) {
    // Time to make some assumptions. We assume the first socket == IPv6, if it
    // exists, and the second socket is IPv4. Then we basically do the same
    // thing we would have done if we'd gotten a write error on that socket.
    // If both sockets are not functional we close the connection.
    auto& happyEyeballsState = clientConn_->happyEyeballsState;
    if (!happyEyeballsState.finished) {
      if (cmsg.cmsg_level == SOL_IPV6 &&
          happyEyeballsState.shouldWriteToFirstSocket) {
        happyEyeballsState.shouldWriteToFirstSocket = false;
        socket_->pauseRead();
        if (happyEyeballsState.connAttemptDelayTimeout &&
            isTimeoutScheduled(happyEyeballsState.connAttemptDelayTimeout)) {
          happyEyeballsState.connAttemptDelayTimeout->timeoutExpired();
          cancelTimeout(happyEyeballsState.connAttemptDelayTimeout);
        }
      } else if (
          cmsg.cmsg_level == SOL_IP &&
          happyEyeballsState.shouldWriteToSecondSocket) {
        happyEyeballsState.shouldWriteToSecondSocket = false;
        happyEyeballsState.secondSocket->pauseRead();
      }
    }

    const struct sock_extended_err* serr =
        reinterpret_cast<const struct sock_extended_err*>(CMSG_DATA(&cmsg));
    auto errStr = quic::errnoStr(serr->ee_errno);
    if (!happyEyeballsState.shouldWriteToFirstSocket &&
        !happyEyeballsState.shouldWriteToSecondSocket) {
      asyncClose(QuicError(
          QuicErrorCode(LocalErrorCode::CONNECT_FAILED), std::move(errStr)));
    }
  }
#endif
}

void QuicClientTransportLite::onReadError(
    const folly::AsyncSocketException& ex) noexcept {
  if (closeState_ == CloseState::OPEN) {
    // closeNow will skip draining the socket. onReadError doesn't gets
    // triggered by retriable errors. If we are here, there is no point of
    // draining the socket.
    asyncClose(QuicError(
        QuicErrorCode(LocalErrorCode::CONNECTION_ABANDONED), ex.what()));
  }
}

void QuicClientTransportLite::getReadBuffer(
    void** /* buf */,
    size_t* /* len */) noexcept {
  folly::terminate_with<std::runtime_error>("getReadBuffer unsupported");
}

void QuicClientTransportLite::onDataAvailable(
    const folly::SocketAddress& /* server */,
    size_t /* len */,
    bool /* truncated */,
    OnDataAvailableParams /* params */) noexcept {
  folly::terminate_with<std::runtime_error>("onDataAvailable unsupported");
}

bool QuicClientTransportLite::shouldOnlyNotify() {
  return true;
}

quic::Expected<void, QuicError> QuicClientTransportLite::recvMsg(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    int numPackets,
    NetworkData& networkData,
    Optional<folly::SocketAddress>& server,
    size_t& totalData) {
  for (int packetNum = 0; packetNum < numPackets; ++packetNum) {
    // We create 1 buffer per packet so that it is not shared, this enables
    // us to decrypt in place.
    BufPtr readBuffer = BufHelpers::createCombined(readBufferSize);
    struct iovec vec;
    vec.iov_base = readBuffer->writableData();
    vec.iov_len = readBufferSize;

    sockaddr* rawAddr{nullptr};

    struct sockaddr_storage addrStorage{};

    if (!server) {
      rawAddr = reinterpret_cast<sockaddr*>(&addrStorage);
      auto familyResult = sock.getLocalAddressFamily();
      if (!familyResult.has_value()) {
        return quic::make_unexpected(QuicError(
            QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
            fmt::format(
                "Failed to get address family: {}",
                familyResult.error().message)));
      }
      rawAddr->sa_family = familyResult.value();
    }

    int flags = 0;
    QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams params;

    struct msghdr msg{};

    msg.msg_name = rawAddr;
    msg.msg_namelen = rawAddr ? kAddrLen : 0;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    bool useGRO = false;
    bool useTs = false;
    bool recvTos = false;

    auto groResult = sock.getGRO();
    if (!groResult.has_value()) {
      // Non-fatal, just log and continue
      LOG(WARNING) << "Failed to get GRO status: " << groResult.error().message;
    } else {
      useGRO = groResult.value() > 0;
    }

    auto tsResult = sock.getTimestamping();
    if (!tsResult.has_value()) {
      // Non-fatal, just log and continue
      LOG(WARNING) << "Failed to get timestamping status: "
                   << tsResult.error().message;
    } else {
      useTs = tsResult.value() > 0;
    }

    auto tosResult = sock.getRecvTos();
    if (!tosResult.has_value()) {
      // Non-fatal, just log and continue
      LOG(WARNING) << "Failed to get TOS status: " << tosResult.error().message;
    } else {
      recvTos = tosResult.value();
    }

    bool checkCmsgs = useGRO || useTs || recvTos;
    char control
        [QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams::kCmsgSpace] =
            {};

    if (checkCmsgs) {
      msg.msg_control = control;
      msg.msg_controllen = sizeof(control);

      // we need to consider MSG_TRUNC too
      flags |= MSG_TRUNC;
    }
#endif

    ssize_t ret = sock.recvmsg(&msg, flags);
    if (ret < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // If we got a retriable error, let us continue.
        if (conn_->loopDetectorCallback) {
          conn_->readDebugState.noReadReason = NoReadReason::RETRIABLE_ERROR;
        }
        break;
      }
      // If we got a non-retriable error, we might have received
      // a packet that we could process, however let's just quit early.
      sock.pauseRead();
      if (conn_->loopDetectorCallback) {
        conn_->readDebugState.noReadReason = NoReadReason::NONRETRIABLE_ERROR;
      }
      return quic::make_unexpected(QuicError(
          QuicErrorCode(LocalErrorCode::CONNECTION_ABANDONED),
          fmt::format(
              "recvmsg() failed, errno={} {}", errno, quic::errnoStr(errno))));
    } else if (ret == 0) {
      break;
    }
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (checkCmsgs) {
      QuicAsyncUDPSocket::fromMsg(params, msg);

      // truncated
      if ((size_t)ret > readBufferSize) {
        ret = readBufferSize;
        if (params.gro > 0) {
          ret = ret - ret % params.gro;
        }
      }
    }
#endif
    ReceivedUdpPacket::Timings timings;
    if (params.ts.has_value()) {
      timings.maybeSoftwareTs =
          QuicAsyncUDPSocket::convertToSocketTimestampExt(*params.ts);
    }

    size_t bytesRead = size_t(ret);
    totalData += bytesRead;
    if (!server) {
      server = folly::SocketAddress();
      server->setFromSockaddr(rawAddr, kAddrLen);
    }
    VLOG(10) << "Got data from socket peer=" << *server << " len=" << bytesRead;
    readBuffer->append(bytesRead);
    if (params.gro > 0) {
      size_t len = bytesRead;
      size_t remaining = len;
      size_t offset = 0;
      size_t totalNumPackets = networkData.getPackets().size() +
          ((len + params.gro - 1) / params.gro);
      networkData.reserve(totalNumPackets);
      while (remaining) {
        if (static_cast<int>(remaining) > params.gro) {
          auto tmp = readBuffer->cloneOne();
          // start at offset
          tmp->trimStart(offset);
          // the actual len is len - offset now
          // leave gro bytes
          tmp->trimEnd(len - offset - params.gro);
          DCHECK_EQ(tmp->length(), params.gro);

          offset += params.gro;
          remaining -= params.gro;
          networkData.addPacket(
              ReceivedUdpPacket(std::move(tmp), timings, params.tos));
        } else {
          // do not clone the last packet
          // start at offset, use all the remaining data
          readBuffer->trimStart(offset);
          DCHECK_EQ(readBuffer->length(), remaining);
          remaining = 0;
          networkData.addPacket(
              ReceivedUdpPacket(std::move(readBuffer), timings, params.tos));
        }
      }
    } else {
      networkData.addPacket(
          ReceivedUdpPacket(std::move(readBuffer), timings, params.tos));
    }
    maybeQlogDatagram(bytesRead);
  }
  trackDatagramsReceived(
      networkData.getPackets().size(), networkData.getTotalData());

  return {};
}

quic::Expected<void, QuicError> QuicClientTransportLite::recvMmsg(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets,
    NetworkData& networkData,
    Optional<folly::SocketAddress>& server,
    size_t& totalData) {
  auto& msgs = recvmmsgStorage_.msgs;
  int flags = 0;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  auto groResult = sock.getGRO();
  if (!groResult.has_value()) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "Failed to get GRO status: {}", groResult.error().message)));
  }
  bool useGRO = groResult.value() > 0;

  auto tsResult = sock.getTimestamping();
  if (!tsResult.has_value()) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "Failed to get timestamping status: {}",
            tsResult.error().message)));
  }
  bool useTs = tsResult.value() > 0;

  auto tosResult = sock.getRecvTos();
  if (!tosResult.has_value()) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "Failed to get TOS status: {}", tosResult.error().message)));
  }
  bool recvTos = tosResult.value();

  bool checkCmsgs = useGRO || useTs || recvTos;
  std::vector<std::array<
      char,
      QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams::kCmsgSpace>>
      controlVec(checkCmsgs ? numPackets : 0);

  // we need to consider MSG_TRUNC too
  if (useGRO) {
    flags |= MSG_TRUNC;
  }
#endif
  for (uint16_t i = 0; i < numPackets; ++i) {
    auto& addr = recvmmsgStorage_.impl_[i].addr;
    auto& readBuffer = recvmmsgStorage_.impl_[i].readBuffer;
    auto& iovec = recvmmsgStorage_.impl_[i].iovec;
    struct msghdr* msg = &msgs[i].msg_hdr;

    if (!readBuffer) {
      readBuffer = BufHelpers::createCombined(readBufferSize);
      iovec.iov_base = readBuffer->writableData();
      iovec.iov_len = readBufferSize;
      msg->msg_iov = &iovec;
      msg->msg_iovlen = 1;
    }
    CHECK(readBuffer != nullptr);

    auto* rawAddr = reinterpret_cast<sockaddr*>(&addr);
    auto addrResult = sock.address();
    if (!addrResult.has_value()) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          fmt::format(
              "Failed to get socket address: {}", addrResult.error().message)));
    }
    rawAddr->sa_family = addrResult.value().getFamily();
    msg->msg_name = rawAddr;
    msg->msg_namelen = kAddrLen;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (checkCmsgs) {
      ::memset(controlVec[i].data(), 0, controlVec[i].size());
      msg->msg_control = controlVec[i].data();
      msg->msg_controllen = controlVec[i].size();
    }
#endif
  }

  int numMsgsRecvd = sock.recvmmsg(msgs.data(), numPackets, flags, nullptr);
  if (numMsgsRecvd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Exit, socket will notify us again when socket is readable.
      if (conn_->loopDetectorCallback) {
        conn_->readDebugState.noReadReason = NoReadReason::RETRIABLE_ERROR;
      }
      return {};
    }
    // If we got a non-retriable error, we might have received
    // a packet that we could process, however let's just quit early.
    sock.pauseRead();
    if (conn_->loopDetectorCallback) {
      conn_->readDebugState.noReadReason = NoReadReason::NONRETRIABLE_ERROR;
    }
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        fmt::format(
            "recvmmsg() failed, errno={} {}", errno, quic::errnoStr(errno))));
  }

  CHECK_LE(numMsgsRecvd, numPackets);
  for (uint16_t i = 0; i < static_cast<uint16_t>(numMsgsRecvd); ++i) {
    auto& addr = recvmmsgStorage_.impl_[i].addr;
    auto& readBuffer = recvmmsgStorage_.impl_[i].readBuffer;
    auto& msg = msgs[i];

    size_t bytesRead = msg.msg_len;
    if (bytesRead == 0) {
      // Empty datagram, this is probably garbage matching our tuple, we
      // should ignore such datagrams.
      continue;
    }
    QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams params;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (checkCmsgs) {
      QuicAsyncUDPSocket::fromMsg(params, msg.msg_hdr);

      // truncated
      if (bytesRead > readBufferSize) {
        bytesRead = readBufferSize;
        if (params.gro > 0) {
          bytesRead = bytesRead - bytesRead % params.gro;
        }
      }
    }
#endif
    totalData += bytesRead;

    if (!server) {
      server.emplace(folly::SocketAddress());
      auto* rawAddr = reinterpret_cast<sockaddr*>(&addr);
      server->setFromSockaddr(rawAddr, kAddrLen);
    }

    ReceivedUdpPacket::Timings timings;
    if (params.ts.has_value()) {
      timings.maybeSoftwareTs =
          QuicAsyncUDPSocket::convertToSocketTimestampExt(*params.ts);
    }

    VLOG(10) << "Got data from socket peer=" << *server << " len=" << bytesRead;
    readBuffer->append(bytesRead);
    if (params.gro > 0) {
      size_t len = bytesRead;
      size_t remaining = len;
      size_t offset = 0;
      size_t totalNumPackets = networkData.getPackets().size() +
          ((len + params.gro - 1) / params.gro);
      networkData.reserve(totalNumPackets);
      while (remaining) {
        if (static_cast<int>(remaining) > params.gro) {
          auto tmp = readBuffer->cloneOne();
          // start at offset
          tmp->trimStart(offset);
          // the actual len is len - offset now
          // leave gro bytes
          tmp->trimEnd(len - offset - params.gro);
          DCHECK_EQ(tmp->length(), params.gro);

          offset += params.gro;
          remaining -= params.gro;
          networkData.addPacket(
              ReceivedUdpPacket(std::move(tmp), timings, params.tos));
        } else {
          // do not clone the last packet
          // start at offset, use all the remaining data
          readBuffer->trimStart(offset);
          DCHECK_EQ(readBuffer->length(), remaining);
          remaining = 0;
          networkData.addPacket(
              ReceivedUdpPacket(std::move(readBuffer), timings, params.tos));
        }
      }
    } else {
      networkData.addPacket(
          ReceivedUdpPacket(std::move(readBuffer), timings, params.tos));
    }

    maybeQlogDatagram(bytesRead);
  }
  trackDatagramsReceived(
      networkData.getPackets().size(), networkData.getTotalData());

  return {};
}

quic::Expected<void, QuicError> QuicClientTransportLite::processPackets(
    const Optional<folly::SocketAddress>& localAddress,
    NetworkData&& networkData,
    const Optional<folly::SocketAddress>& peerAddress) {
  if (networkData.getPackets().empty()) {
    // recvMmsg and recvMsg might have already set the reason and counter
    if (conn_->loopDetectorCallback) {
      if (conn_->readDebugState.noReadReason == NoReadReason::READ_OK) {
        conn_->readDebugState.noReadReason = NoReadReason::EMPTY_DATA;
      }
      if (conn_->readDebugState.noReadReason != NoReadReason::READ_OK) {
        conn_->loopDetectorCallback->onSuspiciousReadLoops(
            ++conn_->readDebugState.loopCount,
            conn_->readDebugState.noReadReason);
      }
    }
    return {};
  }
  DCHECK(localAddress.has_value());
  DCHECK(peerAddress.has_value());
  // TODO: we can get better receive time accuracy than this, with
  // SO_TIMESTAMP or SIOCGSTAMP.
  auto packetReceiveTime = Clock::now();
  networkData.setReceiveTimePoint(packetReceiveTime);

  onNetworkData(*localAddress, std::move(networkData), *peerAddress);
  return {};
}

quic::Expected<void, QuicError>
QuicClientTransportLite::readWithRecvmsgSinglePacketLoop(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize) {
  size_t totalData = 0;
  Optional<folly::SocketAddress> server;
  for (size_t i = 0; i < conn_->transportSettings.maxRecvBatchSize; i++) {
    auto networkDataSinglePacket = NetworkData();
    networkDataSinglePacket.reserve(1);

    auto recvResult = recvMsg(
        sock,
        readBufferSize,
        1 /* numPackets */,
        networkDataSinglePacket,
        server,
        totalData);

    if (!recvResult.has_value()) {
      return recvResult;
    }

    if (!socket_) {
      // Socket has been closed.
      return {};
    }

    if (networkDataSinglePacket.getPackets().size() == 0) {
      break;
    }

    auto localAddressRes = sock.address();
    if (localAddressRes.hasError()) {
      return quic::make_unexpected(localAddressRes.error());
    }

    auto processResult = processPackets(
        localAddressRes.value(), std::move(networkDataSinglePacket), server);
    if (!processResult.has_value()) {
      return processResult;
    }

    if (!socket_) {
      // Socket has been closed.
      return {};
    }
  }

  // Call callbacks/updates manually because processPackets()/onNetworkData()
  // will not schedule it when transportSettings.networkDataPerSocketRead is on.
  processCallbacksAfterNetworkData();
  checkForClosedStream();
  updateReadLooper();
  updateWriteLooper(true);

  return {};
}

void QuicClientTransportLite::onNotifyDataAvailable(
    QuicAsyncUDPSocket& sock) noexcept {
  auto self = this->shared_from_this();
  CHECK(conn_) << "trying to receive packets without a connection";
  auto readBufferSize =
      conn_->transportSettings.maxRecvPacketSize * numGROBuffers_;

  const size_t readAllocSize =
      conn_->transportSettings.readCoalescingSize > kDefaultUDPSendPacketLen
      ? conn_->transportSettings.readCoalescingSize
      : readBufferSize;

  auto result = readWithRecvmsgSinglePacketLoop(sock, readAllocSize);
  if (!result.has_value()) {
    asyncClose(result.error());
  }
}

void QuicClientTransportLite::
    happyEyeballsConnAttemptDelayTimeoutExpired() noexcept {
  // Declare 0-RTT data as lost so that they will be retransmitted over the
  // second socket.
  happyEyeballsStartSecondSocket(clientConn_->happyEyeballsState);
  // If this gets called from the write path then we haven't added the packets
  // to the outstanding packet list yet.
  runOnEvbAsync([&](auto) {
    auto result = markZeroRttPacketsLost(*conn_, markPacketLoss);
    LOG_IF(ERROR, !result.has_value())
        << "Failed to mark 0-RTT packets as lost.";
  });
}

void QuicClientTransportLite::start(
    ConnectionSetupCallback* connSetupCb,
    ConnectionCallback* connCb) {
  if (happyEyeballsEnabled_) {
    // TODO Supply v4 delay amount from somewhere when we want to tune this
    startHappyEyeballs(
        *clientConn_,
        evb_.get(),
        happyEyeballsCachedFamily_,
        happyEyeballsConnAttemptDelayTimeout_,
        happyEyeballsCachedFamily_ == AF_UNSPEC
            ? kHappyEyeballsV4Delay
            : kHappyEyeballsConnAttemptDelayWithCache,
        this,
        this,
        socketOptions_);
  }

  CHECK(conn_->peerAddress.isInitialized());

  if (conn_->qLogger) {
    conn_->qLogger->addTransportStateUpdate(kStart);
  }

  setConnectionSetupCallback(connSetupCb);
  setConnectionCallback(connCb);

  clientConn_->pendingOneRttData.reserve(
      conn_->transportSettings.maxPacketsToBuffer);

  auto socketResult = happyEyeballsSetUpSocket(
      *socket_,
      conn_->localAddress,
      conn_->peerAddress,
      conn_->transportSettings,
      conn_->socketTos.value,
      this,
      this,
      socketOptions_);
  if (!socketResult.has_value()) {
    asyncClose(socketResult.error());
    return;
  }

  auto adjustResult = adjustGROBuffers();
  if (!adjustResult.has_value()) {
    asyncClose(adjustResult.error());
    return;
  }

  CHECK(socket_->address().has_value());
  auto addPathRes = clientConn_->pathManager->addValidatedPath(
      *socket_->address(), conn_->peerAddress);
  if (addPathRes.hasError()) {
    asyncClose(addPathRes.error());
    return;
  }
  conn_->currentPathId = addPathRes.value();

  auto handshakeResult = startCryptoHandshake();
  if (!handshakeResult.has_value()) {
    asyncClose(handshakeResult.error());
    return;
  }
}

void QuicClientTransportLite::addNewPeerAddress(
    folly::SocketAddress peerAddress) {
  CHECK(peerAddress.isInitialized());

  if (peerAddress.getIPAddress().isZero()) {
    // Using the wildcard address as the peer address is a special case which is
    // interpreted as pointing to localhost since the address cannot appear on
    // the wire. We update the peer address here to keep the connection
    // state consistent with what will actually be in the IP headers.
    peerAddress = folly::SocketAddress(
        peerAddress.getFamily() == AF_INET6 ? folly::IPAddress("::1")
                                            : folly::IPAddress("127.0.0.1"),
        peerAddress.getPort());
  }

  if (happyEyeballsEnabled_) {
    conn_->udpSendPacketLen = std::min(
        conn_->udpSendPacketLen,
        (peerAddress.getFamily() == AF_INET6 ? kDefaultV6UDPSendPacketLen
                                             : kDefaultV4UDPSendPacketLen));
    happyEyeballsAddPeerAddress(*clientConn_, peerAddress);
    return;
  }

  conn_->udpSendPacketLen = peerAddress.getFamily() == AF_INET6
      ? kDefaultV6UDPSendPacketLen
      : kDefaultV4UDPSendPacketLen;
  conn_->originalPeerAddress = peerAddress;
  conn_->peerAddress = std::move(peerAddress);
}

void QuicClientTransportLite::setLocalAddress(
    folly::SocketAddress localAddress) {
  CHECK(localAddress.isInitialized());
  conn_->localAddress = std::move(localAddress);
}

void QuicClientTransportLite::setHappyEyeballsEnabled(
    bool happyEyeballsEnabled) {
  happyEyeballsEnabled_ = happyEyeballsEnabled;
}

void QuicClientTransportLite::setHappyEyeballsCachedFamily(
    sa_family_t cachedFamily) {
  happyEyeballsCachedFamily_ = cachedFamily;
}

void QuicClientTransportLite::addNewSocket(
    std::unique_ptr<QuicAsyncUDPSocket> socket) {
  happyEyeballsAddSocket(*clientConn_, std::move(socket));
}

void QuicClientTransportLite::setHostname(const std::string& hostname) {
  hostname_ = hostname;
}

void QuicClientTransportLite::setSelfOwning() {
  selfOwning_ = shared_from_this();
}

quic::Expected<void, QuicError> QuicClientTransportLite::adjustGROBuffers() {
  if (socket_ && conn_) {
    if (conn_->transportSettings.numGROBuffers_ > kDefaultNumGROBuffers) {
      auto setResult = socket_->setGRO(true);
      if (!setResult.has_value()) {
        // Not a fatal error, just log and continue with default buffers
        LOG(WARNING) << "Failed to enable GRO: " << setResult.error().message;
        return {};
      }

      auto groResult = socket_->getGRO();
      if (!groResult.has_value()) {
        // Not a fatal error, just log and continue with default buffers
        LOG(WARNING) << "Failed to get GRO status: "
                     << groResult.error().message;
        return {};
      }

      if (groResult.value() > 0) {
        numGROBuffers_ =
            (conn_->transportSettings.numGROBuffers_ < kMaxNumGROBuffers)
            ? conn_->transportSettings.numGROBuffers_
            : kMaxNumGROBuffers;
      }
    }
  }
  return {};
}

void QuicClientTransportLite::closeTransport() {
  cancelTimeout(&happyEyeballsConnAttemptDelayTimeout_);
}

void QuicClientTransportLite::unbindConnection() {
  selfOwning_ = nullptr;
}

void QuicClientTransportLite::setSupportedVersions(
    const std::vector<QuicVersion>& versions) {
  auto version = versions.at(0);
  conn_->originalVersion = version;
  auto params = conn_->readCodec->getCodecParameters();
  params.version = conn_->originalVersion.value();
  conn_->readCodec->setCodecParameters(params);
}

void QuicClientTransportLite::runOnEvbAsync(
    std::function<void(std::shared_ptr<QuicClientTransportLite>)> func) {
  auto evb = getEventBase();
  evb->runInLoop(
      [self = sharedGuardClient(), func = std::move(func), evb]() mutable {
        if (self->getEventBase() != evb) {
          // The eventbase changed between scheduling the loop and invoking
          // the callback, ignore this
          return;
        }
        func(std::move(self));
      },
      true);
}

void QuicClientTransportLite::asyncClose(QuicError error) {
  runOnEvbAsync([error = std::move(error)](auto self) {
    auto clientPtr = static_cast<QuicClientTransportLite*>(self.get());
    clientPtr->closeImpl(std::move(error), false, false);
  });
}

void QuicClientTransportLite::onNetworkSwitch(
    std::unique_ptr<QuicAsyncUDPSocket> newSock) {
  // Start a probe and immediately migrate to the new path.
  auto probePathId = startPathProbe(std::move(newSock));
  if (probePathId.hasError()) {
    VLOG(4) << "Failed to start path probe: " << probePathId.error();
    asyncClose(probePathId.error());
    return;
  }

  auto migrateResult = migrateConnection(probePathId.value());
  if (migrateResult.hasError()) {
    VLOG(4) << "Failed to migrate connection: " << migrateResult.error();
    asyncClose(migrateResult.error());
    return;
  }
}

quic::Expected<PathIdType, QuicError> QuicClientTransportLite::startPathProbe(
    std::unique_ptr<QuicAsyncUDPSocket> probeSocket,
    QuicPathManager::PathValidationCallback* probeResultCallback) {
  if (!clientConn_->peerSupportsActiveConnectionMigration) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::INTERNAL_ERROR,
        "Peer does not support active connection migration"));
  }
  if (!conn_->oneRttWriteCipher) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::INTERNAL_ERROR,
        "Cannot initiate probe before handshake is complete"));
  }

  if (!socket_) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::INTERNAL_ERROR,
        "Cannot initiate probe without a primary socket"));
  }

  if (!probeSocket) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::INTERNAL_ERROR,
        "Cannot initiate probe without a socket"));
  }

  if (!probeSocket->isBound() || probeSocket->address().hasError()) {
    return quic::make_unexpected(
        QuicError(LocalErrorCode::INTERNAL_ERROR, "Probe socket not bound"));
  }

  if (probeSocket->address()->getFamily() != socket_->address()->getFamily()) {
    return quic::make_unexpected(QuicError(
        LocalErrorCode::INTERNAL_ERROR,
        "Probe socket address family mismatch"));
  }

  if (auto res = probeSocket->setErrMessageCallback(nullptr); res.hasError()) {
    return quic::make_unexpected(res.error());
  }

  // Set up the socket and start reading from it
  auto setupResult = happyEyeballsSetUpSocket(
      *probeSocket,
      std::nullopt, // Empty local address. The socket
                    // is already bound.
      conn_->peerAddress,
      conn_->transportSettings,
      conn_->socketTos.value,
      this,
      this,
      socketOptions_);
  if (!setupResult.has_value()) {
    return quic::make_unexpected(setupResult.error());
  }

  if (auto res = probeSocket->setAdditionalCmsgsFunc(
          [&]() { return getAdditionalCmsgsForAsyncUDPSocket(); });
      res.hasError()) {
    return quic::make_unexpected(res.error());
  }

  auto localAddress = probeSocket->address().value();
  // Add the path
  auto pathIdRes = conn_->pathManager->addPath(
      localAddress, conn_->peerAddress, std::move(probeSocket));
  if (pathIdRes.hasError()) {
    return quic::make_unexpected(pathIdRes.error());
  }
  auto pathId = pathIdRes.value();

  // Set the callback
  if (probeResultCallback) {
    pathValidationCallbacks_[pathId] = probeResultCallback;
  }

  // Schedule a path challenge for the new path
  auto pathChallengeDataResult =
      conn_->pathManager->getNewPathChallengeData(pathId);
  if (pathChallengeDataResult.hasError()) {
    return quic::make_unexpected(pathChallengeDataResult.error());
  }
  conn_->pendingEvents.pathChallenges.emplace(
      pathId, PathChallengeFrame(pathChallengeDataResult.value()));

  // Assign it a new connection id to use. This is done as the last step to
  // avoid assigning a connection id then returning an error leaving a
  // connection id mistakenly marked as in use.
  auto connIdRes = conn_->pathManager->assignDestinationCidForPath(pathId);
  if (connIdRes.hasError()) {
    return quic::make_unexpected(connIdRes.error());
  }

  // Schedule a write.
  updateWriteLooper(true);

  return pathId;
}

quic::Expected<void, QuicError> QuicClientTransportLite::removePath(
    PathIdType pathId) {
  return conn_->pathManager->removePath(pathId);
}

quic::Expected<void, QuicError> QuicClientTransportLite::migrateConnection(
    PathIdType pathId) {
  auto oldPathId = conn_->currentPathId;

  auto switchPathResult = conn_->pathManager->switchCurrentPath(pathId);
  if (switchPathResult.hasError()) {
    return quic::make_unexpected(switchPathResult.error());
  }

  auto newSocket = std::move(switchPathResult.value());
  if (newSocket) {
    // The new path has an associated socket.

    // Cache the socket for the old path in case we need to switch to it later.
    // The oldPathId is no longer the current path. So this cannot fail.
    auto addSocketResult =
        conn_->pathManager->addSocketToPath(oldPathId, std::move(socket_));
    CHECK(!addSocketResult.hasError()) << addSocketResult.error();

    socket_ = std::move(newSocket);
  }

  auto adjustResult = adjustGROBuffers();
  if (adjustResult.hasError()) {
    return quic::make_unexpected(adjustResult.error());
  }

  if (conn_->qLogger) {
    conn_->qLogger->addConnectionMigrationUpdate(true);
  }

  // Keep the old path for some time so we can read any packets that might
  // already be inflight
  auto removePathLambda = [conn = shared_from_this(), oldPathId]() {
    auto removePathRes = conn->clientConn_->pathManager->removePath(oldPathId);
    if (removePathRes.hasError()) {
      LOG(WARNING) << "Failed to remove old path after migration. "
                   << removePathRes.error();
    }
  };
  auto delay = kClientTimeToKeepOldPathAfterMigration *
      std::chrono::ceil<std::chrono::milliseconds>(conn_->lossState.srtt)
          .count();
  evb_->runAfterDelay(removePathLambda, delay);

  // Write something to trigger the migration.
  conn_->pendingEvents.sendPing = true;
  updateWriteLooper(true);

  return {};
}

void QuicClientTransportLite::setTransportStatsCallback(
    std::shared_ptr<QuicTransportStatsCallback> statsCallback) noexcept {
  CHECK(conn_);
  statsCallback_ = std::move(statsCallback);
  if (statsCallback_) {
    conn_->statsCallback = statsCallback_.get();
    conn_->readCodec->setConnectionStatsCallback(statsCallback_.get());
  } else {
    conn_->statsCallback = nullptr;
  }
}

void QuicClientTransportLite::maybeQlogDatagram(size_t len) {
  if (conn_->qLogger) {
    conn_->qLogger->addDatagramReceived(len);
  }
}

void QuicClientTransportLite::trackDatagramsReceived(
    uint32_t totalPackets,
    uint32_t totalPacketLen) {
  QUIC_STATS(statsCallback_, onPacketsReceived, totalPackets);
  QUIC_STATS(statsCallback_, onRead, totalPacketLen);
}

quic::Expected<void, QuicError>
QuicClientTransportLite::maybeSendTransportKnobs() {
  if (!transportKnobsSent_ && hasWriteCipher()) {
    for (const auto& knob : conn_->transportSettings.knobs) {
      auto res =
          setKnob(knob.space, knob.id, BufHelpers::copyBuffer(knob.blob));
      if (!res.has_value()) {
        if (res.error() != LocalErrorCode::KNOB_FRAME_UNSUPPORTED) {
          LOG(ERROR) << "Unexpected error while sending knob frames";
          return quic::make_unexpected(QuicError(
              QuicErrorCode(res.error()),
              "Unexpected error while sending knob frames"));
        }
        // No point in keep trying if transport does not support knob frame
        break;
      }
    }
    transportKnobsSent_ = true;
  }
  return {};
}

quic::Expected<void, QuicError>
QuicClientTransportLite::maybeIssueConnectionIds() {
  const uint64_t maximumIdsToIssue = maximumConnectionIdsToIssue(*conn_);
  if (conn_->clientConnectionId->size() > 0 && conn_->oneRttWriteCipher) {
    // Make sure size of selfConnectionIds is not larger than maximumIdsToIssue
    for (size_t i = conn_->selfConnectionIds.size(); i < maximumIdsToIssue;
         ++i) {
      auto newConnIdRes =
          ConnectionId::createRandom(conn_->clientConnectionId->size());
      if (newConnIdRes.hasError()) {
        return quic::make_unexpected(newConnIdRes.error());
      }

      auto newConnIdData = ConnectionIdData{
          *newConnIdRes, conn_->nextSelfConnectionIdSequence++};
      newConnIdData.token = StatelessResetToken();
      folly::Random::secureRandom(
          newConnIdData.token->data(), newConnIdData.token->size());

      conn_->selfConnectionIds.push_back(newConnIdData);

      NewConnectionIdFrame frame(
          newConnIdData.sequenceNumber,
          0,
          newConnIdData.connId,
          *newConnIdData.token);

      // Always send connection ids on the primary path. We'll make sure they
      // are available to the peer before it needs them. This is easier than
      // having to bundle them with probes.
      sendSimpleFrame(*conn_, std::move(frame));
    }
  }
  return {};
}

Optional<std::vector<TransportParameter>>
QuicClientTransportLite::getPeerTransportParams() const {
  if (clientConn_ && clientConn_->clientHandshakeLayer) {
    auto maybeParams =
        clientConn_->clientHandshakeLayer->getServerTransportParams();
    if (maybeParams) {
      return maybeParams->parameters;
    }
  }
  return std::nullopt;
}

void QuicClientTransportLite::setCongestionControl(CongestionControlType type) {
  if (!conn_->congestionControllerFactory) {
    // If you are hitting this, update your application to call
    // setCongestionControllerFactory() on the transport and share one factory
    // for all transports.
    conn_->congestionControllerFactory =
        std::make_shared<DefaultCongestionControllerFactory>();
    LOG(WARNING)
        << "A congestion controller factory is not set. Using a default per-transport instance.";
  }
  QuicTransportBaseLite::setCongestionControl(type);
}

void QuicClientTransportLite::RecvmmsgStorage::resize(size_t numPackets) {
  if (msgs.size() != numPackets) {
    msgs.resize(numPackets);
    impl_.resize(numPackets);
  }
}

uint64_t QuicClientTransportLite::getNumAckFramesSent() const {
  return conn_->numAckFramesSent;
}

uint64_t QuicClientTransportLite::getNumFlowControlFramesSent() const {
  return conn_->numWindowUpdateFramesSent;
}

uint64_t QuicClientTransportLite::getNumPingFramesSent() const {
  return conn_->numPingFramesSent;
}

uint64_t QuicClientTransportLite::getEagainOrEwouldblockCount() const {
  return conn_->eagainOrEwouldblockCount;
}

uint64_t QuicClientTransportLite::getEnobufsCount() const {
  return conn_->enobufsCount;
}

uint64_t QuicClientTransportLite::getPtoCount() const {
  return conn_->lossState.ptoCount;
}

uint64_t QuicClientTransportLite::getPacketsSentCount() const {
  return conn_->lossState.totalPacketsSent;
}

bool QuicClientTransportLite::canRead() const {
  return socket_ && !socket_->isReadPaused();
}

std::optional<int32_t> QuicClientTransportLite::getHandshakeStatus() const {
  return clientConn_->clientHandshakeLayer->getHandshakeStatus();
}

size_t QuicClientTransportLite::getInitialReadBufferSize() const {
  return clientConn_->clientHandshakeLayer->getInitialReadBufferSize();
}

size_t QuicClientTransportLite::getHandshakeReadBufferSize() const {
  return clientConn_->clientHandshakeLayer->getHandshakeReadBufferSize();
}

size_t QuicClientTransportLite::getAppDataReadBufferSize() const {
  return clientConn_->clientHandshakeLayer->getAppDataReadBufferSize();
}

EncryptionLevel QuicClientTransportLite::getReadEncryptionLevel() const {
  return clientConn_->clientHandshakeLayer->getReadRecordLayerEncryptionLevel();
}

bool QuicClientTransportLite::waitingForHandshakeData() const {
  return clientConn_->clientHandshakeLayer->waitingForData();
}

const std::shared_ptr<const folly::AsyncTransportCertificate>
QuicClientTransportLite::getPeerCertificate() const {
  const auto clientHandshakeLayer = clientConn_->clientHandshakeLayer;
  if (clientHandshakeLayer) {
    return clientHandshakeLayer->getPeerCertificate();
  }
  return nullptr;
}

Optional<Handshake::TLSSummary> QuicClientTransportLite::getTLSSummary() const {
  const auto clientHandshakeLayer = clientConn_->clientHandshakeLayer;
  if (clientHandshakeLayer) {
    return clientHandshakeLayer->getTLSSummary();
  }
  return std::nullopt;
}

void QuicClientTransportLite::onPathValidationResult(const PathInfo& pathInfo) {
  std::string statusStr =
      (pathInfo.status == PathStatus::Validated) ? "VALID" : "NOT VALID";
  VLOG(4) << "onPathValidationResult: pathId=" << pathInfo.id
          << ", status=" << statusStr;
  if (auto it = pathValidationCallbacks_.find(pathInfo.id);
      it != pathValidationCallbacks_.end() && it->second) {
    it->second->onPathValidationResult(pathInfo);
    // Remove the callback
    pathValidationCallbacks_.erase(pathInfo.id);
  }

  if (pathInfo.id != conn_->currentPathId) {
    // The upper layer should decide to migrate or not in the callback. After
    // the callback, if this path is not the current one, remove it to avoid
    // dangling paths/sockets.
    evb_->runInLoop(
        [&, pathId = pathInfo.id]() {
          if (conn_->currentPathId == pathId) {
            return;
          }
          auto removeRes = conn_->pathManager->removePath(pathId);
          if (removeRes.hasError()) {
            LOG(WARNING) << "Failed to remove path " << pathId
                         << " after validation: " << removeRes.error();
          }
        },
        /*thisIteration=*/true);
  } else if (pathInfo.status != PathStatus::Validated) {
    // This is the current path and it has failed validation, we need to close
    // the connection.
    asyncClose(QuicError(
        QuicErrorCode(LocalErrorCode::MIGRATION_FAILED),
        "Path validation failed for current path"));
  }
}

} // namespace quic

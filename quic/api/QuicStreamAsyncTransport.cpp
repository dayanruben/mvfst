/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/io/Cursor.h>
#include <quic/api/QuicStreamAsyncTransport.h>
#include <quic/common/events/FollyQuicEventBase.h>

namespace quic {

QuicStreamAsyncTransport::UniquePtr
QuicStreamAsyncTransport::createWithNewStream(
    std::shared_ptr<quic::QuicSocket> sock) {
  auto streamId = sock->createBidirectionalStream();
  if (!streamId) {
    return nullptr;
  }
  return createWithExistingStream(std::move(sock), *streamId);
}

QuicStreamAsyncTransport::UniquePtr
QuicStreamAsyncTransport::createWithExistingStream(
    std::shared_ptr<quic::QuicSocket> sock,
    quic::StreamId streamId) {
  UniquePtr ptr(new QuicStreamAsyncTransport());
  ptr->setSocket(std::move(sock));
  ptr->setStreamId(streamId);
  return ptr;
}

void QuicStreamAsyncTransport::setSocket(
    std::shared_ptr<quic::QuicSocket> sock) {
  sock_ = std::move(sock);
}

void QuicStreamAsyncTransport::setStreamId(quic::StreamId id) {
  CHECK(!id_.has_value()) << "stream id can only be set once";
  CHECK(state_ == CloseState::OPEN) << "Current state: " << (int)state_;

  id_ = id;

  // TODO: handle timeout for assigning stream id
  auto setCallbackResult = sock_->setReadCallback(*id_, this);
  if (setCallbackResult.hasError()) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::UNKNOWN,
        folly::to<std::string>(
            "Failed to set read callback: ",
            toString(setCallbackResult.error())));
  }
  handleRead();

  if (!writeCallbacks_.empty()) {
    // adjust offsets of buffered writes
    auto streamWriteOffset = sock_->getStreamWriteOffset(*id_);
    if (streamWriteOffset.hasError()) {
      folly::AsyncSocketException ex(
          folly::AsyncSocketException::INTERNAL_ERROR,
          fmt::format(
              "QuicSocket::getStreamWriteOffset error: {}",
              toString(streamWriteOffset.error())));
      closeNowImpl(std::move(ex));
      return;
    }
    for (auto& p : writeCallbacks_) {
      p.first += *streamWriteOffset;
    }
    streamWriteOffset_ += *streamWriteOffset;
    auto res = sock_->notifyPendingWriteOnStream(*id_, this);
    if (!res) {
      LOG(WARNING) << "Failed to notify pending write on stream: "
                   << toString(res.error());
    }
  }
}

void QuicStreamAsyncTransport::destroy() {
  if (state_ != CloseState::CLOSED) {
    closeNow();
  }
  // Then call DelayedDestruction::destroy() to take care of
  // whether or not we need immediate or delayed destruction
  DelayedDestruction::destroy();
}

void QuicStreamAsyncTransport::setReadCB(
    AsyncTransport::ReadCallback* callback) {
  readCb_ = callback;
  if (id_) {
    if (!readCb_) {
      auto pauseResult = sock_->pauseRead(*id_);
      if (pauseResult.hasError()) {
        VLOG(1) << "Failed to pause read: " << toString(pauseResult.error());
      }
    } else if (sock_->resumeRead(*id_).hasError()) {
      // this is our first time installing the read callback
      auto setCallbackResult = sock_->setReadCallback(*id_, this);
      if (setCallbackResult.hasError()) {
        VLOG(1) << "Failed to set read callback: "
                << toString(setCallbackResult.error());
      }
    }
    // It should be ok to do this immediately, rather than in the loop
    handleRead();
  }
}

folly::AsyncTransport::ReadCallback* QuicStreamAsyncTransport::getReadCallback()
    const {
  return readCb_;
}

void QuicStreamAsyncTransport::addWriteCallback(
    AsyncTransport::WriteCallback* callback) {
  size_t size = writeBuf_.chainLength();
  writeCallbacks_.emplace_back(streamWriteOffset_ + size, callback);
  if (id_) {
    auto res = sock_->notifyPendingWriteOnStream(*id_, this);
    if (!res) {
      VLOG(1) << "Failed to notify pending write on stream: "
              << toString(res.error());
    }
  }
}

bool QuicStreamAsyncTransport::handleWriteStateError(
    AsyncTransport::WriteCallback* callback) {
  if (writeEOF_ != EOFState::NOT_SEEN) {
    folly::AsyncSocketException ex(
        folly::AsyncSocketException::UNKNOWN,
        "Quic write error: bad EOF state");
    callback->writeErr(0, ex);
    return true;
  } else if (state_ == CloseState::CLOSED) {
    folly::AsyncSocketException ex(
        folly::AsyncSocketException::UNKNOWN, "Quic write error: closed state");
    callback->writeErr(0, ex);
    return true;
  } else if (ex_) {
    callback->writeErr(0, *ex_);
    return true;
  } else {
    return false;
  }
}

void QuicStreamAsyncTransport::write(
    AsyncTransport::WriteCallback* callback,
    const void* buf,
    size_t bytes,
    folly::WriteFlags /*flags*/) {
  if (handleWriteStateError(callback)) {
    return;
  }
  writeBuf_.append(BufHelpers::wrapBuffer(buf, bytes));
  addWriteCallback(callback);
}

void QuicStreamAsyncTransport::writev(
    AsyncTransport::WriteCallback* callback,
    const iovec* vec,
    size_t count,
    folly::WriteFlags /*flags*/) {
  if (handleWriteStateError(callback)) {
    return;
  }
  for (size_t i = 0; i < count; i++) {
    writeBuf_.append(BufHelpers::wrapBuffer(vec[i].iov_base, vec[i].iov_len));
  }
  addWriteCallback(callback);
}

void QuicStreamAsyncTransport::writeChain(
    AsyncTransport::WriteCallback* callback,
    std::unique_ptr<folly::IOBuf>&& buf,
    folly::WriteFlags /*flags*/) {
  if (handleWriteStateError(callback)) {
    return;
  }
  writeBuf_.append(std::move(buf));
  addWriteCallback(callback);
}

void QuicStreamAsyncTransport::close() {
  state_ = CloseState::CLOSING;
  if (id_) {
    sock_->stopSending(*id_, quic::GenericApplicationErrorCode::UNKNOWN);
  }
  shutdownWrite();
  if (readCb_ && readEOF_ != EOFState::DELIVERED) {
    // This is such a bizarre operation.  I almost think if we haven't seen
    // a fin then we should readErr instead of readEOF, this mirrors
    // AsyncSocket though
    readEOF_ = EOFState::QUEUED;
    handleRead();
  }
}

void QuicStreamAsyncTransport::closeNow() {
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::UNKNOWN, "Quic closeNow");
  if (id_) {
    auto res =
        sock_->stopSending(*id_, quic::GenericApplicationErrorCode::UNKNOWN);
    if (!res) {
      VLOG(1) << "Failed to stop sending during closeNow: "
              << toString(res.error());
    }
    shutdownWriteNow();
  }
  closeNowImpl(std::move(ex));
}

void QuicStreamAsyncTransport::closeWithReset() {
  if (id_) {
    auto res1 =
        sock_->stopSending(*id_, quic::GenericApplicationErrorCode::UNKNOWN);
    if (!res1) {
      VLOG(1) << "Failed to stop sending during closeWithReset: "
              << toString(res1.error());
    }
    auto res2 =
        sock_->resetStream(*id_, quic::GenericApplicationErrorCode::UNKNOWN);
    if (!res2) {
      VLOG(1) << "Failed to reset stream during closeWithReset: "
              << toString(res2.error());
    }
  }
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::UNKNOWN, "Quic closeNow");
  closeNowImpl(std::move(ex));
}

void QuicStreamAsyncTransport::shutdownWrite() {
  if (writeEOF_ == EOFState::NOT_SEEN) {
    writeEOF_ = EOFState::QUEUED;
    if (id_) {
      auto res = sock_->notifyPendingWriteOnStream(*id_, this);
      if (!res) {
        VLOG(1) << "Failed to notify pending write on stream: "
                << toString(res.error());
      }
    }
  }
}

void QuicStreamAsyncTransport::shutdownWriteNow() {
  if (writeEOF_ == EOFState::DELIVERED) {
    // writes already shutdown
    return;
  }
  shutdownWrite();
  send(0);
  if (id_ && writeEOF_ != EOFState::DELIVERED) {
    auto res =
        sock_->resetStream(*id_, quic::GenericApplicationErrorCode::UNKNOWN);
    if (!res) {
      VLOG(1) << "Failed to reset stream during shutdownWriteNow: "
              << toString(res.error());
    } else {
      VLOG(4) << "Reset stream from shutdownWriteNow";
    }
  }
}

bool QuicStreamAsyncTransport::good() const {
  return (
      !ex_ &&
      (readEOF_ == EOFState::NOT_SEEN || writeEOF_ == EOFState::NOT_SEEN));
}

bool QuicStreamAsyncTransport::readable() const {
  return !ex_ && readEOF_ == EOFState::NOT_SEEN;
}

bool QuicStreamAsyncTransport::writable() const {
  return !ex_ && writeEOF_ == EOFState::NOT_SEEN;
}

bool QuicStreamAsyncTransport::isPending() const {
  return false;
}

bool QuicStreamAsyncTransport::connecting() const {
  return !id_.has_value() && (state_ == CloseState::OPEN);
}

bool QuicStreamAsyncTransport::error() const {
  return bool(ex_);
}

folly::EventBase* QuicStreamAsyncTransport::getEventBase() const {
  return sock_->getEventBase()
      ->getTypedEventBase<FollyQuicEventBase>()
      ->getBackingEventBase();
}

void QuicStreamAsyncTransport::attachEventBase(
    folly::EventBase* /*eventBase*/) {
  LOG(FATAL) << "Does QUICSocket support this?";
}

void QuicStreamAsyncTransport::detachEventBase() {
  LOG(FATAL) << "Does QUICSocket support this?";
}

bool QuicStreamAsyncTransport::isDetachable() const {
  return false;
}

void QuicStreamAsyncTransport::setSendTimeout(uint32_t /*milliseconds*/) {
  // QuicSocket needs this
}

uint32_t QuicStreamAsyncTransport::getSendTimeout() const {
  // TODO: follow up on getSendTimeout() use, 0 indicates that no timeout is
  // set.
  return 0;
}

void QuicStreamAsyncTransport::getLocalAddress(
    folly::SocketAddress* address) const {
  *address = sock_->getLocalAddress();
}

void QuicStreamAsyncTransport::getPeerAddress(
    folly::SocketAddress* address) const {
  *address = sock_->getPeerAddress();
}

bool QuicStreamAsyncTransport::isEorTrackingEnabled() const {
  return false;
}

void QuicStreamAsyncTransport::setEorTracking(bool /*track*/) {}

size_t QuicStreamAsyncTransport::getAppBytesWritten() const {
  return streamWriteOffset_ + writeBuf_.chainLength();
}

size_t QuicStreamAsyncTransport::getRawBytesWritten() const {
  // TOOD: should this include QUIC framing overhead?
  return getAppBytesWritten();
}

size_t QuicStreamAsyncTransport::getAppBytesReceived() const {
  // TODO: track read bytes to have it available after QUIC stream closure
  return 0;
}

size_t QuicStreamAsyncTransport::getRawBytesReceived() const {
  return getAppBytesReceived();
}

std::string QuicStreamAsyncTransport::getApplicationProtocol() const noexcept {
  return sock_->getAppProtocol().value_or("");
}

std::string QuicStreamAsyncTransport::getSecurityProtocol() const {
  return "quic/tls1.3";
}

void QuicStreamAsyncTransport::readAvailable(
    quic::StreamId /*streamId*/) noexcept {
  // defer the actual read until the loop callback.  This prevents possible
  // tail recursion with readAvailable -> setReadCallback -> readAvailable
  sock_->getEventBase()->runInLoop(this, true);
}

void QuicStreamAsyncTransport::readError(
    quic::StreamId /*streamId*/,
    QuicError error) noexcept {
  ex_ = folly::AsyncSocketException(
      folly::AsyncSocketException::UNKNOWN,
      fmt::format("Quic read error: {}", toString(error)));
  sock_->getEventBase()->runInLoop(this, true);
  // TODO: RST here?
}

void QuicStreamAsyncTransport::runLoopCallback() noexcept {
  handleRead();
}

void QuicStreamAsyncTransport::handleRead() {
  folly::DelayedDestruction::DestructorGuard dg(this);
  bool emptyRead = false;
  size_t numReads = 0;
  while (readCb_ && id_ && !ex_ && readEOF_ == EOFState::NOT_SEEN &&
         !emptyRead && ++numReads < 16 /* max reads per event */) {
    void* buf = nullptr;
    size_t len = 0;
    if (readCb_->isBufferMovable()) {
      len = readCb_->maxBufferSize();
    } else {
      readCb_->getReadBuffer(&buf, &len);
      if (buf == nullptr || len == 0) {
        ex_ = folly::AsyncSocketException(
            folly::AsyncSocketException::BAD_ARGS,
            "ReadCallback::getReadBuffer() returned empty buffer");
        break;
      }
    }
    auto readData = sock_->read(*id_, len);
    if (readData.hasError()) {
      ex_ = folly::AsyncSocketException(
          folly::AsyncSocketException::UNKNOWN,
          fmt::format("Quic read error: {}", toString(readData.error())));
    } else {
      if (!readData->first) {
        emptyRead = true;
      } else {
        if (readCb_->isBufferMovable()) {
          readCb_->readBufferAvailable(std::move(readData->first));
        } else {
          size_t readLen = readData->first->computeChainDataLength();
          Cursor c(readData->first.get());
          CHECK_NOTNULL(buf);
          c.pull(buf, readLen);
          readCb_->readDataAvailable(readLen);
        }
      }
      if (readData->second && readEOF_ == EOFState::NOT_SEEN) {
        readEOF_ = EOFState::QUEUED;
      }
    }
  }

  // in case readCb_ got reset from read callbacks
  if (!readCb_) {
    return;
  }

  if (ex_) {
    auto cb = readCb_;
    readCb_ = nullptr;
    cb->readErr(*ex_);
  } else if (readEOF_ == EOFState::QUEUED) {
    auto cb = readCb_;
    readCb_ = nullptr;
    cb->readEOF();
    readEOF_ = EOFState::DELIVERED;
  }

  if (id_) {
    if (!readCb_ || readEOF_ != EOFState::NOT_SEEN) {
      auto res = sock_->setReadCallback(*id_, nullptr);
      if (!res) {
        VLOG(1) << "Failed to clear read callback: " << toString(res.error());
      }
    }
  }
}

void QuicStreamAsyncTransport::send(uint64_t maxToSend) {
  VLOG(4) << __func__ << " " << maxToSend;
  CHECK(id_);
  // overkill until there are delivery cbs
  folly::DelayedDestruction::DestructorGuard dg(this);
  uint64_t toSend =
      std::min(maxToSend, static_cast<uint64_t>(writeBuf_.chainLength()));

  uint64_t sentOffset = streamWriteOffset_ + toSend;
  bool writeEOF =
      (writeEOF_ == EOFState::QUEUED && writeBuf_.chainLength() == toSend);
  auto res = sock_->writeChain(
      *id_,
      writeBuf_.split(toSend),
      writeEOF,
      nullptr); // no delivery callbacks right now
  if (res.hasError()) {
    folly::AsyncSocketException ex(
        folly::AsyncSocketException::UNKNOWN,
        fmt::format("Quic write error: {}", toString(res.error())));
    failWrites(ex);
    return;
  }
  if (writeEOF) {
    writeEOF_ = EOFState::DELIVERED;
  } else if (writeBuf_.chainLength()) {
    VLOG(4) << __func__ << " buffered data, requesting callback";
    auto res2 = sock_->notifyPendingWriteOnStream(*id_, this);
    if (!res2) {
      VLOG(1) << "Failed to notify pending write on stream: "
              << toString(res2.error());
    }
  }
  // not actually sent.  Mirrors AsyncSocket and invokes when data is in
  // transport buffers
  streamWriteOffset_ = sentOffset;
  invokeWriteCallbacks();
}

void QuicStreamAsyncTransport::invokeWriteCallbacks() {
  VLOG(4) << __func__ << " " << streamWriteOffset_;
  while (!writeCallbacks_.empty() &&
         writeCallbacks_.front().first <= streamWriteOffset_) {
    VLOG(4) << __func__ << " " << writeCallbacks_.front().first;
    auto wcb = writeCallbacks_.front().second;
    writeCallbacks_.pop_front();
    wcb->writeSuccess();
  }
  if (writeEOF_ == EOFState::DELIVERED) {
    CHECK(writeCallbacks_.empty());
  }
}

void QuicStreamAsyncTransport::failWrites(
    const folly::AsyncSocketException& ex) {
  VLOG(4) << __func__;
  while (!writeCallbacks_.empty()) {
    auto& front = writeCallbacks_.front();
    auto wcb = front.second;
    writeCallbacks_.pop_front();
    // TODO: track bytesWritten, when buffer was split it may not be 0
    wcb->writeErr(0, ex);
  }
  writeEOF_ = EOFState::ERROR;
}

void QuicStreamAsyncTransport::onStreamWriteReady(
    quic::StreamId id,
    uint64_t maxToSend) noexcept {
  CHECK(id == *id_);
  if (writeEOF_ == EOFState::DELIVERED && writeBuf_.empty()) {
    // nothing left to write
    return;
  }
  send(maxToSend);
}

void QuicStreamAsyncTransport::onStreamWriteError(
    StreamId /*id*/,
    QuicError error) noexcept {
  if (writeEOF_ != EOFState::DELIVERED) {
    closeNowImpl(folly::AsyncSocketException(
        folly::AsyncSocketException::UNKNOWN,
        fmt::format("Quic write error: {}", toString(error))));
  }
}

void QuicStreamAsyncTransport::closeNowImpl(folly::AsyncSocketException&& ex) {
  folly::DelayedDestruction::DestructorGuard dg(this);
  if (state_ == CloseState::CLOSED) {
    return;
  }
  state_ = CloseState::CLOSED;
  ex_ = ex;
  readCb_ = nullptr;
  if (id_) {
    auto res1 = sock_->setReadCallback(*id_, nullptr);
    if (!res1) {
      VLOG(1) << "Failed to clear read callback during cleanup: "
              << toString(res1.error());
    }
    auto res2 = sock_->unregisterStreamWriteCallback(*id_);
    if (!res2) {
      VLOG(1) << "Failed to unregister write callback during cleanup: "
              << toString(res2.error());
    }
    id_.reset();
  }
  failWrites(*ex_);
}

} // namespace quic

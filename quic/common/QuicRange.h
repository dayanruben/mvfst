/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <string>

namespace quic {
template <class Iter>
struct Range {
  Iter begin_;
  Iter end_;

  Range(Iter begin, size_t size) : begin_(begin), end_(begin + size) {}

  Range(Iter begin, Iter end) : begin_(begin), end_(end) {}

  Range() : begin_(nullptr), end_(nullptr) {}

  // Conversion constructor for safe conversions (e.g., mutable to const)
  template <class OtherIter>
  Range(
      const Range<OtherIter>& other,
      typename std::enable_if<
          std::is_convertible<OtherIter, Iter>::value>::type* = nullptr)
      : begin_(other.begin_), end_(other.end_) {}

  size_t size() const {
    return end_ - begin_;
  }

  void advance(size_t amount) {
    begin_ += amount;
  }

  bool empty() const {
    return begin_ == end_;
  }

  Iter begin() const {
    return begin_;
  }

  Iter end() const {
    return end_;
  }

  Iter data() const {
    return begin_;
  }

  void clear() {
    begin_ = end_ = nullptr;
  }

  using reference = typename std::iterator_traits<Iter>::reference;

  reference operator[](size_t index) const {
    // Return the value at the specified index
    return *(begin_ + index);
  }

  std::string toString() const {
    return std::string(
        reinterpret_cast<const char*>(begin_),
        reinterpret_cast<const char*>(end_));
  }
};

using StringPiece = Range<const char*>;
using ByteRange = Range<const uint8_t*>;
using MutableByteRange = Range<uint8_t*>;
} // namespace quic

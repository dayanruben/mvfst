/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/common/QuicBuffer.h>

namespace quic {

TEST(QuicBufferTest, TestBasic) {
  auto quicBuffer = QuicBuffer::create(100);
  EXPECT_EQ(quicBuffer->next(), quicBuffer.get());
  EXPECT_EQ(quicBuffer->prev(), quicBuffer.get());

  EXPECT_EQ(quicBuffer->capacity(), 100);
  EXPECT_EQ(quicBuffer->length(), 0);
  EXPECT_EQ(quicBuffer->tailroom(), 100);
  EXPECT_EQ(quicBuffer->headroom(), 0);
  quicBuffer->append(10);
  EXPECT_EQ(quicBuffer->capacity(), 100);
  EXPECT_EQ(quicBuffer->length(), 10);
  EXPECT_EQ(quicBuffer->tailroom(), 90);
  EXPECT_EQ(quicBuffer->headroom(), 0);
}

TEST(QuicBufferTest, TestAppendToChain) {
  auto quicBuffer1 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr1 = quicBuffer1.get();
  auto quicBuffer2 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr2 = quicBuffer2.get();
  auto quicBuffer3 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr3 = quicBuffer3.get();

  quicBuffer2->appendToChain(std::move(quicBuffer3));
  quicBuffer1->appendToChain(std::move(quicBuffer2));

  // Check next pointers
  EXPECT_EQ(quicBufferRawPtr1->next(), quicBufferRawPtr2);
  EXPECT_EQ(quicBufferRawPtr2->next(), quicBufferRawPtr3);
  EXPECT_EQ(quicBufferRawPtr3->next(), quicBufferRawPtr1);

  // Check prev pointers
  EXPECT_EQ(quicBufferRawPtr1->prev(), quicBufferRawPtr3);
  EXPECT_EQ(quicBufferRawPtr2->prev(), quicBufferRawPtr1);
  EXPECT_EQ(quicBufferRawPtr3->prev(), quicBufferRawPtr2);
}

TEST(QuicBufferTest, TestSeparateChain) {
  auto quicBuffer1 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr1 = quicBuffer1.get();
  auto quicBuffer2 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr2 = quicBuffer2.get();
  auto quicBuffer3 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr3 = quicBuffer3.get();
  auto quicBuffer4 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr4 = quicBuffer4.get();
  auto quicBuffer5 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr5 = quicBuffer5.get();
  auto quicBuffer6 = QuicBuffer::create(100);
  QuicBuffer* quicBufferRawPtr6 = quicBuffer6.get();

  // Make the chain like
  // 1->2->3->4->5->6
  quicBuffer5->appendToChain(std::move(quicBuffer6));
  quicBuffer4->appendToChain(std::move(quicBuffer5));
  quicBuffer3->appendToChain(std::move(quicBuffer4));
  quicBuffer2->appendToChain(std::move(quicBuffer3));
  quicBuffer1->appendToChain(std::move(quicBuffer2));

  // The below separateChain call should make things look like:
  // 2->3->4 and 1->5->6
  auto returnedChain =
      quicBuffer1->separateChain(quicBufferRawPtr2, quicBufferRawPtr4);

  EXPECT_EQ(quicBufferRawPtr2->next(), quicBufferRawPtr3);
  EXPECT_EQ(quicBufferRawPtr3->next(), quicBufferRawPtr4);
  EXPECT_EQ(quicBufferRawPtr4->next(), quicBufferRawPtr2);

  EXPECT_EQ(returnedChain.get(), quicBufferRawPtr2);
  EXPECT_EQ(quicBufferRawPtr1->next(), quicBufferRawPtr5);
  EXPECT_EQ(quicBufferRawPtr5->next(), quicBufferRawPtr6);
  EXPECT_EQ(quicBufferRawPtr6->next(), quicBufferRawPtr1);
}

TEST(QuicBufferTest, TestCloneOne) {
  auto quicBuffer1 = QuicBuffer::create(100);
  quicBuffer1->append(10);

  auto quicBuffer2 = quicBuffer1->cloneOne();
  EXPECT_EQ(quicBuffer1->length(), quicBuffer2->length());
  EXPECT_EQ(quicBuffer1->capacity(), quicBuffer2->capacity());
  EXPECT_EQ(quicBuffer1->data(), quicBuffer2->data());
}

TEST(QuicBufferTest, TestClone) {
  auto quicBuffer1 = QuicBuffer::create(100);
  quicBuffer1->append(10);
  auto quicBuffer2 = QuicBuffer::create(100);
  quicBuffer2->append(20);
  auto quicBuffer3 = QuicBuffer::create(100);
  quicBuffer3->append(30);

  auto clonedBuffer = quicBuffer1->clone();
  QuicBuffer* ptr1 = quicBuffer1.get();
  QuicBuffer* ptr2 = clonedBuffer.get();

  for (int i = 0; i < 3; i++) {
    EXPECT_EQ(ptr1->length(), ptr2->length());
    EXPECT_EQ(ptr1->capacity(), ptr2->capacity());
    EXPECT_EQ(ptr1->data(), ptr2->data());
    ptr1 = ptr1->next();
    ptr2 = ptr2->next();
  }
}

TEST(QuicBufferTest, TestAdvance) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer1 = QuicBuffer::create(100);
  memcpy(quicBuffer1->writableData(), data, 5);
  quicBuffer1->append(5);
  const uint8_t* prevData = quicBuffer1->data();
  quicBuffer1->advance(10);
  EXPECT_EQ(quicBuffer1->data(), prevData + 10);
  EXPECT_EQ(memcmp(quicBuffer1->data(), "hello", 5), 0);
}

TEST(QuicBufferTest, TestAdvanceNotEnoughRoom) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer1 = QuicBuffer::create(6);
  memcpy(quicBuffer1->writableData(), data, 5);
  quicBuffer1->append(5);
  quicBuffer1->advance(1); // Should succeed
  EXPECT_DEATH(quicBuffer1->advance(1), "");
}

TEST(QuicBufferTest, TestCopyBufferSpan) {
  const uint8_t* data = (const uint8_t*)"hello";
  std::span range(data, 5);
  auto quicBuffer =
      QuicBuffer::copyBuffer(range, 1 /*headroom*/, 3 /*tailroom*/);
  EXPECT_EQ(quicBuffer->length(), 5);
  EXPECT_EQ(quicBuffer->capacity(), 9);
  EXPECT_EQ(memcmp(quicBuffer->data(), data, 5), 0);
}

TEST(QuicBufferTest, TestCopyBufferString) {
  std::string input("hello");
  auto quicBuffer =
      QuicBuffer::copyBuffer(input, 1 /*headroom*/, 3 /*tailroom*/);
  EXPECT_EQ(quicBuffer->length(), 5);
  EXPECT_EQ(quicBuffer->capacity(), 9);
  EXPECT_EQ(memcmp(quicBuffer->data(), "hello", 5), 0);
}

TEST(QuicBufferTest, TestCopyBufferPointerAndSize) {
  const uint8_t* data = (const uint8_t*)"hello";
  auto quicBuffer =
      QuicBuffer::copyBuffer(data, 5 /*size*/, 1 /*headroom*/, 3 /*tailroom*/);
  EXPECT_EQ(quicBuffer->length(), 5);
  EXPECT_EQ(quicBuffer->capacity(), 9);
  EXPECT_EQ(memcmp(quicBuffer->data(), "hello", 5), 0);
}

} // namespace quic

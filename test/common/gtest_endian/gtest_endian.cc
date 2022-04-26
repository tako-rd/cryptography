/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "gtest_endian.h"

using namespace cryptography;

TEST_F(GTestEndian, Normal_BigEndian_001) {
  uint8_t out_u8[16] = {0};
  uint16_t out_u16[8] = {0};
  uint8_t *out_u8_p = nullptr;
  uint16_t *out_u16_p = nullptr;

  out_u16_p = endian<BIG, uint16_t, 16>::convert(TEST_VECTOR_U8, out_u16);

  for (uint32_t i = 0; i < 8; ++i) {
    EXPECT_EQ(TEST_VECTOR_U16[i], out_u16_p[i]);
  }

  out_u8_p = endian<BIG, uint16_t, 16>::convert(out_u16, out_u8);

  for (uint32_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_VECTOR_U8[i], out_u8_p[i]);
  }
}

TEST_F(GTestEndian, Normal_BigEndian_002) {
  uint8_t out_u8[16] = {0};
  uint32_t out_u32[4] = {0};
  uint8_t *out_u8_p = nullptr;
  uint32_t *out_u32_p  = nullptr;

  out_u32_p = endian<BIG, uint32_t, 16>::convert(TEST_VECTOR_U8, out_u32);

  for (uint32_t i = 0; i < 4; ++i) {
    EXPECT_EQ(TEST_VECTOR_U32[i], out_u32_p[i]);
  }

  out_u8_p = endian<BIG, uint32_t, 16>::convert(out_u32, out_u8);

  for (uint32_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_VECTOR_U8[i], out_u8_p[i]);
  }
}

TEST_F(GTestEndian, Normal_BigEndian_003) {
  uint8_t out_u8[16] = {0};
  uint64_t out_u64[2] = {0};
  uint8_t *out_u8_p = nullptr;
  uint64_t *out_u64_p  = nullptr;

  out_u64_p = endian<BIG, uint64_t, 16>::convert(TEST_VECTOR_U8, out_u64);

  for (uint32_t i = 0; i < 2; ++i) {
    EXPECT_EQ(TEST_VECTOR_U64[i], out_u64_p[i]);
  }

  out_u8_p = endian<BIG, uint64_t, 16>::convert(out_u64, out_u8);

  for (uint32_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_VECTOR_U8[i], out_u8_p[i]);
  }
}
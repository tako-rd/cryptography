/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef GTEST_ENDIAN_DEFS_H
#define GTEST_ENDIAN_DEFS_H

#include <stdint.h>

static const uint8_t TEST_VECTOR_U8[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static const uint16_t TEST_VECTOR_U16[8] = {
  0x0001, 0x0203, 0x0405, 0x0607, 0x0809, 0x0a0b, 0x0c0d, 0x0e0f,
};

static const uint32_t TEST_VECTOR_U32[4] = {
  0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
};

static const uint64_t TEST_VECTOR_U64[2] = {
  0x0001020304050607, 0x08090a0b0c0d0e0f,
};


#endif

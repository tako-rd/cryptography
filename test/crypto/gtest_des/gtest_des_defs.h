/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_DES_DEFS_H
#define GTEST_DES_DEFS_H

#include <stdint.h>

static const uint8_t DES_TEST_KEY_01[8]    = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
static const uint8_t DES_TEST_PLAINTEXT_01[8] = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

static const char DES_TEST_KEY_02[8]       = "ABCDEFG";
static const char DES_TEST_PLAINTEXT_02[8] = "ABCDEFG";

static const uint8_t DES_TEST_KEY_03[8]       = {0b10000001, 0b01000001, 0b00100001, 0b00010001, 0b00001001, 0b00000101, 0b00000011, 0b11111111};
static const uint8_t DES_TEST_PLAINTEXT_03[8] = {0b11111111, 0b00000000, 0b10101010, 0b01010101, 0b00000000, 0b11111111, 0b01010101, 0b10101010};

static const char DES_TEST_STRING_SINGLE_BYTE_STRING[8]    = "cipher.";
static const char DES_TEST_STRING_MULTI_BYTE_STRING[8]     = "à√çÜï∂.";
static const char DES_TEST_STRING_U8_MULTI_BYTE_STRING[8]  = u8"à√çÜ.";

#endif
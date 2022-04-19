/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <stdint.h>

#ifndef GTEST_CAST128_DEFS_H
#define GTEST_CAST128_DEFS_H

/**************************************************************/
/* Quoted from below.                                         */
/* RFC 2144  The CAST-128 Encryption Algorithm  May 1997      */
/* https://datatracker.ietf.org/doc/html/rfc2144              */
/**************************************************************/

/**************************************************************/
/* See below.                                                 */
/* Appendix B. Test Vectors                                   */
/* B.1. Single Plaintext-Key-Ciphertext Sets                  */
/**************************************************************/

/* 128 BIT */
static const uint8_t CAST128_EXAM_128BIT_PLAINTEXT[8] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

static const uint8_t CAST128_EXAM_128BIT_KEY[16] = {
  0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A,
};

static const uint8_t CAST128_EXAM_128BIT_CIPHERTEXT[8] = {
  0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2,
};

/* 80 BIT */
static const uint8_t CAST128_EXAM_80BIT_PLAINTEXT[8] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

static const uint8_t CAST128_EXAM_80BIT_KEY[10] = {
  0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45,
};

static const uint8_t CAST128_EXAM_80BIT_CIPHERTEXT[8] = {
  0xEB, 0x6A, 0x71, 0x1A, 0x2C, 0x02, 0x27, 0x1B,
};

/* 40 BIT */
static const uint8_t CAST128_EXAM_40BIT_PLAINTEXT[8] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

static const uint8_t CAST128_EXAM_40BIT_KEY[5] = {
  0x01, 0x23, 0x45, 0x67, 0x12,
};

static const uint8_t CAST128_EXAM_40BIT_CIPHERTEXT[8] = {
  0x7A, 0xC8, 0x16, 0xD1, 0x6E, 0x9B, 0x30, 0x2E,
};


#endif
/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <stdint.h>

#ifndef GTEST_SEED_DEFS_H
#define GTEST_SEED_DEFS_H

/**************************************************************/
/* See below.                                                 */
/* RFC 4269  The SEED Encryption Algorithm  December 2005     */
/* https://datatracker.ietf.org/doc/html/rfc4269              */
/**************************************************************/

/**************************************************************/
/* See below.                                                 */
/* Appendix B.  Test Vectors                                  */
/**************************************************************/

static const uint8_t SEED_EXAM1_PLAINTEXT[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static const uint8_t SEED_EXAM1_128BIT_KEY[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t SEED_EXAM1_128BIT_CIPHERTEXT[16] = {
  0x5E, 0xBA, 0xC6, 0xE0, 0x05, 0x4E, 0x16, 0x68, 0x19, 0xAF, 0xF1, 0xCC, 0x6D, 0x34, 0x6C, 0xDB
};

#endif
/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <stdint.h>

#ifndef GTEST_RC6_DEFS_H
#define GTEST_RC6_DEFS_H

/****************************************************************************************************/
/* See below.                                                                                       */
/* The Security of the RC6TM Block Cipher Version 1.0 - August 20, 1998                             */
/* https://people.csail.mit.edu/rivest/ContiniRivestRobshawYin-TheSecurityOfTheRC6BlockCipher.pdf   */
/****************************************************************************************************/

/****************************************************************************************************/
/* See below.                                                                                       */
/* Appendix Test vectors                                                                            */
/****************************************************************************************************/

static const uint8_t RC6_EXAM1_PLAINTEXT[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t RC6_EXAM1_128BIT_KEY[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t RC6_EXAM1_128BIT_CIPHERTEXT[16] = {
  0x8f, 0xc3, 0xa5, 0x36, 0x56, 0xb1, 0xf7, 0x78, 0xc1, 0x29, 0xdf, 0x4e, 0x98, 0x48, 0xa4, 0x1e,
};

#endif

/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <stdint.h>

#ifndef GTEST_TWOFISH_DEFS_H
#define GTEST_TWOFISH_DEFS_H

/********************************************************************************/
/* See below.                                                                   */
/* Twofish: A 128-Bit Block Cipher  15 June 1998                                */
/* https://www.schneier.com/wp-content/uploads/2016/02/paper-twofish-paper.pdf  */
/********************************************************************************/

/********************************************************************************/
/* See below.                                                                   */
/* A Twofish Test Vectors                                                       */
/* A.1 Intermediate Values                                                      */
/********************************************************************************/

static const uint8_t TWOFISH_EXAM1_PLAINTEXT[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t TWOFISH_EXAM1_128BIT_KEY[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t TWOFISH_EXAM1_128BIT_CIPHERTEXT[16] = {
  0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
};

#endif
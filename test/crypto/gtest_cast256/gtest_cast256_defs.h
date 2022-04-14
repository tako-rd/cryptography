/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <stdint.h>

#ifndef GTEST_CAST256_DEFS_H
#define GTEST_CAST256_DEFS_H

/**************************************************************/
/* See below.                                                 */
/* RFC 2612  The CAST-256 Encryption Algorithm  June 1999     */
/* https://datatracker.ietf.org/doc/html/rfc2612              */
/**************************************************************/

/**************************************************************/
/* See below.                                                 */
/* Appendix A: Test Vectors                                   */
/**************************************************************/

static const uint8_t CAST256_EXAM1_PLAINTEXT[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t CAST256_EXAM1_128BIT_KEY[16] = {
  0x23, 0x42, 0xbb, 0x9e, 0xfa, 0x38, 0x54, 0x2c, 0x0a, 0xf7, 0x56, 0x47, 0xf2, 0x9f, 0x61, 0x5d,
};

static const uint8_t CAST256_EXAM1_128BIT_CIPHERTEXT[16] = {
  0xc8, 0x42, 0xa0, 0x89, 0x72, 0xb4, 0x3d, 0x20, 0x83, 0x6c, 0x91, 0xd1, 0xb7, 0x53, 0x0f, 0x6b,
};

#endif
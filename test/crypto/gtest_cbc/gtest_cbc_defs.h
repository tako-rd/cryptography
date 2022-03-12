/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CBC_DEFS_H
#define GTEST_CBC_DEFS_H

#include <stdint.h>

/********************************/
/* Test data under development. */
/********************************/

static const uint8_t CBC_TEST_DES_IV[8] = {
  '8', '7', '6', '5', '4', '3', '2', '1',
};

static const uint8_t CBC_TEST_AES_IV[16] = {
  '8', '7', '6', '5', '4', '3', '2', '1',
  '8', '7', '6', '5', '4', '3', '2', '1',
};

static const uint8_t CBC_TEST_STRING[80] = {
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
};

/**************************************************************/
/* See below.                                                 */
/* NIST Special Publication 800-38A 2001 Edition              */
/* Recommendation for Block Cipher Modes of Operation         */
/* https://csrc.nist.gov/publications/detail/sp/800-38a/final */
/**************************************************************/

/*****************************************************************/
/* See below.                                                    */
/* Appendix F: Example Vectors for Modes of Operation of the AES */
/*****************************************************************/

static const uint8_t NIST_AES_CBC_EXAM_PLAINTEXT[64] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

/*****************************************************************/
/* See below.                                                    */
/* F.2 CBC Example Vectors                                       */
/*****************************************************************/

static const uint8_t NIST_AES_CBC_EXAM_AES_KEY[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

static const uint8_t NIST_AES_CBC_EXAM_AES_IV[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

#endif
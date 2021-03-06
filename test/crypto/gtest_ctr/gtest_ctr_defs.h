/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CTR_DEFS_H
#define GTEST_CTR_DEFS_H

#include <stdint.h>

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

static const uint8_t NIST_AES_CTR_EXAM_PLAINTEXT[64] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

/*****************************************************************/
/* See below.                                                    */
/* F.5 CTR Example Vectors                                       */
/*****************************************************************/

static const uint8_t NIST_AES_CTR_EXAM_AES_KEY[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

static const uint8_t NIST_AES_CTR_EXAM_AES_IV[16] = {
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

static const uint8_t NIST_AES_CTR_EXAM_CIPHERTEXT[64] = {
  0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
  0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
  0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
  0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
};

/*********************/
/* 64-bit test data. */
/*********************/
static const uint8_t CTR_64BIT_PLAINTEXT[8] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

static const uint8_t CTR_64BIT_IV[8] = {
  0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
};

static const uint8_t CTR_64BIT_KEY[8] = {
  0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
};

/**********************/
/* 128-bit test data. */
/**********************/
static const uint8_t CTR_128BIT_PLAINTEXT[16] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

static const uint8_t CTR_128BIT_IV[16] = {
  0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
};

static const uint8_t CTR_128BIT_KEY[16] = {
  0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
};

/******************************************************/
/* Character string assuming the use of this library. */
/******************************************************/

static const uint8_t CTR_PLAINTEXT_001[467] = "?[????????????????????????"  \
                                              "????????????????????"  \
                                              "?????????????????????@??????????"  \
                                              "?????????????????@????????????"  \
                                              "?????????????????????@?[????????????????????"  \
                                              "???????????@????????????"  \
                                              "?????????@????????????????????"  \
                                              "?????????@?[????????????????????????"  \
                                              "???????????????[??????????????????"  \
                                              "???????????@????????????"  \
                                              "??????????????????????????????"  \
                                              "?????[?????????@????????????????"  \
                                              "???????????????????????@??????????????????"  \
                                              "?????[??????????????????????????"  \
                                              "???????????@??????????????????";


#endif
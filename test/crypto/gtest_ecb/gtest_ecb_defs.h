/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_ECB_DEFS_H
#define GTEST_ECB_DEFS_H

#include <stdint.h>

/**********************************************************************************/
/* Quoted from below.                                                             */
/* NIST Special Publication 800-38A 2001 Edition                                  */
/* Recommendation for Block Cipher Modes of Operation                             */
/* https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf  */
/**********************************************************************************/

static const uint8_t FIPS197_C1_128BIT_BASED_TEST_KEY[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT[64] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const uint8_t FIPS197_C1_128BIT_BASED_TEST_CIPHERTEXT[64] = {
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};

/******************************************************/
/* Character string assuming the use of this library. */
/******************************************************/

static const uint8_t ECB_PLAINTEXT_001[457] = "ゆうがた　うちへかえると" \
                                              "とぐちで　おやじがしんでいた" \
                                              "めずらしいこともあるものだ　とおもって" \
                                              "おやじをまたいで　なかへはいると" \
                                              "だいどころで　おふくろがしんでいた" \
                                              "ガスレンジのひが　つけっぱなしだったから" \
                                              "ひをけして　シチューのあじみをした" \
                                              "このちょうしでは" \
                                              "あにきもしんでいるに　ちがいない" \
                                              "あんのじょう　ふろばであにきはしんでいた" \
                                              "となりのこどもが　うそなきをしている" \
                                              "そばやのバイクの　ブレーキがきしむ" \
                                              "いつもとかわらぬ　ゆうぐれである" \
                                              "あしたが　なんのやくにもたたぬような";

#endif

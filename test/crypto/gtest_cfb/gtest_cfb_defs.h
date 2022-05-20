/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CFB_DEFS_H
#define GTEST_CFB_DEFS_H

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

static const uint8_t NIST_AES_CFB_EXAM_PLAINTEXT[64] = {
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

/*****************************************************************/
/* See below.                                                    */
/* F.3 CFB Example Vectors                                       */
/*****************************************************************/

static const uint8_t NIST_AES_CFB_EXAM_AES_KEY[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

static const uint8_t NIST_AES_CFB_EXAM_AES_IV[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t NIST_AES_CFB_EXAM_CIPHERTEXT[64] = {
  0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
  0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
  0x26, 0x75, 0x1f, 0x67, 0xa3, 0xcb, 0xb1, 0x40, 0xb1, 0x80, 0x8c, 0xf1, 0x87, 0xa4, 0xf4, 0xdf,
  0xc0, 0x4b, 0x05, 0x35, 0x7c, 0x5d, 0x1c, 0x0e, 0xea, 0xc4, 0xc6, 0x6f, 0x9f, 0xf7, 0xf2, 0xe6,
};

/******************************************************/
/* Character string assuming the use of this library. */
/******************************************************/

static const uint8_t CFB_PLAINTEXT_001[609] = "自分達は後悔なんかしていられない、"  \
                                              "したいことが多すぎる"  \
                                              "進め、進め。"  \
                                              "麦が出来そこなった！"  \
                                              "それもいゝだろう"  \
                                              "あとの為になる"  \
                                              "進め、進め。"  \
                                              "家が焼けた！"  \
                                              "それもいゝだろう"  \
                                              "新しい家がたつ"  \
                                              "進め、進め。"  \
                                              "人がぬけました"  \
                                              "仕方がない、"  \
                                              "更にいゝ人が入るだろう、"  \
                                              "進め、進め。"  \
                                              "何をしたらいゝのかわからない！"  \
                                              "しなければならないことを"  \
                                              "片っぱしからしろ、忠実に。"  \
                                              "進め、進め！"  \
                                              "こんな歩き方でいゝのか。"  \
                                              "いゝのだ。"  \
                                              "一歩でも一寸でも、信じる道を"  \
                                              "進め、進め。"  \
                                              "神がよしと見た道は"  \
                                              "まちがいのない道だ"  \
                                              "進め、進め。"  \
                                              "兄弟姉妹の"  \
                                              "幸福を祈って"  \
                                              "進め、進め。"  \
                                              "つい足をすべらした、"  \
                                              "かまわない"  \
                                              "過ちを再びするな"  \
                                              "進め、進め。"  \
                                              "後悔なんかしていられない、"  \
                                              "したいことが多すぎる"  \
                                              "進め、進め。";


#endif
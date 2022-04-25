/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ofb.h"

using namespace cryptography;

TEST_F(GTestOFB, Normal_AES_OFB_001) {
  secret_key<AES, OFB> aes_ofb;
  uint8_t origin_text[64] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, NIST_AES_OFB_EXAM_PLAINTEXT, sizeof(NIST_AES_OFB_EXAM_PLAINTEXT));

  aes_ofb.initialize(NIST_AES_OFB_EXAM_AES_KEY, sizeof(NIST_AES_OFB_EXAM_AES_KEY), 
                     NIST_AES_OFB_EXAM_AES_IV, sizeof(NIST_AES_OFB_EXAM_AES_IV));
  aes_ofb.encrypt(origin_text, sizeof(origin_text), ciphertext, sizeof(ciphertext));

  for (int32_t i = 0; i < sizeof(NIST_AES_OFB_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_OFB_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  aes_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (int32_t i = 0; i < sizeof(NIST_AES_OFB_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_OFB_EXAM_PLAINTEXT[i], plaintext[i]);
  }
}
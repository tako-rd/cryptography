/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_cfb.h"

using namespace cryptography;

TEST_F(GTestCFB, Normal_AES_CFB_001) {
  secret_key<AES, CFB> aes_cfb;
  uint8_t origin_text[64] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, NIST_AES_CFB_EXAM_PLAINTEXT, sizeof(NIST_AES_CFB_EXAM_PLAINTEXT));

  aes_cfb.initialize(NIST_AES_CFB_EXAM_AES_KEY, sizeof(NIST_AES_CFB_EXAM_AES_KEY), 
                     NIST_AES_CFB_EXAM_AES_IV, sizeof(NIST_AES_CFB_EXAM_AES_IV));
  aes_cfb.encrypt(origin_text, sizeof(origin_text), ciphertext, sizeof(ciphertext));

  for (int32_t i = 0; i < sizeof(NIST_AES_CFB_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CFB_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  aes_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (int32_t i = 0; i < sizeof(NIST_AES_CFB_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CFB_EXAM_PLAINTEXT[i], plaintext[i]);
  }
}


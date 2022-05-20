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
  uint8_t ciphertext[80] = {0};
  uint8_t plaintext[80] = {0};

  aes_ofb.initialize(NIST_AES_OFB_EXAM_AES_KEY, sizeof(NIST_AES_OFB_EXAM_AES_KEY), 
                     NIST_AES_OFB_EXAM_AES_IV, sizeof(NIST_AES_OFB_EXAM_AES_IV));
  aes_ofb.encrypt(NIST_AES_OFB_EXAM_PLAINTEXT, sizeof(NIST_AES_OFB_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext));

  for (int32_t i = 0; i < sizeof(NIST_AES_OFB_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_OFB_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  aes_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (int32_t i = 0; i < sizeof(NIST_AES_OFB_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_OFB_EXAM_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_AES_OFB_002) {
  secret_key<AES, OFB> aes_ofb;
  uint8_t ciphertext[608] = {0};
  uint8_t plaintext[608] = {0};

  aes_ofb.initialize(NIST_AES_OFB_EXAM_AES_KEY, sizeof(NIST_AES_OFB_EXAM_AES_KEY), 
                     NIST_AES_OFB_EXAM_AES_IV, sizeof(NIST_AES_OFB_EXAM_AES_IV));
  aes_ofb.encrypt(OFB_PLAINTEXT_001, sizeof(OFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext));
  aes_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (int32_t i = 0; i < sizeof(OFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(OFB_PLAINTEXT_001[i], plaintext[i]);
  }
}
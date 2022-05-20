/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ctr.h"

using namespace cryptography;

TEST_F(GTestCTR, Normal_AES_CTR_001) {
  secret_key<AES, CTR> aes_ctr;
  uint8_t ciphertext[80] = {0};
  uint8_t plaintext[80] = {0};

  aes_ctr.initialize(NIST_AES_CTR_EXAM_AES_KEY, sizeof(NIST_AES_CTR_EXAM_AES_KEY), 
                     NIST_AES_CTR_EXAM_AES_IV, sizeof(NIST_AES_CTR_EXAM_AES_IV));
  aes_ctr.encrypt(NIST_AES_CTR_EXAM_PLAINTEXT, sizeof(NIST_AES_CTR_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext));

  for (int32_t i = 0; i < sizeof(NIST_AES_CTR_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CTR_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  aes_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (int32_t i = 0; i < sizeof(NIST_AES_CTR_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CTR_EXAM_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_AES_CTR_002) {
  secret_key<AES, CTR> aes_ctr;
  uint8_t ciphertext[480] = {0};
  uint8_t plaintext[480] = {0};

  aes_ctr.initialize(NIST_AES_CTR_EXAM_AES_KEY, sizeof(NIST_AES_CTR_EXAM_AES_KEY), 
                     NIST_AES_CTR_EXAM_AES_IV, sizeof(NIST_AES_CTR_EXAM_AES_IV));
  aes_ctr.encrypt(CTR_PLAINTEXT_001, sizeof(CTR_PLAINTEXT_001), ciphertext, sizeof(ciphertext));
  aes_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (int32_t i = 0; i < sizeof(CTR_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CTR_PLAINTEXT_001[i], plaintext[i]);
  }
}
/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_cbc.h"

using namespace cryptography;

TEST_F(GTestCBC, Normal_AES_CBC_001) {
  secret_key<AES, CBC> aes_cbc;
  uint8_t ciphertext[80] = {0};
  uint8_t plaintext[80] = {0};

  EXPECT_EQ(0, aes_cbc.initialize(NIST_AES_CBC_EXAM_AES_KEY, sizeof(NIST_AES_CBC_EXAM_AES_KEY), 
                                  NIST_AES_CBC_EXAM_AES_IV, sizeof(NIST_AES_CBC_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_cbc.encrypt(NIST_AES_CBC_EXAM_PLAINTEXT, sizeof(NIST_AES_CBC_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CBC_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CBC_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CBC_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CBC_EXAM_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_AES_CBC_002) {
  secret_key<AES, CBC> aes_cbc;
  uint8_t ciphertext[128] = {0};
  uint8_t plaintext[128] = {0};

  EXPECT_EQ(0, aes_cbc.initialize(NIST_AES_CBC_EXAM_AES_KEY, sizeof(NIST_AES_CBC_EXAM_AES_KEY), 
                                  NIST_AES_CBC_EXAM_AES_IV, sizeof(NIST_AES_CBC_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_cbc.encrypt(CBC_PLAINTEXT_001, sizeof(CBC_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, aes_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CBC_PLAINTEXT_001[i], plaintext[i]);
  }
}


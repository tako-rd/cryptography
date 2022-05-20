/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ecb.h"

using namespace cryptography;

TEST_F(GTestECB, Normal_AES_ECB_001) {
  secret_key<AES, ECB> aes_ecb;
  uint8_t origin_text[64] = {0};
  uint8_t ciphertext[80] = {0};
  uint8_t plaintext[80] = {0};

  memcpy(origin_text, FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT, sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT));

  EXPECT_EQ(0, aes_ecb.initialize(FIPS197_C1_128BIT_BASED_TEST_KEY, sizeof(FIPS197_C1_128BIT_BASED_TEST_KEY), nullptr, 0));
  EXPECT_EQ(0, aes_ecb.encrypt(origin_text, sizeof(origin_text), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT); ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_BASED_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT); ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_AES_ECB_002) {
  secret_key<AES, ECB> aes_ecb;
  uint8_t ciphertext[464] = {0};
  uint8_t plaintext[464] = {0};

  EXPECT_EQ(0, aes_ecb.initialize(FIPS197_C1_128BIT_BASED_TEST_KEY, sizeof(FIPS197_C1_128BIT_BASED_TEST_KEY), nullptr, 0));
  EXPECT_EQ(0, aes_ecb.encrypt(ECB_PLAINTEXT_001, sizeof(ECB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, aes_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(ECB_PLAINTEXT_001[i], plaintext[i]);
  }
}
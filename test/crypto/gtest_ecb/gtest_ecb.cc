/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ecb.h"

TEST_F(GTestEcb, Normal_aes_ecb_001) {
  cryptography::ecb<cryptography::aes, 16> ecb;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT, sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT));

  aes.initialize(FIPS197_C1_128BIT_BASED_TEST_KEY, sizeof(FIPS197_C1_128BIT_BASED_TEST_KEY));
  ecb.initialize(nullptr, 0);
  ecb.encrypt(origin_text, sizeof(origin_text), str, sizeof(str));

  memset(str, 0x00, sizeof(str));
  memset(cstr, 0x00, sizeof(cstr));

  do {
    ecb.decrypt(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
    aes.decrypt(cstr, sizeof(cstr), str, sizeof(str));
  } while(0 == ecb.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));


  for (int32_t i = 0; i < sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT); ++i) {
    EXPECT_EQ(origin_text[i], plaintext[i]);
  }
}
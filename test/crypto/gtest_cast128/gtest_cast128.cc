/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_cast128.h"

TEST_F(GTestCast128, Normal_encrypt_to_decrypt_001) {
  cryptography::cast128 cast128;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  cast128.initialize(cryptography::CAST128, CAST128_EXAM1_128BIT_KEY, sizeof(CAST128_EXAM1_128BIT_KEY), false);

  cast128.encrypt(CAST128_EXAM1_PLAINTEXT, sizeof(CAST128_EXAM1_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(CAST128_EXAM1_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  cast128.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(CAST128_EXAM1_PLAINTEXT[i], plaintext[i]);
  }

}
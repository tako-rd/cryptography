/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_rc6.h"

TEST_F(GTestRC6, Normal_encrypt_to_decrypt_001) {
  cryptography::rc6 rc6;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  rc6.initialize(cryptography::RC6_128, RC6_EXAM1_128BIT_KEY, sizeof(RC6_EXAM1_128BIT_KEY), false);

  rc6.encrypt(RC6_EXAM1_PLAINTEXT, sizeof(RC6_EXAM1_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM1_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  rc6.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM1_PLAINTEXT[i], plaintext[i]);
  }

}
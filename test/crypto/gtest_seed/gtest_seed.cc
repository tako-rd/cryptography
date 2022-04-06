/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_seed.h"

TEST_F(GTestSeed, Normal_encrypt_to_decrypt_001) {
  cryptography::seed seed;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  seed.initialize(cryptography::SEED, SEED_EXAM1_128BIT_KEY, sizeof(SEED_EXAM1_128BIT_KEY), false);

  seed.encrypt(SEED_EXAM1_PLAINTEXT, sizeof(SEED_EXAM1_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM1_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  seed.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM1_PLAINTEXT[i], plaintext[i]);
  }

}
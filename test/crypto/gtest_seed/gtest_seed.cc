/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_seed.h"

TEST_F(GTestSeed, Normal_SEED_001) {
  cryptography::secret_key_cryptosystem<cryptography::seed> seed;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  seed.initialize(SEED_EXAM1_128BIT_KEY, sizeof(SEED_EXAM1_128BIT_KEY));

  seed.encrypt(SEED_EXAM1_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM1_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  seed.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM1_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestSeed, Normal_SEED_002) {
  cryptography::secret_key_cryptosystem<cryptography::seed> seed;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  seed.initialize(SEED_EXAM2_128BIT_KEY, sizeof(SEED_EXAM2_128BIT_KEY));

  seed.encrypt(SEED_EXAM2_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM2_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  seed.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM2_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestSeed, Normal_SEED_003) {
  cryptography::secret_key_cryptosystem<cryptography::seed> seed;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  seed.initialize(SEED_EXAM3_128BIT_KEY, sizeof(SEED_EXAM3_128BIT_KEY));

  seed.encrypt(SEED_EXAM3_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM3_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  seed.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM3_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestSeed, Normal_SEED_004) {
  cryptography::secret_key_cryptosystem<cryptography::seed> seed;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  seed.initialize(SEED_EXAM4_128BIT_KEY, sizeof(SEED_EXAM4_128BIT_KEY));

  seed.encrypt(SEED_EXAM4_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM4_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  seed.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(SEED_EXAM4_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

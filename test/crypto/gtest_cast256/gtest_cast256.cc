/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_cast256.h"

TEST_F(GTestCast256, Normal_CAST256_128_001) {
  cryptography::secret_key_cryptosystem<cryptography::cast256> cast256;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  cast256.initialize(CAST256_EXAM_128BIT_KEY, sizeof(CAST256_EXAM_128BIT_KEY));
  cast256.encrypt(CAST256_EXAM_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAST256_EXAM_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  cast256.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAST256_EXAM_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCast256, Normal_CAST256_192_001) {
  cryptography::secret_key_cryptosystem<cryptography::cast256> cast256;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  cast256.initialize(CAST256_EXAM_192BIT_KEY, sizeof(CAST256_EXAM_192BIT_KEY));
  cast256.encrypt(CAST256_EXAM_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAST256_EXAM_192BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  cast256.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAST256_EXAM_192BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCast256, Normal_CAST256_256_001) {
  cryptography::secret_key_cryptosystem<cryptography::cast256> cast256;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  cast256.initialize(CAST256_EXAM_256BIT_KEY, sizeof(CAST256_EXAM_256BIT_KEY));
  cast256.encrypt(CAST256_EXAM_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAST256_EXAM_256BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  cast256.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAST256_EXAM_256BIT_PLAINTEXT[i], plaintext[i]);
  }
}
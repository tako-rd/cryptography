/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_cast128.h"

TEST_F(GTestCast128, Normal_CAST128_128_001) {
  cryptography::secret_key_cryptosystem<cryptography::cast128> cast128;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  cast128.initialize(CAST128_EXAM_128BIT_KEY, sizeof(CAST128_EXAM_128BIT_KEY));
  cast128.encrypt(CAST128_EXAM_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(CAST128_EXAM_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  cast128.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(CAST128_EXAM_128BIT_PLAINTEXT[i], plaintext[i]);
  }

}

TEST_F(GTestCast128, Normal_CAST128_80_001) {
  cryptography::secret_key_cryptosystem<cryptography::cast128> cast128;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  cast128.initialize(CAST128_EXAM_80BIT_KEY, sizeof(CAST128_EXAM_80BIT_KEY));
  cast128.encrypt(CAST128_EXAM_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(CAST128_EXAM_80BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  cast128.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(CAST128_EXAM_80BIT_PLAINTEXT[i], plaintext[i]);
  }

}

TEST_F(GTestCast128, Normal_CAST128_40_001) {
  cryptography::secret_key_cryptosystem<cryptography::cast128> cast128;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  cast128.initialize(CAST128_EXAM_40BIT_KEY, sizeof(CAST128_EXAM_40BIT_KEY));
  cast128.encrypt(CAST128_EXAM_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(CAST128_EXAM_40BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  cast128.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(CAST128_EXAM_40BIT_PLAINTEXT[i], plaintext[i]);
  }
}
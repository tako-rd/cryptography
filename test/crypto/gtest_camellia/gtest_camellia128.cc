/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_camellia128.h"

TEST_F(GTestCamellia128, Normal_Camellia_128_001) {
  cryptography::camellia camellia;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  camellia.initialize(cryptography::CAMELLIA128, CAMELLIA_EXAM_128BIT_KEY, sizeof(CAMELLIA_EXAM_128BIT_KEY), false);

  camellia.encrypt(CAMELLIA_EXAM_PLAINTEXT, sizeof(CAMELLIA_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAMELLIA_EXAM_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  camellia.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAMELLIA_EXAM_PLAINTEXT[i], plaintext[i]);
  }

}

TEST_F(GTestCamellia128, Normal_Camellia_192_001) {
  cryptography::camellia camellia;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  camellia.initialize(cryptography::CAMELLIA192, CAMELLIA_EXAM_192BIT_KEY, sizeof(CAMELLIA_EXAM_192BIT_KEY), false);

  camellia.encrypt(CAMELLIA_EXAM_PLAINTEXT, sizeof(CAMELLIA_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAMELLIA_EXAM_192BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  camellia.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAMELLIA_EXAM_PLAINTEXT[i], plaintext[i]);
  }

}

TEST_F(GTestCamellia128, Normal_Camellia_256_001) {
  cryptography::camellia camellia;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  camellia.initialize(cryptography::CAMELLIA256, CAMELLIA_EXAM_256BIT_KEY, sizeof(CAMELLIA_EXAM_256BIT_KEY), false);

  camellia.encrypt(CAMELLIA_EXAM_PLAINTEXT, sizeof(CAMELLIA_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAMELLIA_EXAM_256BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  camellia.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(CAMELLIA_EXAM_PLAINTEXT[i], plaintext[i]);
  }

}

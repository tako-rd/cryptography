/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_twofish.h"

TEST_F(GTestTwofish, Normal_Twofish_128_001) {
  cryptography::secret_key_cryptosystem<cryptography::twofish> twofish;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {1};

  twofish.initialize(TWOFISH_EXAM1_128BIT_KEY, sizeof(TWOFISH_EXAM1_128BIT_KEY));

  twofish.encrypt(TWOFISH_EXAM1_128BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TWOFISH_EXAM1_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  twofish.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TWOFISH_EXAM1_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestTwofish, Normal_Twofish_192_001) {
  cryptography::secret_key_cryptosystem<cryptography::twofish> twofish;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {1};

  twofish.initialize(TWOFISH_EXAM1_192BIT_KEY, sizeof(TWOFISH_EXAM1_192BIT_KEY));

  twofish.encrypt(TWOFISH_EXAM1_192BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TWOFISH_EXAM1_192BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  twofish.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TWOFISH_EXAM1_192BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestTwofish, Normal_Twofish_256_001) {
  cryptography::secret_key_cryptosystem<cryptography::twofish> twofish;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {1};

  twofish.initialize(TWOFISH_EXAM1_256BIT_KEY, sizeof(TWOFISH_EXAM1_256BIT_KEY));

  twofish.encrypt(TWOFISH_EXAM1_256BIT_PLAINTEXT, ciphertext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TWOFISH_EXAM1_256BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  twofish.decrypt(ciphertext, plaintext);
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TWOFISH_EXAM1_256BIT_PLAINTEXT[i], plaintext[i]);
  }
}
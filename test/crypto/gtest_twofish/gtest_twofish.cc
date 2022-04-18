/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_twofish.h"

TEST_F(GTestTwofish, Normal_encrypt_to_decrypt_001) {
  cryptography::twofish twofish;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = "123456789ABCEFG";

  twofish.initialize(cryptography::TWOFISH, TWOFISH_EXAM1_128BIT_KEY, sizeof(TWOFISH_EXAM1_128BIT_KEY), false);

  twofish.encrypt(TWOFISH_EXAM1_PLAINTEXT, sizeof(TWOFISH_EXAM1_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TWOFISH_EXAM1_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  twofish.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TWOFISH_EXAM1_PLAINTEXT[i], plaintext[i]);
  }

}
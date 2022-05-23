/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_des.h"


TEST_F(GTestDes, Normal_DES_001) {
  cryptography::secret_key_cryptosystem<cryptography::des> des;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  des.initialize(DES_TEST_KEY_01, sizeof(DES_TEST_KEY_01));

  des.encrypt(DES_TEST_STRING_SINGLE_BYTE_STRING, ciphertext);
  des.decrypt(ciphertext, plaintext);

  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(DES_TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestDes, Normal_DES_002) {
  cryptography::secret_key_cryptosystem<cryptography::des> des;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  des.initialize(DES_TEST_KEY_01, sizeof(DES_TEST_KEY_01));

  des.encrypt(DES_TEST_STRING_MULTI_BYTE_STRING, ciphertext);
  des.decrypt(ciphertext, plaintext);

  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(DES_TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestDes, Normal_DES_003) {
  cryptography::secret_key_cryptosystem<cryptography::des> des;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  des.initialize(DES_TEST_KEY_01, sizeof(DES_TEST_KEY_01));

  des.encrypt(DES_TEST_STRING_U8_MULTI_BYTE_STRING, ciphertext);
  des.decrypt(ciphertext, plaintext);

  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(DES_TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}
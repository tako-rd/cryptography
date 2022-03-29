/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_des.h"

TEST_F(GTestDes, Normal_initialize_001) {
  cryptography::des des;

  des.initialize(cryptography::SIMPLE_DES, DES_TEST_KEY_01, sizeof(DES_TEST_KEY_01), false);
}

TEST_F(GTestDes, Normal_encrypt_001) {
  cryptography::des des;
  uint8_t ciphertext[8] = {0};

  des.initialize(cryptography::SIMPLE_DES, DES_TEST_KEY_01, sizeof(DES_TEST_KEY_01), false);

  des.encrypt(DES_TEST_PLAINTEXT_01, sizeof(DES_TEST_PLAINTEXT_01), ciphertext, sizeof(ciphertext));
}

TEST_F(GTestDes, Normal_decrypt_001) {
  cryptography::des des;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  des.initialize(cryptography::SIMPLE_DES, (uint8_t *)DES_TEST_KEY_03, sizeof(DES_TEST_KEY_03), false);

  des.encrypt(DES_TEST_PLAINTEXT_03, sizeof(DES_TEST_PLAINTEXT_03), ciphertext, sizeof(ciphertext));
  des.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(DES_TEST_PLAINTEXT_03[i], plaintext[i]);
  }
}

TEST_F(GTestDes, Normal_encrypt_to_decrypt_001) {
  cryptography::des des;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  des.initialize(cryptography::SIMPLE_DES, DES_TEST_KEY_01, sizeof(DES_TEST_KEY_01), false);

  des.encrypt(DES_TEST_STRING_SINGLE_BYTE_STRING, sizeof(DES_TEST_STRING_SINGLE_BYTE_STRING), ciphertext, sizeof(ciphertext));
  des.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(DES_TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestDes, Normal_encrypt_to_decrypt_002) {
  cryptography::des des;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  des.initialize(cryptography::SIMPLE_DES, DES_TEST_KEY_01, sizeof(DES_TEST_KEY_01), false);

  des.encrypt(DES_TEST_STRING_MULTI_BYTE_STRING, sizeof(DES_TEST_STRING_MULTI_BYTE_STRING), ciphertext, sizeof(ciphertext));
  des.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(DES_TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestDes, Normal_encrypt_to_decrypt_003) {
  cryptography::des des;
  uint8_t ciphertext[8] = {0};
  uint8_t plaintext[8] = {0};

  des.initialize(cryptography::SIMPLE_DES, DES_TEST_KEY_01, sizeof(DES_TEST_KEY_01), false);

  des.encrypt(DES_TEST_STRING_U8_MULTI_BYTE_STRING, sizeof(DES_TEST_STRING_U8_MULTI_BYTE_STRING), ciphertext, sizeof(ciphertext));
  des.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 8; ++i) {
    EXPECT_EQ(DES_TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}
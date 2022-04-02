/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_camellia128.h"

TEST_F(GTestCamellia128, Normal_encrypt_to_decrypt_001) {
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

TEST_F(GTestCamellia128, Normal_encrypt_to_decrypt_002) {
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

TEST_F(GTestCamellia128, Normal_encrypt_to_decrypt_003) {
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
#if 0
TEST_F(GTestCamellia128, calculate_sp32bit) {
  cryptography::camellia camellia;

  for (uint32_t i = 0; i < 4; ++i) {
    printf("-------- calculate %d sbox --------\n", i + 1);

    for (uint32_t j = 0; j <= 255; j += 4) {
      printf("%03d : 0x%08x, 0x%08x, 0x%08x, 0x%08x,\n", j, 
                                                         camellia.calculate_sp32bit(((uint8_t)j), i),
                                                         camellia.calculate_sp32bit(((uint8_t)j + 1), i),
                                                         camellia.calculate_sp32bit(((uint8_t)j + 2), i),
                                                         camellia.calculate_sp32bit(((uint8_t)j + 3), i));
    }
  }
}

TEST_F(GTestCamellia128, calculate_sp64bit) {
  cryptography::camellia camellia;
 
  for (uint32_t i = 0; i < 8; ++i) {
    printf("-------- calculate %d sbox --------\n", i + 1);

    for (uint32_t j = 0; j <= 255; j += 4) {
      printf("%03d : 0x%016llx, 0x%016llx, 0x%016llx, 0x%016llx,\n", j, 
                                                                     camellia.calculate_sp64bit(((uint8_t)j), i),
                                                                     camellia.calculate_sp64bit(((uint8_t)j + 1), i),
                                                                     camellia.calculate_sp64bit(((uint8_t)j + 2), i),
                                                                     camellia.calculate_sp64bit(((uint8_t)j + 3), i));
    }
  }
}
#endif
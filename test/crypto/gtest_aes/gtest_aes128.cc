/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_aes128.h"

#ifdef ENABLE_FUNCTIONS_FOR_GTEST
TEST_F(GTestAes128, Normal_initialize_001) {
  cryptography::aes aes;
  std::vector<uint8_t> subkeys;

  aes.initialize(cryptography::AES128, 
                 FIPS197_A1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_A1_128BIT_TEST_KEY), 
                 false);
  subkeys = aes.get_subkeys_for_unit_test();
  for (uint64_t i = 0; i < sizeof(FIPS197_A1_128BIT_TEST_SUB_KEY); ++i) {
    EXPECT_EQ(FIPS197_A1_128BIT_TEST_SUB_KEY[i], subkeys[i]);
  }
}

TEST_F(GTestAes128, Normal_initialize_002) {
  cryptography::aes aes;
  std::vector<uint8_t> subkeys;
  uint64_t keypos = 0;

  aes.initialize(cryptography::AES128, 
                 FIPS197_A1_128BIT_TEST_KEY,
                 sizeof(FIPS197_A1_128BIT_TEST_KEY), 
                 true);
  subkeys = aes.get_encskeys_for_unit_test();
  for (uint64_t i = 0; i < sizeof(FIPS197_A1_128BIT_TEST_SUB_KEY); ++i) {
    EXPECT_EQ(FIPS197_A1_128BIT_TEST_SUB_KEY[i], subkeys[i]);
  }
}
#endif

TEST_F(GTestAes128, Normal_encrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
              sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
              ciphertext, 
              sizeof(ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }
}

TEST_F(GTestAes128, Normal_encrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
              sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
              ciphertext, 
              sizeof(ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }
}

TEST_F(GTestAes128, Normal_decrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
              sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_decrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
              sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_encrypt_to_decrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.encrypt(TEST_STRING_SINGLE_BYTE_STRING, 
              sizeof(TEST_STRING_SINGLE_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_encrypt_to_decrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.encrypt(TEST_STRING_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_encrypt_to_decrypt_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.encrypt(TEST_STRING_U8_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_U8_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_encrypt_to_decrypt_004) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.encrypt(TEST_STRING_SINGLE_BYTE_STRING, 
              sizeof(TEST_STRING_SINGLE_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_encrypt_to_decrypt_005) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.encrypt(TEST_STRING_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_encrypt_to_decrypt_006) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.encrypt(TEST_STRING_U8_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_U8_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_no_intrinsic_encrypt_to_intrinsic_decrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.encrypt(TEST_STRING_SINGLE_BYTE_STRING, 
              sizeof(TEST_STRING_SINGLE_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_no_intrinsic_encrypt_to_intrinsic_decrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.encrypt(TEST_STRING_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_no_intrinsic_encrypt_to_intrinsic_decrypt_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.encrypt(TEST_STRING_U8_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_U8_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}


TEST_F(GTestAes128, Normal_intrinsic_encrypt_to_no_intrinsic_decrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.encrypt(TEST_STRING_SINGLE_BYTE_STRING, 
              sizeof(TEST_STRING_SINGLE_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_intrinsic_encrypt_to_no_intrinsic_decrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.encrypt(TEST_STRING_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes128, Normal_intrinsic_encrypt_to_no_intrinsic_decrypt_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 true);

  aes.encrypt(TEST_STRING_U8_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_U8_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES128, 
                 FIPS197_C1_128BIT_TEST_KEY, 
                 sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                 false);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}
#if 0
TEST_F(GTestAes128, generate_mixed_sbox) {
  cryptography::aes aes;

  for (int32_t i = 0; i < 4; ++i) {
    printf("--------- generate mixed sbox %d ---------\n", i + 1);
    for (int32_t j = 0; j < 256; j += 4) {
      printf("%03d : 0x%08x, 0x%08x, 0x%08x, 0x%08x,\n", j,
                                                         aes.calc_mixed_sbox(j, i),
                                                         aes.calc_mixed_sbox(j + 1, i),
                                                         aes.calc_mixed_sbox(j + 2, i),
                                                         aes.calc_mixed_sbox(j + 3, i));
    }
  }

}

TEST_F(GTestAes128, generate_mixed_invsbox) {
  cryptography::aes aes;

  for (int32_t i = 0; i < 4; ++i) {
    printf("--------- generate mixed invsbox %d ---------\n", i + 1);
    for (int32_t j = 0; j < 256; j += 4) {
      printf("%03d : 0x%08x, 0x%08x, 0x%08x, 0x%08x,\n", j,
                                                         aes.calc_mixed_invsbox(j, i),
                                                         aes.calc_mixed_invsbox(j + 1, i),
                                                         aes.calc_mixed_invsbox(j + 2, i),
                                                         aes.calc_mixed_invsbox(j + 3, i));
    }
  }
}
#endif
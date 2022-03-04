/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_aes192.h"

TEST_F(GTestAes192, Normal_initialize_001) {
  cryptography::aes aes;
  std::vector<uint8_t> subkeys;

  aes.initialize(cryptography::AES192, 
                 FIPS197_A2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_A2_192BIT_TEST_KEY), 
                 false);
  subkeys = aes.get_subkeys_for_unit_test();
  for (uint64_t i = 0; i < sizeof(FIPS197_A2_192BIT_TEST_KEY); ++i) {
    EXPECT_EQ(FIPS197_A2_192BIT_TEST_KEY[i], subkeys[i]);
  }
}

TEST_F(GTestAes192, Normal_initialize_002) {
  cryptography::aes aes;
  std::vector<uint8_t> subkeys;
  uint64_t keypos = 0;

  aes.initialize(cryptography::AES192, 
                 FIPS197_A2_192BIT_TEST_KEY,
                 sizeof(FIPS197_A2_192BIT_TEST_KEY), 
                 true);
  subkeys = aes.get_encskeys_for_unit_test();
  for (uint64_t i = 0; i < sizeof(FIPS197_A2_192BIT_TEST_KEY); ++i) {
    EXPECT_EQ(FIPS197_A2_192BIT_TEST_KEY[i], subkeys[i]);
  }
}

TEST_F(GTestAes192, Normal_encrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.encrypt((const char *)FIPS197_C2_192BIT_TEST_PLAINTEXT, 
              sizeof(FIPS197_C2_192BIT_TEST_PLAINTEXT),
              ciphertext, 
              sizeof(ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }
}

TEST_F(GTestAes192, Normal_encrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.encrypt((const char *)FIPS197_C2_192BIT_TEST_PLAINTEXT, 
              sizeof(FIPS197_C2_192BIT_TEST_PLAINTEXT),
              ciphertext, 
              sizeof(ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }
}

TEST_F(GTestAes192, Normal_decrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.encrypt((const char *)FIPS197_C2_192BIT_TEST_PLAINTEXT, 
              sizeof(FIPS197_C2_192BIT_TEST_PLAINTEXT),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ((char)FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_decrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.encrypt((const char *)FIPS197_C2_192BIT_TEST_PLAINTEXT, 
              sizeof(FIPS197_C2_192BIT_TEST_PLAINTEXT),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ((char)FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_encrypt_to_decrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.encrypt((const char *)TEST_STRING_SINGLE_BYTE_STRING, 
              sizeof(TEST_STRING_SINGLE_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_encrypt_to_decrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.encrypt((const char *)TEST_STRING_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_encrypt_to_decrypt_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.encrypt((const char *)TEST_STRING_U8_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_U8_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_encrypt_to_decrypt_004) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.encrypt((const char *)TEST_STRING_SINGLE_BYTE_STRING, 
              sizeof(TEST_STRING_SINGLE_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_encrypt_to_decrypt_005) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.encrypt((const char *)TEST_STRING_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_encrypt_to_decrypt_006) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.encrypt((const char *)TEST_STRING_U8_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_U8_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_no_intrinsic_encrypt_to_intrinsic_decrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.encrypt((const char *)TEST_STRING_SINGLE_BYTE_STRING, 
              sizeof(TEST_STRING_SINGLE_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_no_intrinsic_encrypt_to_intrinsic_decrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.encrypt((const char *)TEST_STRING_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_no_intrinsic_encrypt_to_intrinsic_decrypt_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.encrypt((const char *)TEST_STRING_U8_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_U8_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}


TEST_F(GTestAes192, Normal_intrinsic_encrypt_to_no_intrinsic_decrypt_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.encrypt((const char *)TEST_STRING_SINGLE_BYTE_STRING, 
              sizeof(TEST_STRING_SINGLE_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_SINGLE_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_intrinsic_encrypt_to_no_intrinsic_decrypt_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.encrypt((const char *)TEST_STRING_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}

TEST_F(GTestAes192, Normal_intrinsic_encrypt_to_no_intrinsic_decrypt_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  char plaintext[16];

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 true);

  aes.encrypt((const char *)TEST_STRING_U8_MULTI_BYTE_STRING, 
              sizeof(TEST_STRING_U8_MULTI_BYTE_STRING),
              ciphertext, 
              sizeof(ciphertext));

  aes.initialize(cryptography::AES192, 
                 FIPS197_C2_192BIT_TEST_KEY, 
                 sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                 false);

  aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(TEST_STRING_U8_MULTI_BYTE_STRING[i], plaintext[i]);
  }
}
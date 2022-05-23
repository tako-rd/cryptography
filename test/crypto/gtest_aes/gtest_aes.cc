/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_aes.h"

/****************************************/
/* AES encryption test with 128BIT Key. */
/****************************************/

TEST_F(GTestAes, Normal_AES128_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes> aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY)));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AESSIMD128_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes_simd> aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY)));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AESNI128_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes_ni> aes_ni;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes_ni.initialize(FIPS197_C1_128BIT_TEST_KEY, sizeof(FIPS197_C1_128BIT_TEST_KEY)));

  EXPECT_EQ(0, aes_ni.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_ni.decrypt(ciphertext, plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, SemiNormal_AES128_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes> aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];
  uint8_t invalid_key[4] = "AAA";

  EXPECT_EQ(1, aes.initialize(invalid_key, sizeof(invalid_key)));
  EXPECT_EQ(1, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, ciphertext));
  EXPECT_EQ(1, aes.decrypt(ciphertext, plaintext));
}

/****************************************/
/* AES encryption test with 192BIT Key. */
/****************************************/
TEST_F(GTestAes, Normal_AES192_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes> aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(FIPS197_C2_192BIT_TEST_KEY, sizeof(FIPS197_C2_192BIT_TEST_KEY)));
  EXPECT_EQ(0, aes.encrypt(FIPS197_C2_192BIT_TEST_PLAINTEXT, ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AESSIMD192_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes_simd> aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(FIPS197_C2_192BIT_TEST_KEY, sizeof(FIPS197_C2_192BIT_TEST_KEY)));
  EXPECT_EQ(0, aes.encrypt(FIPS197_C2_192BIT_TEST_PLAINTEXT, ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AESNI192_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes_ni> aes_ni;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes_ni.initialize(FIPS197_C2_192BIT_TEST_KEY, sizeof(FIPS197_C2_192BIT_TEST_KEY)));
  EXPECT_EQ(0, aes_ni.encrypt(FIPS197_C2_192BIT_TEST_PLAINTEXT, ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_ni.decrypt(ciphertext, plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

/****************************************/
/* AES encryption test with 256BIT Key. */
/****************************************/
TEST_F(GTestAes, Normal_AES256_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes> aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(FIPS197_C3_256BIT_TEST_KEY, sizeof(FIPS197_C3_256BIT_TEST_KEY)));
  EXPECT_EQ(0, aes.encrypt(FIPS197_C3_256BIT_TEST_PLAINTEXT, ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C3_256BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AESSIMD256_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes_simd> aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(FIPS197_C3_256BIT_TEST_KEY, sizeof(FIPS197_C3_256BIT_TEST_KEY)));
  EXPECT_EQ(0, aes.encrypt(FIPS197_C3_256BIT_TEST_PLAINTEXT, ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C3_256BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AESNI256_001) {
  cryptography::secret_key_cryptosystem<cryptography::aes_ni> aes_ni;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes_ni.initialize(FIPS197_C3_256BIT_TEST_KEY, sizeof(FIPS197_C3_256BIT_TEST_KEY)));
  EXPECT_EQ(0, aes_ni.encrypt(FIPS197_C3_256BIT_TEST_PLAINTEXT, ciphertext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C3_256BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_ni.decrypt(ciphertext, plaintext));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C3_256BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}
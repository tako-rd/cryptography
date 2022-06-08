/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ecb.h"

using namespace cryptography;

TEST_F(GTestECB, Normal_AES_ECB_001) {
  secret_key<AES, ECB> aes_ecb;
  uint8_t origin_text[64] = {0};
  uint8_t ciphertext[80] = {0};
  uint8_t plaintext[80] = {0};

  memcpy(origin_text, FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT, sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT));

  EXPECT_EQ(0, aes_ecb.initialize(FIPS197_C1_128BIT_BASED_TEST_KEY, sizeof(FIPS197_C1_128BIT_BASED_TEST_KEY), nullptr, 0));
  EXPECT_EQ(0, aes_ecb.encrypt(origin_text, sizeof(origin_text), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT); ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_BASED_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT); ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_AES_ECB_002) {
  secret_key<AES, ECB> aes_ecb;
  uint8_t ciphertext[464] = {0};
  uint8_t plaintext[464] = {0};

  EXPECT_EQ(0, aes_ecb.initialize(FIPS197_C1_128BIT_BASED_TEST_KEY, sizeof(FIPS197_C1_128BIT_BASED_TEST_KEY), nullptr, 0));
  EXPECT_EQ(0, aes_ecb.encrypt(ECB_PLAINTEXT_001, sizeof(ECB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, aes_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(ECB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_Camellia_ECB_001) {
  secret_key<Camellia, ECB> camellia_ecb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, camellia_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                       ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, camellia_ecb.encrypt(ECB_128BIT_PLAINTEXT, sizeof(ECB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(ECB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_Camellia_ECB_002) {
  secret_key<Camellia, ECB> camellia_ecb;
  uint8_t ciphertext[464] = {0};
  uint8_t plaintext[464] = {0};

  EXPECT_EQ(0, camellia_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                       ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, camellia_ecb.encrypt(ECB_PLAINTEXT_001, sizeof(ECB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(ECB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_CAST128_ECB_001) {
  secret_key<CAST128, ECB> cast128_ecb;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, cast128_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                      ECB_64BIT_IV, sizeof(ECB_64BIT_IV)));
  EXPECT_EQ(0, cast128_ecb.encrypt(ECB_64BIT_PLAINTEXT, sizeof(ECB_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(ECB_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_CAST128_ECB_002) {
  secret_key<CAST128, ECB> cast128_ecb;
  uint8_t ciphertext[464] = {0};
  uint8_t plaintext[464] = {0};

  EXPECT_EQ(0, cast128_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                      ECB_64BIT_IV, sizeof(ECB_64BIT_IV)));
  EXPECT_EQ(0, cast128_ecb.encrypt(ECB_PLAINTEXT_001, sizeof(ECB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(ECB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_CAST256_ECB_001) {
  secret_key<CAST256, ECB> cast256_ecb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, cast256_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                      ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, cast256_ecb.encrypt(ECB_128BIT_PLAINTEXT, sizeof(ECB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(ECB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_CAST256_ECB_002) {
  secret_key<CAST256, ECB> cast256_ecb;
  uint8_t ciphertext[464] = {0};
  uint8_t plaintext[464] = {0};

  EXPECT_EQ(0, cast256_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                      ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, cast256_ecb.encrypt(ECB_PLAINTEXT_001, sizeof(ECB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(ECB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_DES_ECB_001) {
  secret_key<DES, ECB> des_ecb;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, des_ecb.initialize(ECB_64BIT_KEY, sizeof(ECB_64BIT_KEY), 
                                  ECB_64BIT_IV, sizeof(ECB_64BIT_IV)));
  EXPECT_EQ(0, des_ecb.encrypt(ECB_64BIT_PLAINTEXT, sizeof(ECB_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(ECB_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_DES_ECB_002) {
  secret_key<DES, ECB> des_ecb;
  uint8_t ciphertext[464] = {0};
  uint8_t plaintext[464] = {0};

  EXPECT_EQ(0, des_ecb.initialize(ECB_64BIT_KEY, sizeof(ECB_64BIT_KEY), 
                                  ECB_64BIT_IV, sizeof(ECB_64BIT_IV)));
  EXPECT_EQ(0, des_ecb.encrypt(ECB_PLAINTEXT_001, sizeof(ECB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(ECB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_RC6_ECB_001) {
  secret_key<RC6, ECB> rc6_ecb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, rc6_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                  ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, rc6_ecb.encrypt(ECB_128BIT_PLAINTEXT, sizeof(ECB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(ECB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_RC6_ECB_002) {
  secret_key<CAST256, ECB> rc6_ecb;
  uint8_t ciphertext[464] = {0};
  uint8_t plaintext[464] = {0};

  EXPECT_EQ(0, rc6_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                  ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, rc6_ecb.encrypt(ECB_PLAINTEXT_001, sizeof(ECB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(ECB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_SEED_ECB_001) {
  secret_key<SEED, ECB> seed_ecb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, seed_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                   ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, seed_ecb.encrypt(ECB_128BIT_PLAINTEXT, sizeof(ECB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(ECB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_SEED_ECB_002) {
  secret_key<CAST256, ECB> seed_ecb;
  uint8_t ciphertext[464] = {0};
  uint8_t plaintext[464] = {0};

  EXPECT_EQ(0, seed_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                   ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, seed_ecb.encrypt(ECB_PLAINTEXT_001, sizeof(ECB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(ECB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_Twofish_ECB_001) {
  secret_key<Twofish, ECB> twofish_ecb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, twofish_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                      ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, twofish_ecb.encrypt(ECB_128BIT_PLAINTEXT, sizeof(ECB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(ECB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestECB, Normal_Twofish_ECB_002) {
  secret_key<Twofish, ECB> twofish_ecb;
  uint8_t ciphertext[464] = {0};
  uint8_t plaintext[464] = {0};

  EXPECT_EQ(0, twofish_ecb.initialize(ECB_128BIT_KEY, sizeof(ECB_128BIT_KEY), 
                                      ECB_128BIT_IV, sizeof(ECB_128BIT_IV)));
  EXPECT_EQ(0, twofish_ecb.encrypt(ECB_PLAINTEXT_001, sizeof(ECB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_ecb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(ECB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(ECB_PLAINTEXT_001[i], plaintext[i]);
  }
}
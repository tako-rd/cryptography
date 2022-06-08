/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ctr.h"

using namespace cryptography;

TEST_F(GTestCTR, Normal_AES_CTR_001) {
  secret_key<AES, CTR> aes_ctr;
  uint8_t ciphertext[80] = {0};
  uint8_t plaintext[80] = {0};

  EXPECT_EQ(0, aes_ctr.initialize(NIST_AES_CTR_EXAM_AES_KEY, sizeof(NIST_AES_CTR_EXAM_AES_KEY), 
                                  NIST_AES_CTR_EXAM_AES_IV, sizeof(NIST_AES_CTR_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_ctr.encrypt(NIST_AES_CTR_EXAM_PLAINTEXT, sizeof(NIST_AES_CTR_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CTR_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CTR_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CTR_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CTR_EXAM_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_AES_CTR_002) {
  secret_key<AES, CTR> aes_ctr;
  uint8_t ciphertext[480] = {0};
  uint8_t plaintext[480] = {0};

  EXPECT_EQ(0, aes_ctr.initialize(NIST_AES_CTR_EXAM_AES_KEY, sizeof(NIST_AES_CTR_EXAM_AES_KEY), 
                                  NIST_AES_CTR_EXAM_AES_IV, sizeof(NIST_AES_CTR_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_ctr.encrypt(CTR_PLAINTEXT_001, sizeof(CTR_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, aes_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CTR_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_Camellia_CTR_001) {
  secret_key<Camellia, CTR> camellia_ctr;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, camellia_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                       CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, camellia_ctr.encrypt(CTR_128BIT_PLAINTEXT, sizeof(CTR_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CTR_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_Camellia_CTR_002) {
  secret_key<Camellia, CTR> camellia_ctr;
  uint8_t ciphertext[480] = {0};
  uint8_t plaintext[480] = {0};

  EXPECT_EQ(0, camellia_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                       CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, camellia_ctr.encrypt(CTR_PLAINTEXT_001, sizeof(CTR_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CTR_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_CAST128_CTR_001) {
  secret_key<CAST128, CTR> cast128_ctr;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, cast128_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                      CTR_64BIT_IV, sizeof(CTR_64BIT_IV)));
  EXPECT_EQ(0, cast128_ctr.encrypt(CTR_64BIT_PLAINTEXT, sizeof(CTR_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CTR_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_CAST128_CTR_002) {
  secret_key<CAST128, CTR> cast128_ctr;
  uint8_t ciphertext[472] = {0};
  uint8_t plaintext[472] = {0};

  EXPECT_EQ(0, cast128_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                      CTR_64BIT_IV, sizeof(CTR_64BIT_IV)));
  EXPECT_EQ(0, cast128_ctr.encrypt(CTR_PLAINTEXT_001, sizeof(CTR_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CTR_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_CAST256_CTR_001) {
  secret_key<CAST256, CTR> cast256_ctr;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, cast256_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                      CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, cast256_ctr.encrypt(CTR_128BIT_PLAINTEXT, sizeof(CTR_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CTR_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_CAST256_CTR_002) {
  secret_key<CAST256, CTR> cast256_ctr;
  uint8_t ciphertext[480] = {0};
  uint8_t plaintext[480] = {0};

  EXPECT_EQ(0, cast256_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                      CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, cast256_ctr.encrypt(CTR_PLAINTEXT_001, sizeof(CTR_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CTR_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_DES_CTR_001) {
  secret_key<DES, CTR> des_ctr;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, des_ctr.initialize(CTR_64BIT_KEY, sizeof(CTR_64BIT_KEY), 
                                  CTR_64BIT_IV, sizeof(CTR_64BIT_IV)));
  EXPECT_EQ(0, des_ctr.encrypt(CTR_64BIT_PLAINTEXT, sizeof(CTR_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CTR_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_DES_CTR_002) {
  secret_key<DES, CTR> des_ctr;
  uint8_t ciphertext[472] = {0};
  uint8_t plaintext[472] = {0};

  EXPECT_EQ(0, des_ctr.initialize(CTR_64BIT_KEY, sizeof(CTR_64BIT_KEY), 
                                  CTR_64BIT_IV, sizeof(CTR_64BIT_IV)));
  EXPECT_EQ(0, des_ctr.encrypt(CTR_PLAINTEXT_001, sizeof(CTR_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CTR_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_RC6_CTR_001) {
  secret_key<RC6, CTR> rc6_ctr;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, rc6_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                  CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, rc6_ctr.encrypt(CTR_128BIT_PLAINTEXT, sizeof(CTR_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CTR_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_RC6_CTR_002) {
  secret_key<CAST256, CTR> rc6_ctr;
  uint8_t ciphertext[480] = {0};
  uint8_t plaintext[480] = {0};

  EXPECT_EQ(0, rc6_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                  CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, rc6_ctr.encrypt(CTR_PLAINTEXT_001, sizeof(CTR_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CTR_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_SEED_CTR_001) {
  secret_key<SEED, CTR> seed_ctr;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, seed_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                   CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, seed_ctr.encrypt(CTR_128BIT_PLAINTEXT, sizeof(CTR_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CTR_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_SEED_CTR_002) {
  secret_key<CAST256, CTR> seed_ctr;
  uint8_t ciphertext[480] = {0};
  uint8_t plaintext[480] = {0};

  EXPECT_EQ(0, seed_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                   CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, seed_ctr.encrypt(CTR_PLAINTEXT_001, sizeof(CTR_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CTR_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_Twofish_CTR_001) {
  secret_key<Twofish, CTR> twofish_ctr;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, twofish_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                      CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, twofish_ctr.encrypt(CTR_128BIT_PLAINTEXT, sizeof(CTR_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CTR_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCTR, Normal_Twofish_CTR_002) {
  secret_key<Twofish, CTR> twofish_ctr;
  uint8_t ciphertext[480] = {0};
  uint8_t plaintext[480] = {0};

  EXPECT_EQ(0, twofish_ctr.initialize(CTR_128BIT_KEY, sizeof(CTR_128BIT_KEY), 
                                      CTR_128BIT_IV, sizeof(CTR_128BIT_IV)));
  EXPECT_EQ(0, twofish_ctr.encrypt(CTR_PLAINTEXT_001, sizeof(CTR_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_ctr.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CTR_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CTR_PLAINTEXT_001[i], plaintext[i]);
  }
}
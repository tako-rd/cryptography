/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_cbc.h"

using namespace cryptography;

TEST_F(GTestCBC, Normal_AES_CBC_001) {
  secret_key<AES, CBC> aes_cbc;
  uint8_t ciphertext[80] = {0};
  uint8_t plaintext[80] = {0};

  EXPECT_EQ(0, aes_cbc.initialize(NIST_AES_CBC_EXAM_AES_KEY, sizeof(NIST_AES_CBC_EXAM_AES_KEY), 
                                  NIST_AES_CBC_EXAM_AES_IV, sizeof(NIST_AES_CBC_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_cbc.encrypt(NIST_AES_CBC_EXAM_PLAINTEXT, sizeof(NIST_AES_CBC_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CBC_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CBC_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CBC_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CBC_EXAM_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_AES_CBC_002) {
  secret_key<AES, CBC> aes_cbc;
  uint8_t ciphertext[128] = {0};
  uint8_t plaintext[128] = {0};

  EXPECT_EQ(0, aes_cbc.initialize(NIST_AES_CBC_EXAM_AES_KEY, sizeof(NIST_AES_CBC_EXAM_AES_KEY), 
                                  NIST_AES_CBC_EXAM_AES_IV, sizeof(NIST_AES_CBC_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_cbc.encrypt(CBC_PLAINTEXT_001, sizeof(CBC_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, aes_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CBC_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_Camellia_CBC_001) {
  secret_key<Camellia, CBC> camellia_cbc;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, camellia_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                       CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, camellia_cbc.encrypt(CBC_128BIT_PLAINTEXT, sizeof(CBC_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CBC_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_Camellia_CBC_002) {
  secret_key<Camellia, CBC> camellia_cbc;
  uint8_t ciphertext[128] = {0};
  uint8_t plaintext[128] = {0};

  EXPECT_EQ(0, camellia_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                       CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, camellia_cbc.encrypt(CBC_PLAINTEXT_001, sizeof(CBC_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CBC_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_CAST128_CBC_001) {
  secret_key<CAST128, CBC> cast128_cbc;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, cast128_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                      CBC_64BIT_IV, sizeof(CBC_64BIT_IV)));
  EXPECT_EQ(0, cast128_cbc.encrypt(CBC_64BIT_PLAINTEXT, sizeof(CBC_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CBC_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_CAST128_CBC_002) {
  secret_key<CAST128, CBC> cast128_cbc;
  uint8_t ciphertext[120] = {0};
  uint8_t plaintext[120] = {0};

  EXPECT_EQ(0, cast128_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                      CBC_64BIT_IV, sizeof(CBC_64BIT_IV)));
  EXPECT_EQ(0, cast128_cbc.encrypt(CBC_PLAINTEXT_001, sizeof(CBC_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CBC_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_CAST256_CBC_001) {
  secret_key<CAST256, CBC> cast256_cbc;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, cast256_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                      CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, cast256_cbc.encrypt(CBC_128BIT_PLAINTEXT, sizeof(CBC_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CBC_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_CAST256_CBC_002) {
  secret_key<CAST256, CBC> cast256_cbc;
  uint8_t ciphertext[128] = {0};
  uint8_t plaintext[128] = {0};

  EXPECT_EQ(0, cast256_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                      CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, cast256_cbc.encrypt(CBC_PLAINTEXT_001, sizeof(CBC_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CBC_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_DES_CBC_001) {
  secret_key<DES, CBC> des_cbc;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, des_cbc.initialize(CBC_64BIT_KEY, sizeof(CBC_64BIT_KEY), 
                                  CBC_64BIT_IV, sizeof(CBC_64BIT_IV)));
  EXPECT_EQ(0, des_cbc.encrypt(CBC_64BIT_PLAINTEXT, sizeof(CBC_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CBC_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_DES_CBC_002) {
  secret_key<DES, CBC> des_cbc;
  uint8_t ciphertext[120] = {0};
  uint8_t plaintext[120] = {0};

  EXPECT_EQ(0, des_cbc.initialize(CBC_64BIT_KEY, sizeof(CBC_64BIT_KEY), 
                                  CBC_64BIT_IV, sizeof(CBC_64BIT_IV)));
  EXPECT_EQ(0, des_cbc.encrypt(CBC_PLAINTEXT_001, sizeof(CBC_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CBC_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_RC6_CBC_001) {
  secret_key<RC6, CBC> rc6_cbc;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, rc6_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                  CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, rc6_cbc.encrypt(CBC_128BIT_PLAINTEXT, sizeof(CBC_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CBC_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_RC6_CBC_002) {
  secret_key<CAST256, CBC> rc6_cbc;
  uint8_t ciphertext[128] = {0};
  uint8_t plaintext[128] = {0};

  EXPECT_EQ(0, rc6_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                  CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, rc6_cbc.encrypt(CBC_PLAINTEXT_001, sizeof(CBC_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CBC_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_SEED_CBC_001) {
  secret_key<SEED, CBC> seed_cbc;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, seed_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                  CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, seed_cbc.encrypt(CBC_128BIT_PLAINTEXT, sizeof(CBC_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CBC_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_SEED_CBC_002) {
  secret_key<CAST256, CBC> seed_cbc;
  uint8_t ciphertext[128] = {0};
  uint8_t plaintext[128] = {0};

  EXPECT_EQ(0, seed_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                  CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, seed_cbc.encrypt(CBC_PLAINTEXT_001, sizeof(CBC_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CBC_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_Twofish_CBC_001) {
  secret_key<Twofish, CBC> twofish_cbc;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, twofish_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                   CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, twofish_cbc.encrypt(CBC_128BIT_PLAINTEXT, sizeof(CBC_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CBC_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCBC, Normal_Twofish_CBC_002) {
  secret_key<Twofish, CBC> twofish_cbc;
  uint8_t ciphertext[128] = {0};
  uint8_t plaintext[128] = {0};

  EXPECT_EQ(0, twofish_cbc.initialize(CBC_128BIT_KEY, sizeof(CBC_128BIT_KEY), 
                                   CBC_128BIT_IV, sizeof(CBC_128BIT_IV)));
  EXPECT_EQ(0, twofish_cbc.encrypt(CBC_PLAINTEXT_001, sizeof(CBC_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_cbc.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CBC_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CBC_PLAINTEXT_001[i], plaintext[i]);
  }
}
/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_cfb.h"

using namespace cryptography;

TEST_F(GTestCFB, Normal_AES_CFB_001) {
  secret_key<AES, CFB> aes_cfb;
  uint8_t ciphertext[80] = {0};
  uint8_t plaintext[80] = {0};

  EXPECT_EQ(0, aes_cfb.initialize(NIST_AES_CFB_EXAM_AES_KEY, sizeof(NIST_AES_CFB_EXAM_AES_KEY), 
                                  NIST_AES_CFB_EXAM_AES_IV, sizeof(NIST_AES_CFB_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_cfb.encrypt(NIST_AES_CFB_EXAM_PLAINTEXT, sizeof(NIST_AES_CFB_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CFB_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CFB_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CFB_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CFB_EXAM_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_AES_CFB_002) {
  secret_key<AES, CFB> aes_cfb;
  uint8_t ciphertext[624] = {0};
  uint8_t plaintext[624] = {0};

  EXPECT_EQ(0, aes_cfb.initialize(NIST_AES_CFB_EXAM_AES_KEY, sizeof(NIST_AES_CFB_EXAM_AES_KEY), 
                                  NIST_AES_CFB_EXAM_AES_IV, sizeof(NIST_AES_CFB_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_cfb.encrypt(CFB_PLAINTEXT_001, sizeof(CFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, aes_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_Camellia_CFB_001) {
  secret_key<Camellia, CFB> camellia_cfb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, camellia_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                       CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, camellia_cfb.encrypt(CFB_128BIT_PLAINTEXT, sizeof(CFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_Camellia_CFB_002) {
  secret_key<Camellia, CFB> camellia_cfb;
  uint8_t ciphertext[624] = {0};
  uint8_t plaintext[624] = {0};

  EXPECT_EQ(0, camellia_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                       CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, camellia_cfb.encrypt(CFB_PLAINTEXT_001, sizeof(CFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_CAST128_CFB_001) {
  secret_key<CAST128, CFB> cast128_cfb;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, cast128_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                      CFB_64BIT_IV, sizeof(CFB_64BIT_IV)));
  EXPECT_EQ(0, cast128_cfb.encrypt(CFB_64BIT_PLAINTEXT, sizeof(CFB_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CFB_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_CAST128_CFB_002) {
  secret_key<CAST128, CFB> cast128_cfb;
  uint8_t ciphertext[616] = {0};
  uint8_t plaintext[616] = {0};

  EXPECT_EQ(0, cast128_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                      CFB_64BIT_IV, sizeof(CFB_64BIT_IV)));
  EXPECT_EQ(0, cast128_cfb.encrypt(CFB_PLAINTEXT_001, sizeof(CFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_CAST256_CFB_001) {
  secret_key<CAST256, CFB> cast256_cfb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, cast256_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                      CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, cast256_cfb.encrypt(CFB_128BIT_PLAINTEXT, sizeof(CFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_CAST256_CFB_002) {
  secret_key<CAST256, CFB> cast256_cfb;
  uint8_t ciphertext[624] = {0};
  uint8_t plaintext[624] = {0};

  EXPECT_EQ(0, cast256_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                      CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, cast256_cfb.encrypt(CFB_PLAINTEXT_001, sizeof(CFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_DES_CFB_001) {
  secret_key<DES, CFB> des_cfb;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, des_cfb.initialize(CFB_64BIT_KEY, sizeof(CFB_64BIT_KEY), 
                                  CFB_64BIT_IV, sizeof(CFB_64BIT_IV)));
  EXPECT_EQ(0, des_cfb.encrypt(CFB_64BIT_PLAINTEXT, sizeof(CFB_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CFB_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_DES_CFB_002) {
  secret_key<DES, CFB> des_cfb;
  uint8_t ciphertext[616] = {0};
  uint8_t plaintext[616] = {0};

  EXPECT_EQ(0, des_cfb.initialize(CFB_64BIT_KEY, sizeof(CFB_64BIT_KEY), 
                                  CFB_64BIT_IV, sizeof(CFB_64BIT_IV)));
  EXPECT_EQ(0, des_cfb.encrypt(CFB_PLAINTEXT_001, sizeof(CFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_RC6_CFB_001) {
  secret_key<RC6, CFB> rc6_cfb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, rc6_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                  CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, rc6_cfb.encrypt(CFB_128BIT_PLAINTEXT, sizeof(CFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_RC6_CFB_002) {
  secret_key<CAST256, CFB> rc6_cfb;
  uint8_t ciphertext[624] = {0};
  uint8_t plaintext[624] = {0};

  EXPECT_EQ(0, rc6_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                  CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, rc6_cfb.encrypt(CFB_PLAINTEXT_001, sizeof(CFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_SEED_CFB_001) {
  secret_key<SEED, CFB> seed_cfb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, seed_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                   CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, seed_cfb.encrypt(CFB_128BIT_PLAINTEXT, sizeof(CFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_SEED_CFB_002) {
  secret_key<CAST256, CFB> seed_cfb;
  uint8_t ciphertext[624] = {0};
  uint8_t plaintext[624] = {0};

  EXPECT_EQ(0, seed_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                   CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, seed_cfb.encrypt(CFB_PLAINTEXT_001, sizeof(CFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_Twofish_CFB_001) {
  secret_key<Twofish, CFB> twofish_cfb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, twofish_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                      CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, twofish_cfb.encrypt(CFB_128BIT_PLAINTEXT, sizeof(CFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(CFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestCFB, Normal_Twofish_CFB_002) {
  secret_key<Twofish, CFB> twofish_cfb;
  uint8_t ciphertext[624] = {0};
  uint8_t plaintext[624] = {0};

  EXPECT_EQ(0, twofish_cfb.initialize(CFB_128BIT_KEY, sizeof(CFB_128BIT_KEY), 
                                      CFB_128BIT_IV, sizeof(CFB_128BIT_IV)));
  EXPECT_EQ(0, twofish_cfb.encrypt(CFB_PLAINTEXT_001, sizeof(CFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_cfb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(CFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(CFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

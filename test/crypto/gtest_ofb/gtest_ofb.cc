/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ofb.h"

using namespace cryptography;

TEST_F(GTestOFB, Normal_AES_OFB_001) {
  secret_key<AES, OFB> aes_ofb;
  uint8_t ciphertext[80] = {0};
  uint8_t plaintext[80] = {0};

  EXPECT_EQ(0, aes_ofb.initialize(NIST_AES_OFB_EXAM_AES_KEY, sizeof(NIST_AES_OFB_EXAM_AES_KEY), 
                                  NIST_AES_OFB_EXAM_AES_IV, sizeof(NIST_AES_OFB_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_ofb.encrypt(NIST_AES_OFB_EXAM_PLAINTEXT, sizeof(NIST_AES_OFB_EXAM_PLAINTEXT), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_OFB_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_OFB_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_OFB_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_OFB_EXAM_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_AES_OFB_002) {
  secret_key<AES, OFB> aes_ofb;
  uint8_t ciphertext[608] = {0};
  uint8_t plaintext[608] = {0};

  EXPECT_EQ(0, aes_ofb.initialize(NIST_AES_OFB_EXAM_AES_KEY, sizeof(NIST_AES_OFB_EXAM_AES_KEY), 
                                  NIST_AES_OFB_EXAM_AES_IV, sizeof(NIST_AES_OFB_EXAM_AES_IV)));
  EXPECT_EQ(0, aes_ofb.encrypt(OFB_PLAINTEXT_001, sizeof(OFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, aes_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(OFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_Camellia_OFB_001) {
  secret_key<Camellia, OFB> camellia_ofb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, camellia_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                       OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, camellia_ofb.encrypt(OFB_128BIT_PLAINTEXT, sizeof(OFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(OFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_Camellia_OFB_002) {
  secret_key<Camellia, OFB> camellia_ofb;
  uint8_t ciphertext[608] = {0};
  uint8_t plaintext[608] = {0};

  EXPECT_EQ(0, camellia_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                       OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, camellia_ofb.encrypt(OFB_PLAINTEXT_001, sizeof(OFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, camellia_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(OFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_CAST128_OFB_001) {
  secret_key<CAST128, OFB> cast128_ofb;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, cast128_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                      OFB_64BIT_IV, sizeof(OFB_64BIT_IV)));
  EXPECT_EQ(0, cast128_ofb.encrypt(OFB_64BIT_PLAINTEXT, sizeof(OFB_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(OFB_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_CAST128_OFB_002) {
  secret_key<CAST128, OFB> cast128_ofb;
  uint8_t ciphertext[608] = {0};
  uint8_t plaintext[608] = {0};

  EXPECT_EQ(0, cast128_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                      OFB_64BIT_IV, sizeof(OFB_64BIT_IV)));
  EXPECT_EQ(0, cast128_ofb.encrypt(OFB_PLAINTEXT_001, sizeof(OFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast128_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(OFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_CAST256_OFB_001) {
  secret_key<CAST256, OFB> cast256_ofb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, cast256_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                      OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, cast256_ofb.encrypt(OFB_128BIT_PLAINTEXT, sizeof(OFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(OFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_CAST256_OFB_002) {
  secret_key<CAST256, OFB> cast256_ofb;
  uint8_t ciphertext[608] = {0};
  uint8_t plaintext[608] = {0};

  EXPECT_EQ(0, cast256_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                      OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, cast256_ofb.encrypt(OFB_PLAINTEXT_001, sizeof(OFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, cast256_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(OFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_DES_OFB_001) {
  secret_key<DES, OFB> des_ofb;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  EXPECT_EQ(0, des_ofb.initialize(OFB_64BIT_KEY, sizeof(OFB_64BIT_KEY), 
                                  OFB_64BIT_IV, sizeof(OFB_64BIT_IV)));
  EXPECT_EQ(0, des_ofb.encrypt(OFB_64BIT_PLAINTEXT, sizeof(OFB_64BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_64BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(OFB_64BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_DES_OFB_002) {
  secret_key<DES, OFB> des_ofb;
  uint8_t ciphertext[608] = {0};
  uint8_t plaintext[608] = {0};

  EXPECT_EQ(0, des_ofb.initialize(OFB_64BIT_KEY, sizeof(OFB_64BIT_KEY), 
                                  OFB_64BIT_IV, sizeof(OFB_64BIT_IV)));
  EXPECT_EQ(0, des_ofb.encrypt(OFB_PLAINTEXT_001, sizeof(OFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, des_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(OFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_RC6_OFB_001) {
  secret_key<RC6, OFB> rc6_ofb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, rc6_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                  OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, rc6_ofb.encrypt(OFB_128BIT_PLAINTEXT, sizeof(OFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(OFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_RC6_OFB_002) {
  secret_key<CAST256, OFB> rc6_ofb;
  uint8_t ciphertext[608] = {0};
  uint8_t plaintext[608] = {0};

  EXPECT_EQ(0, rc6_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                  OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, rc6_ofb.encrypt(OFB_PLAINTEXT_001, sizeof(OFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, rc6_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(OFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_SEED_OFB_001) {
  secret_key<SEED, OFB> seed_ofb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, seed_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                   OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, seed_ofb.encrypt(OFB_128BIT_PLAINTEXT, sizeof(OFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(OFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_SEED_OFB_002) {
  secret_key<CAST256, OFB> seed_ofb;
  uint8_t ciphertext[608] = {0};
  uint8_t plaintext[608] = {0};

  EXPECT_EQ(0, seed_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                   OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, seed_ofb.encrypt(OFB_PLAINTEXT_001, sizeof(OFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, seed_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(OFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_Twofish_OFB_001) {
  secret_key<Twofish, OFB> twofish_ofb;
  uint8_t ciphertext[32] = {0};
  uint8_t plaintext[32] = {0};

  EXPECT_EQ(0, twofish_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                      OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, twofish_ofb.encrypt(OFB_128BIT_PLAINTEXT, sizeof(OFB_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_128BIT_PLAINTEXT); ++i) {
    EXPECT_EQ(OFB_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestOFB, Normal_Twofish_OFB_002) {
  secret_key<Twofish, OFB> twofish_ofb;
  uint8_t ciphertext[608] = {0};
  uint8_t plaintext[608] = {0};

  EXPECT_EQ(0, twofish_ofb.initialize(OFB_128BIT_KEY, sizeof(OFB_128BIT_KEY), 
                                      OFB_128BIT_IV, sizeof(OFB_128BIT_IV)));
  EXPECT_EQ(0, twofish_ofb.encrypt(OFB_PLAINTEXT_001, sizeof(OFB_PLAINTEXT_001), ciphertext, sizeof(ciphertext)));
  EXPECT_EQ(0, twofish_ofb.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (int32_t i = 0; i < sizeof(OFB_PLAINTEXT_001); ++i) {
    EXPECT_EQ(OFB_PLAINTEXT_001[i], plaintext[i]);
  }
}

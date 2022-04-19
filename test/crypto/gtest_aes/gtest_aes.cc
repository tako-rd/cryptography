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
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AES128_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AES128_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AES128_004) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C1_128BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, SemiNormal_AES128_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];
  uint8_t invalid_key[4] = "AAA";

  EXPECT_EQ(1, aes.initialize(cryptography::AES128, 
                              invalid_key, 
                              sizeof(invalid_key), 
                              false));

  EXPECT_EQ(1, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  EXPECT_EQ(1, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));
}

TEST_F(GTestAes, SemiNormal_AES128_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];
  uint8_t invalid_key[4] = "AAA";

  EXPECT_EQ(1, aes.initialize(cryptography::AES128, 
                              invalid_key, 
                              sizeof(invalid_key), 
                              true));

  EXPECT_EQ(1, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  EXPECT_EQ(1, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));
}

TEST_F(GTestAes, SemiNormal_AES128_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(1, aes.initialize(cryptography::AES192, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(1, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  EXPECT_EQ(1, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));
}

TEST_F(GTestAes, SemiNormal_AES128_004) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(1, aes.initialize(cryptography::AES192, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(1, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  EXPECT_EQ(1, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));
}

TEST_F(GTestAes, SemiNormal_AES128_005) {
  cryptography::aes aes;
  uint8_t ciphertext[8];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(1, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  EXPECT_EQ(1, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));
}

TEST_F(GTestAes, SemiNormal_AES128_006) {
  cryptography::aes aes;
  uint8_t ciphertext[8];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(1, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  EXPECT_EQ(1, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));
}

TEST_F(GTestAes, SemiNormal_AES128_007) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[8];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  EXPECT_EQ(1, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));
}

TEST_F(GTestAes, SemiNormal_AES128_008) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[8];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C1_128BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C1_128BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  EXPECT_EQ(1, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));
}

TEST_F(GTestAes, SemiNormal_AES128_009) {
  cryptography::aes aes;
  uint8_t invalid_plaintext[8] = "ABCDEFG";
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(1, aes.encrypt(invalid_plaintext, 
                           sizeof(invalid_plaintext),
                           ciphertext, 
                           sizeof(ciphertext)));
}

TEST_F(GTestAes, SemiNormal_AES128_010) {
  cryptography::aes aes;
  uint8_t invalid_plaintext[8] = "ABCDEFG";
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES128, 
                              FIPS197_C1_128BIT_TEST_KEY, 
                              sizeof(FIPS197_C1_128BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(1, aes.encrypt(invalid_plaintext, 
                           sizeof(invalid_plaintext),
                           ciphertext, 
                           sizeof(ciphertext)));
}

/****************************************/
/* AES encryption test with 192BIT Key. */
/****************************************/
TEST_F(GTestAes, Normal_AES192_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES192, 
                              FIPS197_C2_192BIT_TEST_KEY, 
                              sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C2_192BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C2_192BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AES192_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES192, 
                              FIPS197_C2_192BIT_TEST_KEY, 
                              sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C2_192BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C2_192BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AES192_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES192, 
                              FIPS197_C2_192BIT_TEST_KEY, 
                              sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C2_192BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C2_192BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.initialize(cryptography::AES192, 
                              FIPS197_C2_192BIT_TEST_KEY, 
                              sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AES192_004) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES192, 
                              FIPS197_C2_192BIT_TEST_KEY, 
                              sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C2_192BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C2_192BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.initialize(cryptography::AES192, 
                              FIPS197_C2_192BIT_TEST_KEY, 
                              sizeof(FIPS197_C2_192BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

/****************************************/
/* AES encryption test with 256BIT Key. */
/****************************************/
TEST_F(GTestAes, Normal_AES256_001) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES256, 
                              FIPS197_C3_256BIT_TEST_KEY, 
                              sizeof(FIPS197_C3_256BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C3_256BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C3_256BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C3_256BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AES256_002) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES256, 
                              FIPS197_C3_256BIT_TEST_KEY, 
                              sizeof(FIPS197_C3_256BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C3_256BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C3_256BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C3_256BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AES256_003) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES256, 
                              FIPS197_C3_256BIT_TEST_KEY, 
                              sizeof(FIPS197_C3_256BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C3_256BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C3_256BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C3_256BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.initialize(cryptography::AES256, 
                              FIPS197_C3_256BIT_TEST_KEY, 
                              sizeof(FIPS197_C3_256BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C2_192BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestAes, Normal_AES256_004) {
  cryptography::aes aes;
  uint8_t ciphertext[16];
  uint8_t plaintext[16];

  EXPECT_EQ(0, aes.initialize(cryptography::AES256, 
                              FIPS197_C3_256BIT_TEST_KEY, 
                              sizeof(FIPS197_C3_256BIT_TEST_KEY), 
                              true));

  EXPECT_EQ(0, aes.encrypt(FIPS197_C3_256BIT_TEST_PLAINTEXT, 
                           sizeof(FIPS197_C3_256BIT_TEST_PLAINTEXT),
                           ciphertext, 
                           sizeof(ciphertext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C3_256BIT_TEST_CIPHERTEXT[i], ciphertext[i]);
  }

  EXPECT_EQ(0, aes.initialize(cryptography::AES256, 
                              FIPS197_C3_256BIT_TEST_KEY, 
                              sizeof(FIPS197_C3_256BIT_TEST_KEY), 
                              false));

  EXPECT_EQ(0, aes.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext)));

  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(FIPS197_C3_256BIT_TEST_PLAINTEXT[i], plaintext[i]);
  }
}
/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_rc6.h"

TEST_F(GTestRC6, Normal_RC6_128_001) {
  cryptography::rc6 rc6;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  rc6.initialize(cryptography::RC6_128, RC6_EXAM1_128BIT_KEY, sizeof(RC6_EXAM1_128BIT_KEY), false);

  rc6.encrypt(RC6_EXAM1_128BIT_PLAINTEXT, sizeof(RC6_EXAM1_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM1_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  rc6.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM1_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestRC6, Normal_RC6_128_002) {
  cryptography::rc6 rc6;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  rc6.initialize(cryptography::RC6_128, RC6_EXAM2_128BIT_KEY, sizeof(RC6_EXAM2_128BIT_KEY), false);

  rc6.encrypt(RC6_EXAM2_128BIT_PLAINTEXT, sizeof(RC6_EXAM2_128BIT_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM2_128BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  rc6.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM2_128BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestRC6, Normal_RC6_192_001) {
  cryptography::rc6 rc6;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  rc6.initialize(cryptography::RC6_128, RC6_EXAM1_192BIT_KEY, sizeof(RC6_EXAM1_192BIT_KEY), false);

  rc6.encrypt(RC6_EXAM1_192BIT_PLAINTEXT, sizeof(RC6_EXAM1_192BIT_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM1_192BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  rc6.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM1_192BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestRC6, Normal_RC6_192_002) {
  cryptography::rc6 rc6;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  rc6.initialize(cryptography::RC6_128, RC6_EXAM2_192BIT_KEY, sizeof(RC6_EXAM2_192BIT_KEY), false);

  rc6.encrypt(RC6_EXAM2_192BIT_PLAINTEXT, sizeof(RC6_EXAM2_192BIT_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM2_192BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  rc6.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM2_192BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestRC6, Normal_RC6_256_001) {
  cryptography::rc6 rc6;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  rc6.initialize(cryptography::RC6_128, RC6_EXAM1_256BIT_KEY, sizeof(RC6_EXAM1_256BIT_KEY), false);

  rc6.encrypt(RC6_EXAM1_256BIT_PLAINTEXT, sizeof(RC6_EXAM1_256BIT_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM1_256BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  rc6.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM1_256BIT_PLAINTEXT[i], plaintext[i]);
  }
}

TEST_F(GTestRC6, Normal_RC6_256_002) {
  cryptography::rc6 rc6;
  uint8_t ciphertext[16] = {0};
  uint8_t plaintext[16] = {0};

  rc6.initialize(cryptography::RC6_128, RC6_EXAM2_256BIT_KEY, sizeof(RC6_EXAM2_256BIT_KEY), false);

  rc6.encrypt(RC6_EXAM2_256BIT_PLAINTEXT, sizeof(RC6_EXAM2_256BIT_PLAINTEXT), ciphertext, sizeof(ciphertext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM2_256BIT_CIPHERTEXT[i], ciphertext[i]);
  }

  rc6.decrypt(ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
  for (uint64_t i = 0; i < 16; ++i) {
    EXPECT_EQ(RC6_EXAM2_256BIT_PLAINTEXT[i], plaintext[i]);
  }
}


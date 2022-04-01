/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ctr.h"

TEST_F(GTestCtr, Normal_aes_ctr_encrypt_001) {
  cryptography::ctr ctr;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t iv[16] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t out_str[64] = {0};

  memcpy(origin_text, NIST_AES_CTR_EXAM_PLAINTEXT, sizeof(NIST_AES_CTR_EXAM_PLAINTEXT));
  memcpy(iv, NIST_AES_CTR_EXAM_AES_IV, sizeof(NIST_AES_CTR_EXAM_AES_IV));

  aes.initialize(cryptography::AES128, NIST_AES_CTR_EXAM_AES_KEY, sizeof(NIST_AES_CTR_EXAM_AES_KEY), false);
  ctr.initialize(cryptography::AES128, (uint8_t *)iv, sizeof(iv));
  do {
    ctr.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt(str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == ctr.enc_postprocess(cstr, sizeof(cstr), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CTR_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CTR_EXAM_CIPHERTEXT[i], out_str[i]);
  }
}

TEST_F(GTestCtr, Normal_aes_ctr_encrypt_002) {
  cryptography::ctr ctr;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t iv[16] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t out_str[64] = {0};

  memcpy(origin_text, NIST_AES_CTR_EXAM_PLAINTEXT, sizeof(NIST_AES_CTR_EXAM_PLAINTEXT));
  memcpy(iv, NIST_AES_CTR_EXAM_AES_IV, sizeof(NIST_AES_CTR_EXAM_AES_IV));

  aes.initialize(cryptography::AES128, NIST_AES_CTR_EXAM_AES_KEY, sizeof(NIST_AES_CTR_EXAM_AES_KEY), true);
  ctr.initialize(cryptography::AES128, (uint8_t *)iv, sizeof(iv));
  do {
    ctr.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt(str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == ctr.enc_postprocess(cstr, sizeof(cstr), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CTR_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CTR_EXAM_CIPHERTEXT[i], out_str[i]);
  }
}

TEST_F(GTestCtr, Normal_aes_ctr_decrypt_001) {
  cryptography::ctr ctr;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t iv[16] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, NIST_AES_CTR_EXAM_PLAINTEXT, sizeof(NIST_AES_CTR_EXAM_PLAINTEXT));
  memcpy(iv, NIST_AES_CTR_EXAM_AES_IV, sizeof(NIST_AES_CTR_EXAM_AES_IV));

  aes.initialize(cryptography::AES128, NIST_AES_CTR_EXAM_AES_KEY, sizeof(NIST_AES_CTR_EXAM_AES_KEY), false);
  ctr.initialize(cryptography::AES128, (uint8_t *)iv, sizeof(iv));
  do {
    ctr.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt(str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == ctr.enc_postprocess(cstr, sizeof(cstr), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CTR_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CTR_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  memset(str, 0x00, sizeof(str));
  memset(cstr, 0x00, sizeof(cstr));

  do {
    ctr.dec_preprocess(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
    EXPECT_EQ(0, aes.encrypt(cstr, sizeof(cstr), str, sizeof(str)));
  } while(0 == ctr.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));


  for (int32_t i = 0; i < sizeof(origin_text); ++i) {
    EXPECT_EQ(origin_text[i], plaintext[i]);
  }
}

TEST_F(GTestCtr, Normal_aes_ctr_decrypt_002) {
  cryptography::ctr ctr;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t iv[16] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, NIST_AES_CTR_EXAM_PLAINTEXT, sizeof(NIST_AES_CTR_EXAM_PLAINTEXT));
  memcpy(iv, NIST_AES_CTR_EXAM_AES_IV, sizeof(NIST_AES_CTR_EXAM_AES_IV));

  aes.initialize(cryptography::AES128, NIST_AES_CTR_EXAM_AES_KEY, sizeof(NIST_AES_CTR_EXAM_AES_KEY), true);
  ctr.initialize(cryptography::AES128, (uint8_t *)iv, sizeof(iv));
  do {
    ctr.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt(str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == ctr.enc_postprocess(cstr, sizeof(cstr), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CTR_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CTR_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  memset(str, 0x00, sizeof(str));
  memset(cstr, 0x00, sizeof(cstr));

  do {
    ctr.dec_preprocess(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
    EXPECT_EQ(0, aes.encrypt(cstr, sizeof(cstr), str, sizeof(str)));
  } while(0 == ctr.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));


  for (int32_t i = 0; i < sizeof(origin_text); ++i) {
    EXPECT_EQ(origin_text[i], plaintext[i]);
  }
}
#if 0
TEST_F(GTestCtr, Normal_aes_ctr_decrypt_003) {
  cryptography::ctr ctr;
  cryptography::aes aes;
  uint8_t origin_text[28160] = {0};
  uint8_t iv[16] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[28160] = {0};
  uint8_t plaintext[28160] = {0};

  memcpy(origin_text, CTR_TEST_STRING, sizeof(CTR_TEST_STRING));
  memcpy(iv, NIST_AES_CTR_EXAM_AES_IV, sizeof(NIST_AES_CTR_EXAM_AES_IV));

  aes.initialize(cryptography::AES128, NIST_AES_CTR_EXAM_AES_KEY, sizeof(NIST_AES_CTR_EXAM_AES_KEY), false);
  ctr.initialize(cryptography::AES128, (uint8_t *)iv, sizeof(iv));

  for (uint64_t i = 0; i < 100; ++i) {
    do {
      ctr.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
      EXPECT_EQ(0, aes.encrypt(str, sizeof(str), cstr, sizeof(cstr)));
    } while(0 == ctr.enc_postprocess(cstr, sizeof(cstr), ciphertext, sizeof(ciphertext)));

    memset(str, 0x00, sizeof(str));
    memset(cstr, 0x00, sizeof(cstr));

    do {
      ctr.dec_preprocess(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
      EXPECT_EQ(0, aes.encrypt(cstr, sizeof(cstr), str, sizeof(str)));
    } while(0 == ctr.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));
  }
}
#endif
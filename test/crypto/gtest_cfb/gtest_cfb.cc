/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_cfb.h"

TEST_F(GTestCfb, Normal_initialize_001) {
  cryptography::cfb cfb;
  cfb.initialize(cryptography::DES, (uint8_t *)CFB_TEST_DES_IV, sizeof(CFB_TEST_DES_IV));
}

TEST_F(GTestCfb, Normal_initialize_002) {
  cryptography::cfb cfb;
  cfb.initialize(cryptography::AES128, (uint8_t *)CFB_TEST_AES_IV, sizeof(CFB_TEST_AES_IV));
}

TEST_F(GTestCfb, Normal_enc_postprocess_001) {
  cryptography::cfb cfb;
  uint8_t origin_text[80] = {0};
  uint8_t in_str[9] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, CFB_TEST_STRING, sizeof(CFB_TEST_STRING));

  cfb.initialize(cryptography::DES, (uint8_t *)CFB_TEST_DES_IV, sizeof(CFB_TEST_DES_IV));
  do {
    cfb.enc_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == cfb.enc_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0, j = 0; i < sizeof(out_str); ++i, ++j) {
    printf("%02x ", out_str[i]);
  }
  printf("\n");
}

TEST_F(GTestCfb, Normal_enc_postprocess_002) {
  cryptography::cfb cfb;
  uint8_t origin_text[80] = {0};
  uint8_t in_str[17] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, CFB_TEST_STRING, sizeof(CFB_TEST_STRING));

  cfb.initialize(cryptography::AES128, (uint8_t *)CFB_TEST_AES_IV, sizeof(CFB_TEST_AES_IV));
  do {
    cfb.enc_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == cfb.enc_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0, j = 0; i < sizeof(out_str); ++i, ++j) {
    printf("%02x ", out_str[i]);
  }
  printf("\n");
}

TEST_F(GTestCfb, Normal_aes_cfb_encrypt_001) {
  cryptography::cfb cfb;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t out_str[64] = {0};

  memcpy(origin_text, NIST_AES_CFB_EXAM_PLAINTEXT, sizeof(NIST_AES_CFB_EXAM_PLAINTEXT));

  aes.initialize(cryptography::AES128, NIST_AES_CFB_EXAM_AES_KEY, sizeof(NIST_AES_CFB_EXAM_AES_KEY), false);
  cfb.initialize(cryptography::AES128, (uint8_t *)NIST_AES_CFB_EXAM_AES_IV, sizeof(NIST_AES_CFB_EXAM_AES_IV));
  do {
    cfb.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt((char *)str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == cfb.enc_postprocess(cstr, sizeof(cstr), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CFB_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CFB_EXAM_CIPHERTEXT[i], out_str[i]);
  }
}

TEST_F(GTestCfb, Normal_aes_cfb_encrypt_002) {
  cryptography::cfb cfb;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t out_str[64] = {0};

  memcpy(origin_text, NIST_AES_CFB_EXAM_PLAINTEXT, sizeof(NIST_AES_CFB_EXAM_PLAINTEXT));

  aes.initialize(cryptography::AES128, NIST_AES_CFB_EXAM_AES_KEY, sizeof(NIST_AES_CFB_EXAM_AES_KEY), true);
  cfb.initialize(cryptography::AES128, (uint8_t *)NIST_AES_CFB_EXAM_AES_IV, sizeof(NIST_AES_CFB_EXAM_AES_IV));
  do {
    cfb.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt((char *)str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == cfb.enc_postprocess(cstr, sizeof(cstr), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CFB_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CFB_EXAM_CIPHERTEXT[i], out_str[i]);
  }
}

TEST_F(GTestCfb, Normal_aes_cfb_decrypt_001) {
  cryptography::cfb cfb;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, NIST_AES_CFB_EXAM_PLAINTEXT, sizeof(NIST_AES_CFB_EXAM_PLAINTEXT));

  aes.initialize(cryptography::AES128, NIST_AES_CFB_EXAM_AES_KEY, sizeof(NIST_AES_CFB_EXAM_AES_KEY), false);
  cfb.initialize(cryptography::AES128, (uint8_t *)NIST_AES_CFB_EXAM_AES_IV, sizeof(NIST_AES_CFB_EXAM_AES_IV));
  do {
    cfb.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt((char *)str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == cfb.enc_postprocess(cstr, sizeof(cstr), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CFB_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CFB_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  memset(str, 0x00, sizeof(str));
  memset(cstr, 0x00, sizeof(cstr));

  do {
    cfb.dec_preprocess(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
    EXPECT_EQ(0, aes.encrypt((char *)cstr, sizeof(cstr), str, sizeof(str)));
  } while(0 == cfb.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));


  for (int32_t i = 0; i < sizeof(origin_text); ++i) {
    //printf("%02x ", plaintext[i]);
    EXPECT_EQ(origin_text[i], plaintext[i]);
  }
}

TEST_F(GTestCfb, Normal_aes_cfb_decrypt_002) {
  cryptography::cfb cfb;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, NIST_AES_CFB_EXAM_PLAINTEXT, sizeof(NIST_AES_CFB_EXAM_PLAINTEXT));

  aes.initialize(cryptography::AES128, NIST_AES_CFB_EXAM_AES_KEY, sizeof(NIST_AES_CFB_EXAM_AES_KEY), true);
  cfb.initialize(cryptography::AES128, (uint8_t *)NIST_AES_CFB_EXAM_AES_IV, sizeof(NIST_AES_CFB_EXAM_AES_IV));
  do {
    cfb.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt((char *)str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == cfb.enc_postprocess(cstr, sizeof(cstr), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CFB_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CFB_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  memset(str, 0x00, sizeof(str));
  memset(cstr, 0x00, sizeof(cstr));

  do {
    cfb.dec_preprocess(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
    EXPECT_EQ(0, aes.encrypt((char *)cstr, sizeof(cstr), str, sizeof(str)));
  } while(0 == cfb.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));


  for (int32_t i = 0; i < sizeof(origin_text); ++i) {
    EXPECT_EQ(origin_text[i], plaintext[i]);
  }
}
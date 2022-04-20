/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ofb.h"

TEST_F(GTestOfb, Normal_initialize_001) {
  cryptography::ofb ofb;
  ofb.initialize(cryptography::SIMPLE_DES, (uint8_t *)OFB_TEST_DES_IV, sizeof(OFB_TEST_DES_IV));
}

TEST_F(GTestOfb, Normal_initialize_002) {
  cryptography::ofb ofb;
  ofb.initialize(cryptography::AES128, (uint8_t *)OFB_TEST_AES_IV, sizeof(OFB_TEST_AES_IV));
}

TEST_F(GTestOfb, Normal_enc_postprocess_001) {
  cryptography::ofb ofb;
  uint8_t origin_text[80] = {0};
  uint8_t in_str[9] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, OFB_TEST_STRING, sizeof(OFB_TEST_STRING));

  ofb.initialize(cryptography::SIMPLE_DES, (uint8_t *)OFB_TEST_DES_IV, sizeof(OFB_TEST_DES_IV));
  do {
    ofb.enc_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == ofb.enc_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0, j = 0; i < sizeof(out_str); ++i, ++j) {
    printf("%02x ", out_str[i]);
  }
  printf("\n");
}

TEST_F(GTestOfb, Normal_enc_postprocess_002) {
  cryptography::ofb ofb;
  uint8_t origin_text[80] = {0};
  uint8_t in_str[17] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, OFB_TEST_STRING, sizeof(OFB_TEST_STRING));

  ofb.initialize(cryptography::AES128, (uint8_t *)OFB_TEST_AES_IV, sizeof(OFB_TEST_AES_IV));
  do {
    ofb.enc_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == ofb.enc_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0, j = 0; i < sizeof(out_str); ++i, ++j) {
    printf("%02x ", out_str[i]);
  }
  printf("\n");
}

TEST_F(GTestOfb, Normal_aes_ofb_decrypt_001) {
  cryptography::ofb ofb;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, NIST_AES_OFB_EXAM_PLAINTEXT, sizeof(NIST_AES_OFB_EXAM_PLAINTEXT));

  aes.initialize(NIST_AES_OFB_EXAM_AES_KEY, sizeof(NIST_AES_OFB_EXAM_AES_KEY));
  ofb.initialize(cryptography::AES128, (uint8_t *)NIST_AES_OFB_EXAM_AES_IV, sizeof(NIST_AES_OFB_EXAM_AES_IV));
  do {
    ofb.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt(str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == ofb.enc_postprocess(cstr, sizeof(cstr), ciphertext, sizeof(ciphertext)));

  for (int32_t i = 0; i < sizeof(NIST_AES_OFB_EXAM_CIPHERTEXT); ++i) {
    EXPECT_EQ(NIST_AES_OFB_EXAM_CIPHERTEXT[i], ciphertext[i]);
  }

  memset(str, 0x00, sizeof(str));
  memset(cstr, 0x00, sizeof(cstr));

  do {
    ofb.dec_preprocess(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
    EXPECT_EQ(0, aes.encrypt(cstr, sizeof(cstr), str, sizeof(str)));
  } while(0 == ofb.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));


  for (int32_t i = 0; i < sizeof(origin_text); ++i) {
    //printf("%02x ", plaintext[i]);
    EXPECT_EQ(origin_text[i], plaintext[i]);
  }
}

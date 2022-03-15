/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_cbc.h"

TEST_F(GTestCbc, Normal_initialize_001) {
  cryptography::cbc cbc;
  cbc.initialize(cryptography::DES, (uint8_t *)CBC_TEST_DES_IV, sizeof(CBC_TEST_DES_IV));
}

TEST_F(GTestCbc, Normal_initialize_002) {
  cryptography::cbc cbc;
  cbc.initialize(cryptography::AES128, (uint8_t *)CBC_TEST_AES_IV, sizeof(CBC_TEST_AES_IV));
}

TEST_F(GTestCbc, Normal_enc_preprocess_001) {
  cryptography::cbc cbc;
  uint8_t input[80] = {0};
  uint8_t split_str[8] = {0};

  memcpy(input, CBC_TEST_STRING, sizeof(CBC_TEST_STRING));

  cbc.initialize(cryptography::DES, (uint8_t *)CBC_TEST_DES_IV, sizeof(CBC_TEST_DES_IV));
  cbc.enc_preprocess(input, sizeof(input), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    //EXPECT_EQ(CBC_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestCbc, Normal_enc_preprocess_002) {
  cryptography::cbc cbc;
  uint8_t input[80] = {0};
  uint8_t split_str[17] = {0};

  memcpy(input, CBC_TEST_STRING, sizeof(CBC_TEST_STRING));

  cbc.initialize(cryptography::AES128, (uint8_t *)CBC_TEST_AES_IV, sizeof(CBC_TEST_AES_IV));
  cbc.enc_preprocess(input, sizeof(input), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    //EXPECT_EQ(CBC_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestCbc, Normal_enc_postprocess_001) {
  cryptography::cbc cbc;
  uint8_t origin_text[80] = {0};
  uint8_t in_str[9] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, CBC_TEST_STRING, sizeof(CBC_TEST_STRING));

  cbc.initialize(cryptography::DES, (uint8_t *)CBC_TEST_DES_IV, sizeof(CBC_TEST_DES_IV));
  do {
    cbc.enc_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == cbc.enc_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0, j = 0; i < sizeof(out_str); ++i, ++j) {
    printf("%02x ", out_str[i]);
  }
  printf("\n");
}

TEST_F(GTestCbc, Normal_enc_postprocess_002) {
  cryptography::cbc cbc;
  uint8_t origin_text[80] = {0};
  uint8_t in_str[17] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, CBC_TEST_STRING, sizeof(CBC_TEST_STRING));
  
  cbc.initialize(cryptography::AES128, (uint8_t *)CBC_TEST_AES_IV, sizeof(CBC_TEST_AES_IV));
  do {
    cbc.enc_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == cbc.enc_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0, j = 0; i < sizeof(CBC_TEST_STRING); ++i, ++j) {
    printf("%02x ", out_str[i]);
  }
}

TEST_F(GTestCbc, Normal_aes_cbc_encrypt_001) {
  cryptography::cbc cbc;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t out_str[64] = {0};

  memcpy(origin_text, NIST_AES_CBC_EXAM_PLAINTEXT, sizeof(NIST_AES_CBC_EXAM_PLAINTEXT));

  aes.initialize(cryptography::AES128, NIST_AES_CBC_EXAM_AES_KEY, sizeof(NIST_AES_CBC_EXAM_AES_KEY), false);
  cbc.initialize(cryptography::AES128, (uint8_t *)NIST_AES_CBC_EXAM_AES_IV, sizeof(NIST_AES_CBC_EXAM_AES_IV));
  do {
    cbc.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt((char *)str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == cbc.enc_postprocess(cstr, sizeof(cstr), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CBC_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CBC_EXAM_CIPHERTEXT[i], out_str[i]);
  }
}

TEST_F(GTestCbc, Normal_aes_cbc_encrypt_002) {
  cryptography::cbc cbc;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t out_str[64] = {0};

  memcpy(origin_text, NIST_AES_CBC_EXAM_PLAINTEXT, sizeof(NIST_AES_CBC_EXAM_PLAINTEXT));

  aes.initialize(cryptography::AES128, NIST_AES_CBC_EXAM_AES_KEY, sizeof(NIST_AES_CBC_EXAM_AES_KEY), true);
  cbc.initialize(cryptography::AES128, (uint8_t *)NIST_AES_CBC_EXAM_AES_IV, sizeof(NIST_AES_CBC_EXAM_AES_IV));
  do {
    cbc.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt((char *)str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == cbc.enc_postprocess(cstr, sizeof(cstr), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(NIST_AES_CBC_EXAM_PLAINTEXT); ++i) {
    EXPECT_EQ(NIST_AES_CBC_EXAM_CIPHERTEXT[i], out_str[i]);
  }
}

TEST_F(GTestCbc, Normal_aes_cbc_decrypt_001) {
  cryptography::cbc cbc;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, NIST_AES_CBC_EXAM_PLAINTEXT, sizeof(NIST_AES_CBC_EXAM_PLAINTEXT));

  aes.initialize(cryptography::AES128, NIST_AES_CBC_EXAM_AES_KEY, sizeof(NIST_AES_CBC_EXAM_AES_KEY), false);
  cbc.initialize(cryptography::AES128, (uint8_t *)NIST_AES_CBC_EXAM_AES_IV, sizeof(NIST_AES_CBC_EXAM_AES_IV));
  do {
    cbc.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt((char *)str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == cbc.enc_postprocess(cstr, sizeof(cstr), ciphertext, sizeof(ciphertext)));

  memset(str, 0x00, sizeof(str));
  memset(cstr, 0x00, sizeof(cstr));

  do {
    cbc.dec_preprocess(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
    EXPECT_EQ(0, aes.decrypt(cstr, sizeof(cstr), (char *)str, sizeof(str)));
  } while(0 == cbc.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));


  for (int32_t i = 0; i < sizeof(origin_text); ++i) {
    EXPECT_EQ(origin_text[i], plaintext[i]);
  }
}

TEST_F(GTestCbc, Normal_aes_cbc_decrypt_002) {
  cryptography::cbc cbc;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, NIST_AES_CBC_EXAM_PLAINTEXT, sizeof(NIST_AES_CBC_EXAM_PLAINTEXT));

  aes.initialize(cryptography::AES128, NIST_AES_CBC_EXAM_AES_KEY, sizeof(NIST_AES_CBC_EXAM_AES_KEY), true);
  cbc.initialize(cryptography::AES128, (uint8_t *)NIST_AES_CBC_EXAM_AES_IV, sizeof(NIST_AES_CBC_EXAM_AES_IV));
  do {
    cbc.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    EXPECT_EQ(0, aes.encrypt((char *)str, sizeof(str), cstr, sizeof(cstr)));
  } while(0 == cbc.enc_postprocess(cstr, sizeof(cstr), ciphertext, sizeof(ciphertext)));

  memset(str, 0x00, sizeof(str));
  memset(cstr, 0x00, sizeof(cstr));

  do {
    cbc.dec_preprocess(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
    EXPECT_EQ(0, aes.decrypt(cstr, sizeof(cstr), (char *)str, sizeof(str)));
  } while(0 == cbc.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));


  for (int32_t i = 0; i < sizeof(origin_text); ++i) {
    EXPECT_EQ(origin_text[i], plaintext[i]);
  }
}
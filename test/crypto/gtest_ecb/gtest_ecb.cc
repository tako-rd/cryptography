/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest_ecb.h"

TEST_F(GTestEcb, Normal_initialize_001) {
  cryptography::ecb ecb;
  ecb.initialize(cryptography::DES, nullptr, 0);
}

TEST_F(GTestEcb, Normal_initialize_002) {
  cryptography::ecb ecb;
  ecb.initialize(cryptography::AES128, nullptr, 0);
}

TEST_F(GTestEcb, Normal_enc_preprocess_001) {
  cryptography::ecb ecb;
  uint8_t origin_text[81] = {0};
  uint8_t split_str[8] = {0};

  memcpy(origin_text, ECB_TEST_STRING, sizeof(ECB_TEST_STRING));

  ecb.initialize(cryptography::DES, nullptr, 0);
  ecb.enc_preprocess(origin_text, sizeof(origin_text), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestEcb, Normal_enc_preprocess_002) {
  cryptography::ecb ecb;
  uint8_t origin_text[81] = {0};
  uint8_t split_str[16] = {0};

  memcpy(origin_text, ECB_TEST_STRING, sizeof(ECB_TEST_STRING));

  ecb.initialize(cryptography::AES128, nullptr, 0);
  ecb.enc_preprocess(origin_text, sizeof(origin_text), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestEcb, Normal_enc_postprocess_001) {
  cryptography::ecb ecb;
  uint8_t origin_text[81] = {0};
  uint8_t in_str[9] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, ECB_TEST_STRING, sizeof(ECB_TEST_STRING));

  ecb.initialize(cryptography::DES, nullptr, 0);
  do {
    ecb.enc_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == ecb.enc_postprocess(in_str, sizeof(ECB_TEST_STRING), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(ECB_TEST_STRING); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], out_str[i]);
  }
}

TEST_F(GTestEcb, Normal_enc_postprocess_002) {
  cryptography::ecb ecb;
  uint8_t origin_text[81] = {0};
  uint8_t in_str[17] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, ECB_TEST_STRING, sizeof(ECB_TEST_STRING));

  ecb.initialize(cryptography::AES128, nullptr, 0);
  do {
    ecb.enc_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == ecb.enc_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(ECB_TEST_STRING); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], out_str[i]);
  }
}

TEST_F(GTestEcb, Normal_dec_preprocess_001) {
  cryptography::ecb ecb;
  uint8_t origin_text[81] = {0};
  uint8_t split_str[8] = {0};

  memcpy(origin_text, ECB_TEST_STRING, sizeof(ECB_TEST_STRING));

  ecb.initialize(cryptography::DES, nullptr, 0);
  ecb.dec_preprocess(origin_text, sizeof(origin_text), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestEcb, Normal_dec_preprocess_002) {
  cryptography::ecb ecb;
  uint8_t origin_text[81] = {0};
  uint8_t split_str[16] = {0};

  memcpy(origin_text, ECB_TEST_STRING, sizeof(ECB_TEST_STRING));

  ecb.initialize(cryptography::AES128, nullptr, 0);
  ecb.dec_preprocess(origin_text, sizeof(origin_text), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestEcb, Normal_dec_postprocess_001) {
  cryptography::ecb ecb;
  uint8_t origin_text[81] = {0};
  uint8_t in_str[9] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, ECB_TEST_STRING, sizeof(ECB_TEST_STRING));

  ecb.initialize(cryptography::DES, nullptr, 0);
  do {
    ecb.dec_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == ecb.dec_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(ECB_TEST_STRING); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], out_str[i]);
  }
}

TEST_F(GTestEcb, Normal_dec_postprocess_002) {
  cryptography::ecb ecb;
  uint8_t origin_text[81] = {0};
  uint8_t in_str[17] = {0};
  uint8_t out_str[81] = {0};

  memcpy(origin_text, ECB_TEST_STRING, sizeof(ECB_TEST_STRING));

  ecb.initialize(cryptography::AES128, nullptr, 0);
  do {
    ecb.dec_preprocess(origin_text, sizeof(origin_text), in_str, sizeof(in_str));
  } while(0 == ecb.dec_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(ECB_TEST_STRING); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], out_str[i]);
  }
}

TEST_F(GTestEcb, Normal_aes_ecb_001) {
  cryptography::ecb ecb;
  cryptography::aes aes;
  uint8_t origin_text[64] = {0};
  uint8_t str[16] = {0};
  uint8_t cstr[16] = {0};
  uint8_t ciphertext[64] = {0};
  uint8_t plaintext[64] = {0};

  memcpy(origin_text, FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT, sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT));

  aes.initialize(cryptography::AES128, FIPS197_C1_128BIT_BASED_TEST_KEY, sizeof(FIPS197_C1_128BIT_BASED_TEST_KEY), false);
  ecb.initialize(cryptography::AES128, nullptr, 0);
  do {
    ecb.enc_preprocess(origin_text, sizeof(origin_text), str, sizeof(str));
    aes.encrypt((char *)str, sizeof(str), cstr, sizeof(cstr));
  } while(0 == ecb.enc_postprocess(cstr, sizeof(cstr), ciphertext, sizeof(ciphertext)));

  memset(str, 0x00, sizeof(str));
  memset(cstr, 0x00, sizeof(cstr));

  do {
    ecb.dec_preprocess(ciphertext, sizeof(ciphertext), cstr, sizeof(cstr));
    aes.decrypt(cstr, sizeof(cstr), (char *)str, sizeof(str));
  } while(0 == ecb.dec_postprocess(str, sizeof(str), plaintext, sizeof(plaintext)));


  for (int32_t i = 0; i < sizeof(FIPS197_C1_128BIT_BASED_TEST_PLAINTEXT); ++i) {
    EXPECT_EQ(origin_text[i], plaintext[i]);
  }
}
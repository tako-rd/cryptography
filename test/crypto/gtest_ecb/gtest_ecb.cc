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
  uint8_t split_str[8] = {0};

  ecb.initialize(cryptography::DES, nullptr, 0);
  ecb.enc_preprocess(ECB_TEST_STRING, sizeof(ECB_TEST_STRING), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestEcb, Normal_enc_preprocess_002) {
  cryptography::ecb ecb;
  uint8_t split_str[16] = {0};

  ecb.initialize(cryptography::AES128, nullptr, 0);
  ecb.enc_preprocess(ECB_TEST_STRING, sizeof(ECB_TEST_STRING), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestEcb, Normal_enc_postprocess_001) {
  cryptography::ecb ecb;
  uint8_t in_str[9] = {0};
  uint8_t out_str[81] = {0};

  ecb.initialize(cryptography::DES, nullptr, 0);
  do {
    ecb.enc_preprocess(ECB_TEST_STRING, sizeof(ECB_TEST_STRING), in_str, sizeof(in_str));
  } while(0 == ecb.enc_postprocess(in_str, sizeof(ECB_TEST_STRING), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(ECB_TEST_STRING); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], out_str[i]);
  }
}

TEST_F(GTestEcb, Normal_enc_postprocess_002) {
  cryptography::ecb ecb;
  uint8_t in_str[17] = {0};
  uint8_t out_str[81] = {0};

  ecb.initialize(cryptography::AES128, nullptr, 0);
  do {
    ecb.enc_preprocess(ECB_TEST_STRING, sizeof(ECB_TEST_STRING), in_str, sizeof(in_str));
  } while(0 == ecb.enc_postprocess(in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(ECB_TEST_STRING); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], out_str[i]);
  }
}

TEST_F(GTestEcb, Normal_dec_preprocess_001) {
  cryptography::ecb ecb;
  uint8_t split_str[8] = {0};

  ecb.initialize(cryptography::DES, nullptr, 0);
  ecb.dec_preprocess((uint8_t *)ECB_TEST_STRING, sizeof(ECB_TEST_STRING), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestEcb, Normal_dec_preprocess_002) {
  cryptography::ecb ecb;
  uint8_t split_str[16] = {0};

  ecb.initialize(cryptography::AES128, nullptr, 0);
  ecb.dec_preprocess((uint8_t *)ECB_TEST_STRING, sizeof(ECB_TEST_STRING), split_str, sizeof(split_str));
  for (int32_t i = 0; i < sizeof(split_str); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], split_str[i]);
  }
}

TEST_F(GTestEcb, Normal_dec_postprocess_001) {
  cryptography::ecb ecb;
  uint8_t in_str[9] = {0};
  char out_str[81] = {0};

  ecb.initialize(cryptography::DES, nullptr, 0);
  do {
    ecb.dec_preprocess((uint8_t *)ECB_TEST_STRING, sizeof(ECB_TEST_STRING), in_str, sizeof(in_str));
  } while(0 == ecb.dec_postprocess((char *)in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(ECB_TEST_STRING); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], out_str[i]);
  }
}

TEST_F(GTestEcb, Normal_dec_postprocess_002) {
  cryptography::ecb ecb;
  uint8_t in_str[17] = {0};
  char out_str[81] = {0};

  ecb.initialize(cryptography::AES128, nullptr, 0);
  do {
    ecb.dec_preprocess((uint8_t *)ECB_TEST_STRING, sizeof(ECB_TEST_STRING), in_str, sizeof(in_str));
  } while(0 == ecb.dec_postprocess((char *)in_str, sizeof(in_str), out_str, sizeof(out_str)));

  for (int32_t i = 0; i < sizeof(ECB_TEST_STRING); ++i) {
    EXPECT_EQ(ECB_TEST_STRING[i], out_str[i]);
  }
}
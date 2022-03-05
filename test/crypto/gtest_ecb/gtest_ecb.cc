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

}

TEST_F(GTestEcb, Normal_enc_postprocess_001) {

}

TEST_F(GTestEcb, Normal_dec_preprocess_001) {

}

TEST_F(GTestEcb, Normal_dec_postprocess_001) {

}
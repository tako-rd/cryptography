/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest/gtest.h"
#include "gtest_aes_defs.h"

#include "aes.h"

#ifndef GTEST_AES128_H
#define GTEST_AES128_H

class GTestAes : public ::testing::Test {
 public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
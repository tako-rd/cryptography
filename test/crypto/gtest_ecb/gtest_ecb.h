/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_ECB_H
#define GTEST_ECB_H

#include "gtest/gtest.h"
#include "gtest_ecb_defs.h"

#include "secret_key.h"

class GTestEcb : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
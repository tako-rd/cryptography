/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_TWOFISH_H
#define GTEST_TWOFISH_H

#include "gtest/gtest.h"
#include "gtest_twofish_defs.h"

#include "twofish.h"

class GTestTwofish : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
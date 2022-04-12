/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CAST128_H
#define GTEST_CAST128_H

#include "gtest/gtest.h"
#include "gtest_cast128_defs.h"

#include "cast128.h"

class GTestCast128 : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
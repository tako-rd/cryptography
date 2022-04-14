/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CAST256_H
#define GTEST_CAST256_H

#include "gtest/gtest.h"
#include "gtest_cast256_defs.h"

#include "cast256.h"

class GTestCast256 : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
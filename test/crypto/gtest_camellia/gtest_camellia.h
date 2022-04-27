/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CAMELLIA128_H
#define GTEST_CAMELLIA128_H

#include "gtest/gtest.h"
#include "gtest_camellia_defs.h"

#include "camellia.h"

class GTestCamellia : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
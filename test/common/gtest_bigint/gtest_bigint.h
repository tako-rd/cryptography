/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef GTEST_BIGINT_H
#define GTEST_BIGINT_H

#include "gtest/gtest.h"
#include "gtest_bigint_defs.h"

#include "common/bignumber.h"

class GTestBigint : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
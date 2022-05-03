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

#include "common/bigint.h"

class GTestBigint : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
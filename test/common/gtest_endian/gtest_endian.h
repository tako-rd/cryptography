/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef GTEST_ENDIAN_H
#define GTEST_ENDIAN_H

#include "gtest/gtest.h"
#include "gtest_endian_defs.h"

#include "common/endian.h"

class GTestEndian : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif

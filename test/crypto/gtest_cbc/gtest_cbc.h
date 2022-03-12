/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CBC_H
#define GTEST_CBC_H

#include "gtest/gtest.h"
#include "gtest_cbc_defs.h"

#include "cbc.h"

class GTestCbc : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
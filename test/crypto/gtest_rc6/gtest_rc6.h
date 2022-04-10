/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_RC6_H
#define GTEST_RC6_H

#include "gtest/gtest.h"
#include "gtest_rc6_defs.h"

#include "rc6.h"

class GTestRC6 : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif

/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CFB_H
#define GTEST_CFB_H

#include "gtest/gtest.h"
#include "gtest_cfb_defs.h"
#include "aes.h"

#include "cfb.h"

class GTestCfb : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
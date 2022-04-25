/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_OFB_H
#define GTEST_OFB_H

#include "gtest/gtest.h"
#include "gtest_ofb_defs.h"

#include "secret_key.h"

class GTestOFB : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
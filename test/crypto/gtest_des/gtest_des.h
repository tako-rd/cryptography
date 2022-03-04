/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "gtest/gtest.h"

#include "des.h"
#include "gtest_des_defs.h"

#ifndef GTEST_DES_H
#define GTEST_DES_H

class GTestDes : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CTR_H
#define GTEST_CTR_H

#include "gtest/gtest.h"
#include "gtest_ctr_defs.h"
#include "aes.h"

#include "ctr.h"

class GTestCtr : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
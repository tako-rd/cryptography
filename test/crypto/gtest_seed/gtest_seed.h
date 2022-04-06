/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_SEED_H
#define GTEST_SEED_H

#include "gtest/gtest.h"
#include "gtest_seed_defs.h"

#include "seed.h"

class GTestSeed : public ::testing::Test {
public:
  virtual void SetUp() {};

  virtual void TearDown() {};
};

#endif
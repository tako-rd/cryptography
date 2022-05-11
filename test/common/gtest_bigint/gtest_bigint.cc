/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "gtest_bigint.h"

using namespace cryptography;

/* Biguint64 test. */
TEST_F(GTestBigint, Normal_Biguint64_Add_001) {
  uint32_t u32data[2] = {0};
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum2 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;
  uint64_t num2 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 + bigunum2;
    num1 = num1 + num2;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Add_002) {
  uint32_t u32data[2] = {0};
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 + 1;
    num1 = num1 + 1;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Add_003) {
  uint32_t u32data[2] = {0};
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 + BIG_NUMBER_64BIT_ARRAY_001;
    num1 = num1 + BIG_NUMBER_64BIT_001;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Sub_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_002;
  biguint<64> bigunum2 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_002;
  uint64_t num2 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 - bigunum2;
    num1 = num1 - num2;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Sub_002) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_002;
  uint64_t num1 = BIG_NUMBER_64BIT_002;
 
  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 - 1;
    num1 = num1 - 1;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Sub_003) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_002;
  uint64_t num1 = BIG_NUMBER_64BIT_002;

  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 - BIG_NUMBER_64BIT_ARRAY_001;
    num1 = num1 - BIG_NUMBER_64BIT_001;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Mult_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum2 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;
  uint64_t num2 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 * bigunum2;
    num1 = num1 * num2;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Mult_002) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 * i;
    num1 = num1 * i;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Mult_003) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 * BIG_NUMBER_64BIT_ARRAY_001;
    num1 = num1 * BIG_NUMBER_64BIT_001;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Div_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum2 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;
  uint64_t num2 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 0; i < 50; i += 1) {
    bigunum1 = bigunum1 / bigunum2;
    num1 = num1 / num2;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Div_002) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 1; i < 50; i += 1) {
    bigunum1 = bigunum1 / i;
    num1 = num1 / i;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Div_003) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_002;
  uint64_t num1 = BIG_NUMBER_64BIT_002;

  for (int32_t i = 1; i < 50; i += 1) {
    bigunum1 = bigunum1 / BIG_NUMBER_64BIT_ARRAY_001;
    num1 = num1 / BIG_NUMBER_64BIT_001;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Mod_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum2 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;
  uint64_t num2 = BIG_NUMBER_64BIT_001;

  for (int32_t i = 1; i < 50; i += 1) {
    bigunum1 = bigunum1 % bigunum2;
    num1 = num1 % num2;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Mod_002) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  uint64_t num1 = BIG_NUMBER_64BIT_001;
  
  for (int32_t i = 1; i < 50; i += 1) {
    bigunum1 = bigunum1 % i;
    num1 = num1 % i;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Mod_003) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_002;
  uint64_t num1 = BIG_NUMBER_64BIT_002;

  for (int32_t i = 1; i < 50; i += 1) {
    bigunum1 = bigunum1 % BIG_NUMBER_64BIT_ARRAY_001;
    num1 = num1 % BIG_NUMBER_64BIT_001;

    EXPECT_EQ((uint32_t)((num1 >> 32) & 0xFFFF'FFFF), bigunum1[0]);
    EXPECT_EQ((uint32_t)(num1 & 0xFFFF'FFFF), bigunum1[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_LeftShift_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum2 = 0;
  uint64_t num1 = BIG_NUMBER_64BIT_001;
  uint64_t num2 = 0;

  for (int32_t shift = 0; shift <= 64; ++shift) {
    bigunum2 = bigunum1 << shift;
    num2 = num1 << shift;

    EXPECT_EQ((uint32_t)((num2 >> 32) & 0xFFFF'FFFF), bigunum2[0]);
    EXPECT_EQ((uint32_t)(num2 & 0xFFFF'FFFF), bigunum2[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_RightShift_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum2;
  uint64_t num1 = BIG_NUMBER_64BIT_001;
  uint64_t num2 = 0;

  for (int32_t shift = 0; shift <= 64; ++shift) {
    bigunum2 = bigunum1 >> shift;
    num2 = num1 >> shift;

    EXPECT_EQ((uint32_t)((num2 >> 32) & 0xFFFF'FFFF), bigunum2[0]);
    EXPECT_EQ((uint32_t)(num2 & 0xFFFF'FFFF), bigunum2[1]);
  }
}

TEST_F(GTestBigint, Normal_Biguint64_Equal_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum2 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum3 = BIG_NUMBER_64BIT_ARRAY_002;
  biguint<64> bigunum4 = BIG_NUMBER_64BIT_ARRAY_003;

  EXPECT_EQ(true, (bigunum1 == bigunum2));
  EXPECT_EQ(false, (bigunum1 == bigunum3));
  EXPECT_EQ(true, (bigunum1 == BIG_NUMBER_64BIT_ARRAY_001));
  EXPECT_EQ(true, (bigunum4 == 1));
  EXPECT_EQ(false, (bigunum4 == 0));
}

TEST_F(GTestBigint, Normal_Biguint64_Greator_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum2 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum3 = BIG_NUMBER_64BIT_ARRAY_002;
  biguint<64> bigunum4 = BIG_NUMBER_64BIT_ARRAY_003;

  EXPECT_EQ(false, (bigunum1 > bigunum2));
  EXPECT_EQ(false, (bigunum1 > bigunum3));
  EXPECT_EQ(false, (bigunum1 < bigunum2));
  EXPECT_EQ(true, (bigunum1 < bigunum3));
  EXPECT_EQ(false, (bigunum4 < 1));
  EXPECT_EQ(false, (bigunum4 > 1));
  EXPECT_EQ(true, (bigunum4 > 0));
  EXPECT_EQ(false, (bigunum4 < 0));
}

TEST_F(GTestBigint, Normal_Biguint64_NoLess_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum2 = BIG_NUMBER_64BIT_ARRAY_001;
  biguint<64> bigunum3 = BIG_NUMBER_64BIT_ARRAY_002;
  biguint<64> bigunum4 = BIG_NUMBER_64BIT_ARRAY_003;

  EXPECT_EQ(true, (bigunum1 >= bigunum2));
  EXPECT_EQ(true, (bigunum1 <= bigunum2));
  EXPECT_EQ(false, (bigunum1 >= bigunum3));
  EXPECT_EQ(true, (bigunum1 <= bigunum3));
  EXPECT_EQ(true, (bigunum4 <= 1));
  EXPECT_EQ(true, (bigunum4 >= 1));
  EXPECT_EQ(false, (bigunum4 <= 0));
  EXPECT_EQ(true, (bigunum4 >= 0));
}

TEST_F(GTestBigint, Normal_Biguint64_IsPrime_001) {
  biguint<64> bigunum1 = BIG_NUMBER_64BIT_ARRAY_003;
  int32_t idx = 0;

  for (int32_t i = 0; i < 10000; ++i) {
    if (true == bigunum1.is_prime()) {
      for (int32_t j = 0; j < sizeof(PRIME_NUMBER_LIST); ++j) {
        if (bigunum1 == PRIME_NUMBER_LIST[j]) {
          EXPECT_EQ(true, true);
        }
      }
    }
    bigunum1 = bigunum1 + 1;
  }
}

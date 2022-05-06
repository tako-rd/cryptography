/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "common/bigint.h"

namespace cryptography {
#if 0
#define BIT32_MSB       0x8000'0000
#define BIT32_LSB       0x0000'0001

#define MASK_BIT32_LSB  0x7FFF'FFFF
#define MASK_BIT32_MSB  0xFFFF'FFFE

#define BIT32_MAX       0xFFFF'FFFF

void bigarithmetic::add(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
  uint32_t x_reg1 = 0;
  uint32_t y_reg1 = 0;
  bool is_overflow = false;

  for (int32_t pos = unitsize - 1; pos >= 0; --pos) {

    /* The process that the value overflowing from     */
    /* the previous data is added to the current data. */
    if (true == is_overflow) {
      if (BIT32_MAX == x[pos]) {
        x_reg1 = BIT32_MSB;
        x[pos] -= BIT32_MSB;
        x[pos] += BIT32_LSB;
      } else {
        x[pos] += BIT32_LSB;
      }
      is_overflow = false;
    }

    /* Check MSB of data. */
    x_reg1 = (BIT32_MSB == (y[pos] & BIT32_MSB)) ? BIT32_MSB : 0;
    y_reg1 = (BIT32_MSB == (y[pos] & BIT32_MSB)) ? BIT32_MSB : 0;

    /* Check for overflow and calculate. */
    if (0 != x_reg1 && 0 != y_reg1) {
      x[pos] = (x[pos] - BIT32_MSB) + (y[pos] - BIT32_MSB);
      is_overflow = true;

    } else if (0 != x_reg1 && 0 == y_reg1) {
      x[pos] = (x[pos] - BIT32_MSB) + y[pos];
      if (1 == (x[pos] & BIT32_MSB)) {
        is_overflow = true;
      } else {
        is_overflow = false;
      }

    } else if (0 == x_reg1 && 0 != y_reg1) {
      x[pos] = x[pos] + (y[pos] - BIT32_MSB);
      if (1 == (x[pos] & BIT32_MSB)) {
        is_overflow = true;
      } else {
        is_overflow = false;
      }

    } else {
      x[pos] = x[pos] + y[pos];
      is_overflow = false;
    }
  }
}

void bigarithmetic::sub(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
  uint32_t x_reg1 = 0;
  bool is_overflow = false;

  for (int32_t pos = unitsize - 1; pos >= 0; --pos) {

    /* The process that the value overflowing from     */
    /* the previous data is added to the current data. */
    if (true == is_overflow) {
      if (0 != x[pos]) {
        x[pos] -= 1;
        is_overflow = false;
      } else {
        x[pos] = 0xFFFF'FFFF;
        is_overflow = true;
      }
    }

    /* Check for overflow and calculate. */
    if (x[pos] <= y[pos]) {
      x[pos] -= y[pos];
    } else {
      x_reg1 = y[pos] - x[pos];
      x[pos] = (x[pos] + BIT32_MSB) - x_reg1;
      is_overflow = true;
    }
  }
}

void bigarithmetic::mult(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
  const int32_t bitsize = (unitsize << 5) - 1;
  int32_t unitpos = 0;
  int32_t bitmask = 0;


  for (int32_t bitpos = bitsize; bitpos >= 0; --bitpos) {
    unitpos = bitsize >> 5;
    bitmask = (0x8000'0000 >> (bitpos & 0x1F));

    if (bitmask == (y[unitpos] & bitmask)) {
      left_shift(x, bitpos, unitsize);

    } 

  }

}

void bigarithmetic::div(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {

}

void bigarithmetic::rem(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {

}

void bigarithmetic::left_shift(uint32_t *x, const int32_t y, const int32_t unitsize) noexcept {
  const int32_t bitshift = y & 0x7FFF'FFFF;
  const int32_t byteshift = y >> 5;
  uint32_t reg[2] = {0};

  reg[unitsize & 0x01] = x[unitsize - 1] >>= (32 - bitshift);
  x[unitsize - 1] <<= bitshift;

  for (int32_t pos = unitsize - 2; pos >= 0; --pos) {
    reg[pos & 0x01] = x[pos] >> (32 - bitshift);  /* switch between odd or even. */
    x[pos] = (x[pos] << bitshift) | reg[(pos + 1) & 0x01];
  }

  for (int32_t pos = 0; pos < byteshift; ++pos) {
    x[pos] = x[pos + byteshift];
  }
}

void bigarithmetic::right_shift(uint32_t *x, const int32_t y, const int32_t unitsize) noexcept {
  const uint32_t bitshift = y & 0x7FFF'FFFF;
  const uint32_t byteshift = y >> 5;
  uint32_t reg[2] = {0};

  reg[0] = x[0] <<= (32 - bitshift);
  x[0] >>= bitshift;

  for (int32_t pos = 1; pos < unitsize; ++pos) {
    reg[pos & 0x01] = x[pos] << (32 - bitshift);  /* switch between odd or even. */
    x[pos] = (x[pos] >> bitshift) | reg[(pos + 1) & 0x01];
  }

  for (int32_t pos = unitsize; pos < unitsize - byteshift; ++pos) {
    x[pos] = x[pos - byteshift];
  }
}

bool bigarithmetic::bigger_than(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
  for (int32_t pos = 0; pos < unitsize; ++pos) {
    if (x[pos] > y[pos]) {
      return true;
    } else if (x[pos] < y[pos]) {
      return false;
    }
  }
  return false;
}
#endif
}
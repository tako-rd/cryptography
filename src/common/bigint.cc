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

#define BIT32_MSB         0x1000'0000
#define BIT32_LSB         0x0000'0001

#define EXTRACT_BIT32_LSB 0xEFFF'FFFF
#define EXTRACT_BIT32_MSB 0xFFFF'FFFE

#define BIT32_MAX         0xFFFF'FFFF

void bigarithmetic::add(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
  uint32_t x_reg1 = 0;
  uint32_t y_reg1 = 0;
  uint32_t x_reg2 = 0;
  uint32_t y_reg2 = 0;
  bool is_overflow = false;

  for (int32_t pos = unitsize - 1; pos >= 0; --pos) {

    /* The process that the value overflowing from     */
    /* the previous data is added to the current data. */
    if (1 == is_overflow) {
      if (BIT32_MAX == x[pos]) {
        x_reg1 = BIT32_MSB;
        x[pos] -= BIT32_MSB;
        x[pos] += BIT32_LSB;
      } else {
        x[pos] += BIT32_LSB;
      }
      is_overflow = false;
    }

    /* Check MSB of x data . */
    if (1 == (x[pos] & BIT32_MSB)) {
      x_reg1 = x[pos] - EXTRACT_BIT32_LSB; 
    }

    /* Check MSB of y data . */
    if (1 == (y[pos] & BIT32_MSB)) {
      y_reg1 = y[pos] - EXTRACT_BIT32_LSB; 
    }

    /* Check for overflow. */
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

}

void bigarithmetic::mult(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {

}

void bigarithmetic::div(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {

}

void bigarithmetic::rem(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {

}

void bigarithmetic::left_shift(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {

}

void bigarithmetic::right_shift(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {

}

bool bigarithmetic::bigger_than(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
  return true;
}

}
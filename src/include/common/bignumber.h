/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef BIGNUMBER_H
#define BIGNUMBER_H

#include <string.h>
#include <stdint.h>

#include "common/random.h"

namespace cryptography {

#define BIT32_MSB       0x8000'0000
#define BIT32_LSB       0x0000'0001

#define MASK_BIT32_LSB  0x7FFF'FFFF
#define MASK_BIT32_MSB  0xFFFF'FFFE

#define BIT32_MAX       0xFFFF'FFFF

#define BINT_BYTE_SIZE(x) ((x) >> 3)
#define BINT_UNIT_SIZE(x) ((x) >> 5)

#define NPRIMELITY_TESTS  20

template <int32_t BitSize> class biguint;
template <int32_t BitSize> class arithmetic;
template <int32_t BitSize> class mathematics;

template <int32_t BitSize>
class biguint {
 public:
  biguint() noexcept : value_{0} {};

  biguint(biguint &inst) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  biguint(const biguint &inst) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  biguint(biguint &&inst) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  biguint(const biguint &&inst) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  biguint(uint32_t (&value)[BINT_UNIT_SIZE(BitSize)]) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), value, BINT_UNIT_SIZE(BitSize));
  };

  biguint(const uint32_t (&value)[BINT_UNIT_SIZE(BitSize)]) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), value, BINT_UNIT_SIZE(BitSize));
  };

  biguint(uint32_t value) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), &value, 1);
  };

  ~biguint() {};

  /*********************/
  /* Utillity methods. */
  /*********************/
  int32_t bitsize() noexcept {
    return BIT_SIZE;
  };

  bool is_prime() noexcept {
    biguint<BitSize> out = this->value_;
    return mathematics_.is_prime(out);
  }

  /***************************/
  /* Substitution functions. */
  /***************************/
  biguint operator=(biguint &inst) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return *this;
  };

  biguint operator=(const biguint &inst) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return *this;
  };

  /***********************/
  /* Addition functions. */
  /***********************/
  biguint operator+(biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.add(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator+(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.add(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /**************************/
  /* Subtraction functions. */
  /**************************/
  biguint operator-(biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.subtract(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator-(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.subtract(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /*****************************/
  /* Multiplication functions. */
  /*****************************/
  biguint operator*(biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.multiply(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator*(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.multiply(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /***********************/
  /* Division functions. */
  /***********************/
  biguint operator/(biguint &inst) noexcept {
    biguint<BitSize> out = this->value_;
    arithmetic_.divide(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator/(const biguint &inst) noexcept {
    biguint<BitSize> out = this->value_;
    arithmetic_.divide(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /*********************/
  /* Modulo functions. */
  /*********************/
  biguint operator%(biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.modulo(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator%(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.modulo(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /*************************/
  /* Comparison functions. */
  /*************************/
  bool operator==(const biguint &inst) noexcept { 
    return arithmetic_.equal(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  bool operator!=(const biguint &inst) noexcept { 
    return !arithmetic_.equal(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  bool operator<(const biguint &inst) noexcept { 
    return arithmetic_.greater(inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE), this->value_, BINT_UNIT_SIZE(BitSize));
  };

  bool operator>(const biguint &inst) noexcept { 
    return arithmetic_.greater(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  bool operator<=(const biguint &inst) noexcept { 
    return arithmetic_.no_less(inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE), this->value_, BINT_UNIT_SIZE(BitSize));
  };

  bool operator>=(const biguint &inst) noexcept { 
    return arithmetic_.no_less(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  /******************************/
  /* Bitwise operator function. */
  /******************************/
  biguint operator&(biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.logical_and(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator&(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.logical_and(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator|(biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.logical_or(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator|(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.logical_or(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator^(biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.logical_xor(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  biguint operator^(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.logical_xor(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /********************/
  /* Shift functions. */
  /********************/
  biguint operator<<(const int32_t shift) noexcept { 
    biguint<BitSize> out = this->value_;
    arithmetic_.left_shift(out.value_, shift, BINT_UNIT_SIZE(BitSize));
    return out;
  };

  biguint operator>>(const int32_t &shift) noexcept {
    biguint<BitSize> out = this->value_;
    arithmetic_.right_shift(out.value_, shift, BINT_UNIT_SIZE(BitSize));
    return out;
  };

  /********************/
  /* Other functions. */
  /********************/
  uint32_t& operator[](const uint32_t pos) noexcept { 
    return this->value_[pos];
  };

 private:
  inline void copy(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) const noexcept {
    int32_t end = (xsize <= ysize) ? xsize: ysize;
    int32_t xend = xsize - 1; 
    int32_t yend = ysize - 1; 

    memset(x, 0x00, BINT_BYTE_SIZE(BitSize));
    for (int32_t i = 0; i < end; ++i) {
      x[xend - i] = y[yend - i];
    }
  };

  arithmetic<BitSize> arithmetic_;

  mathematics<BitSize> mathematics_;

  uint32_t value_[BINT_UNIT_SIZE(BitSize)];

  const int32_t BIT_SIZE = BitSize;

  static_assert(0 == (BitSize % 32), "Specify BitSize as a multiple of 32.");
  static_assert(0 != BitSize, "Can not specify 0 for BitSize.");
  static_assert(0 < BitSize, "Negative values cannot be specified for BitSize.");
};

template <int32_t BitSize>
class arithmetic {
 public:
  arithmetic() noexcept {};

  ~arithmetic() {};

  void add(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    uint32_t x_msb = 0;
    uint32_t y_msb = 0;
    bool is_overflow = false;

    for (int32_t xpos = xsize - 1, ypos = ysize - 1; xpos >= 0 && ypos >= 0; --xpos, --ypos) {

      /* The process that the value overflowing from     */
      /* the previous data is added to the current data. */
      if (true == is_overflow) {
        if (BIT32_MAX == x[xpos]) {
          x_msb = BIT32_MSB;
        }
        x[xpos] += BIT32_LSB;
        is_overflow = false;
      }

      /* Check MSB of data. */
      x_msb = (BIT32_MSB == (x[xpos] & BIT32_MSB)) ? BIT32_MSB : 0;
      y_msb = (BIT32_MSB == (y[ypos] & BIT32_MSB)) ? BIT32_MSB : 0;

      /* Check for overflow and calculate. */
      if (BIT32_MSB != x_msb && BIT32_MSB != y_msb) {
        x[xpos] = x[xpos] + y[ypos];
      } else if (BIT32_MSB == x_msb && 0 == y_msb) {
        x[xpos] = (x[xpos] - BIT32_MSB) + y[ypos];
        if (BIT32_MSB == (x[xpos] & BIT32_MSB)) {
          is_overflow = true;
        } 
        x[xpos] += BIT32_MSB;
      } else if (0 == x_msb && BIT32_MSB == y_msb) {
        x[xpos] = x[xpos] + (y[ypos] - BIT32_MSB);
        if (BIT32_MSB == (x[xpos] & BIT32_MSB)) {
          is_overflow = true;
        } 
        x[xpos] += BIT32_MSB;
      } else {
        x[xpos] = x[xpos] + y[ypos];
        is_overflow = true;
      }
    }
  };

  void subtract(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    bool is_overflow = false;

    for (int32_t xpos = xsize - 1, ypos = ysize - 1; xpos >= 0 && ypos >= 0; --xpos, --ypos) {

      /* The process that the value overflowing from     */
      /* the previous data is added to the current data. */
      if (true == is_overflow) {
        if (0 != x[xpos]) {
          is_overflow = false;
        } else {
          is_overflow = true;
        }
        x[xpos] -= 1;
      }

      /* Check for overflow and calculate. */
      is_overflow = (x[xpos] >= y[ypos]) ? false : true;
      x[xpos] -= y[ypos];
    }
  };

  void multiply(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t bitsize = (ysize << 5) - 1;
    int32_t ypos = 0;
    uint32_t bitmask = 0;
    uint32_t buf[BitSize >> 5] = {0};
    uint32_t out[BitSize >> 5] = {0};

    for (int32_t bit = bitsize; bit >= 0; --bit) {
      ypos = (ysize - 1) - (bit >> 5);
      bitmask = (BIT32_MSB >> (31 - (uint32_t)bit & 0x1F));

      if (bitmask == (y[ypos] & bitmask)) {
        for (int32_t i = 0; i < xsize; ++i) {
          buf[i] = x[i];
        }
        left_shift(buf, bit, xsize);
        add(out, xsize, buf, xsize);
      }
    }

    for (int32_t i = 0; i < xsize; ++i) {
      x[i] = out[i];
    }
  };

  void divide(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t bitsize = (ysize << 5) - 1;
    int32_t shiftwidth = (xsize >= ysize) ? (xsize - ysize) << 5 : (ysize - xsize) << 5;
    uint32_t ypos = 0;
    uint32_t bitmask = 0;
    uint32_t tmp_x[BINT_UNIT_SIZE(BitSize)] = {0};
    uint32_t out[BINT_UNIT_SIZE(BitSize)] = {0};

    for (int32_t i = 0; i < xsize; ++i) {
      tmp_x[i] = x[i];
    }

    for (int32_t bit = bitsize; bit >= 0; --bit) {
      ypos = (ysize - 1) - (bit >> 5);
      bitmask = (BIT32_MSB >> (31 - bit & 0x1F));

      if (bitmask == (y[ypos] & bitmask)) {
        break;
      }
      shiftwidth += 1;
    }

    for (int32_t shift = shiftwidth; shift >= 0; --shift) {
      uint32_t tmp_y[BINT_UNIT_SIZE(BitSize)] = {0};

      for (int32_t xpos = xsize - 1, ypos = ysize - 1; xpos >= 0 && ypos >= 0; --xpos, --ypos) {
        tmp_y[xpos] = y[ypos];
      }
      left_shift(tmp_y, shift, xsize);

      if (true == no_less(tmp_x, xsize, tmp_y, xsize)) {
        subtract(tmp_x, xsize, tmp_y, xsize);

        /* Clear tmp_y. */
        for (int32_t i = 0; i < xsize - 1; ++i) {
          tmp_y[i] = 0x0000'0000;
        }
        tmp_y[BINT_UNIT_SIZE(BitSize) - 1] = BIT32_LSB;

        left_shift(tmp_y, shift, xsize);
        add(out, xsize, tmp_y, xsize);
      }
    }

    for (int32_t i = 0; i < xsize; ++i) {
      x[i] = out[i];
    }
  };

  void modulo(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t bitsize = (ysize << 5) - 1;
    int32_t moveable = (xsize >= ysize) ? (xsize - ysize) << 5 : (ysize - xsize) << 5;
    uint32_t ypos = 0;
    uint32_t bitmask = 0;
    uint32_t out[BINT_UNIT_SIZE(BitSize)] = {0};

    for (int32_t i = 0; i < xsize; ++i) {
      out[i] = x[i];
    }

    for (int32_t bit = bitsize; bit >= 0; --bit) {
      ypos = (ysize - 1) - (bit >> 5);
      bitmask = (BIT32_MSB >> (31 - bit & 0x1F));

      if (bitmask == (y[ypos] & bitmask)) {
        break;
      }
      moveable += 1;
    }

    for (int32_t shift = moveable; shift >= 0; --shift) {
      uint32_t buf1[BINT_UNIT_SIZE(BitSize)] = {0};

      for (int32_t xpos = xsize - 1, ypos = ysize - 1; xpos >= 0 && ypos >= 0; --xpos, --ypos) {
        buf1[xpos] = y[ypos];
      }
      left_shift(buf1, shift, xsize);

      if (true == no_less(out, xsize, buf1, xsize)) {
        subtract(out, xsize, buf1, xsize);
      }
    }

    for (int32_t i = 0; i < xsize; ++i) {
      x[i] = out[i];
    }
  };

  void left_shift(uint32_t *x, const int32_t y, const int32_t xsize) noexcept {
    int32_t bitshift = y & 0x1F;
    int32_t byteshift = y >> 5;
    uint32_t reg[2] = {0};

    /* Bit shift operation to the entire data. */
    if (0 < bitshift) {
      reg[(xsize - 1) & 0x01] = (x[xsize - 1] >> (32 - bitshift));
      x[xsize - 1] <<= bitshift;

      for (int32_t pos = xsize - 2; pos >= 0; --pos) {
        reg[pos & 0x01] = x[pos] >> (32 - bitshift);  /* switch between odd or even. */
        x[pos] = (x[pos] << bitshift) | reg[(pos + 1) & 0x01];
      }
    }

    if (xsize > byteshift) {
      /* Byte shift operation to the entire data. */
      for (int32_t pos = 0; pos < byteshift; ++pos) {
        x[pos] = x[pos + byteshift];
      }

      /* 0 filling process. */
      for (int32_t pos = byteshift; pos > 0; --pos) {
        x[pos] = 0x0000'0000;
      } 
    }
  };

  void right_shift(uint32_t *x, const int32_t y, const int32_t xsize) noexcept {
    int32_t bitshift = y & 0x1F;
    int32_t byteshift = y >> 5;
    uint32_t reg[2] = {0};

    /* Bit shift operation to the entire data. */
    if (0 < bitshift) {
      reg[0] = (x[0] << (32 - bitshift));
      x[0] >>= bitshift;

      for (int32_t pos = 1; pos < xsize; ++pos) {
        reg[pos & 0x01] = x[pos] << (32 - bitshift);  /* switch between odd or even. */
        x[pos] = (x[pos] >> bitshift) | reg[(pos + 1) & 0x01];
      }
    }

    if (xsize > byteshift) {
      /* Byte shift operation to the entire data. */
      for (int32_t pos = xsize - 1; pos >= xsize - byteshift; --pos) {
        x[pos] = x[pos - byteshift];
      }

      /* 0 filling process. */
      for (int32_t pos = 0; pos < byteshift; ++pos) {
        x[pos] = 0x0000'0000;
      }
    }
  };

  bool greater(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t xstart = (xsize >= ysize) ? xsize - ysize : 0;
    int32_t ystart = (xsize >= ysize) ? 0 : ysize - xsize;

    /* Check the value of the larger array size. */
    if (xsize > ysize) {
      for (int32_t xpos = 0; xpos < xstart; ++xpos) {
        if (0 != x[xpos]) {
          return true;
        }
      }
    } else if (xsize < ysize) {
      for (int32_t ypos = 0; ypos < ystart; ++ypos) {
        if (0 != y[ypos]) {
          return false;
        }
      }
    }

    /* Compare 32-bit values with the same number of digits. */
    for (int32_t xpos = xstart, ypos = ystart; xpos < xsize && ypos < ysize; ++xpos, ++ypos) {
      if (x[xpos] > y[ypos]) {
        return true;
      } else if (x[xpos] < y[ypos]) {
        return false;
      }
    }
    return false;
  }

  bool no_less(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t xstart = (xsize >= ysize) ? xsize - ysize : 0;
    int32_t ystart = (xsize >= ysize) ? 0 : ysize - xsize;

    /* Check the value of the larger array size. */
    if (xsize > ysize) {
      for (int32_t xpos = 0; xpos < xstart; ++xpos) {
        if (0 != x[xpos]) {
          return true;
        }
      }
    } else if (xsize < ysize) {
      for (int32_t ypos = 0; ypos < ystart; ++ypos) {
        if (0 != y[ypos]) {
          return false;
        }
      }
    }

    /* Compare 32-bit values with the same number of digits. */
    for (int32_t xpos = xstart, ypos = ystart; xpos < xsize && ypos < ysize; ++xpos, ++ypos) {
      if (x[xpos] > y[ypos]) {
        return true;
      } else if (x[xpos] < y[ypos]) {
        return false;
      }
    }
    return true;
  }

  bool equal(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t xstart = (xsize >= ysize) ? xsize - ysize : 0;
    int32_t ystart = (xsize >= ysize) ? 0 : ysize - xsize;

    /* Check the value of the larger array size. */
    if (xsize > ysize) {
      for (int32_t xpos = 0; xpos < xstart; ++xpos) {
        if (0 != x[xpos]) {
          return false;
        }
      }
    } else if (xsize < ysize) {
      for (int32_t ypos = 0; ypos < ystart; ++ypos) {
        if (0 != y[ypos]) {
          return false;
        }
      }
    }

    /* Compare 32-bit values with the same number of digits. */
    for (int32_t xpos = xstart, ypos = ystart; xpos < xsize && ypos < ysize; ++xpos, ++ypos) {
      if (x[xpos] != y[ypos]) {
        return false;
      }
    }
    return true;
  }

  void logical_and(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t xstart = (xsize >= ysize) ? xsize - ysize : 0;
    int32_t ystart = (xsize >= ysize) ? 0 : ysize - xsize;

    if (xsize > ysize) {
      for (int32_t xpos = 0; xpos < xstart; ++xpos) {
        x[xpos] &= 0x0000'0000;
      }
    }

    for (int32_t xpos = xstart, ypos = ystart; xpos < xsize && ypos < ysize; ++xpos, ++ypos) {
      x[xpos] &= y[ypos];
    }
  }

  void logical_or(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t xstart = (xsize >= ysize) ? xsize - ysize : 0;
    int32_t ystart = (xsize >= ysize) ? 0 : ysize - xsize;

    if (xsize > ysize) {
      for (int32_t xpos = 0; xpos < xstart; ++xpos) {
        x[xpos] |= 0x0000'0000;
      }
    }

    for (int32_t xpos = xstart, ypos = ystart; xpos < xsize && ypos < ysize; ++xpos, ++ypos) {
      x[xpos] |= y[ypos];
    }
  }

  void logical_xor(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t xstart = (xsize >= ysize) ? xsize - ysize : 0;
    int32_t ystart = (xsize >= ysize) ? 0 : ysize - xsize;

    if (xsize > ysize) {
      for (int32_t xpos = 0; xpos < xstart; ++xpos) {
        x[xpos] ^= 0x0000'0000;
      }
    }

    for (int32_t xpos = xstart, ypos = ystart; xpos < xsize && ypos < ysize; ++xpos, ++ypos) {
      x[xpos] ^= y[ypos];
    }
  }
};

template <int32_t BitSize>
class mathematics {
 public:
  mathematics() noexcept {};

  ~mathematics() {};

  void extended_gcd(biguint<BitSize> a, biguint<BitSize> b, biguint<BitSize> &nx, biguint<BitSize> &ny) noexcept {
    biguint<BitSize> x = 0;
    biguint<BitSize> y = 0;

    nx = 0;
    ny = 1;
    while (a % b != 0) {
      biguint<BitSize> q = a / b;
      biguint<BitSize> r = a % b;
      biguint<BitSize> tx = x - q * nx;
      biguint<BitSize> ty = y - q * ny;

      a = b;
      b = r;
      x = nx;
      y = ny;
      nx = tx;
      ny = ty;
    }
  }

  bool is_prime(biguint<BitSize> &n) noexcept {
    if (n == 1 || (n & 0x0000'0001) == 0) {
      return false;
    } else if (n == 2) {
      return true;
    }

    biguint<BitSize> d = n - 1;
    biguint<BitSize> a = 0U;
    biguint<BitSize> t = 0U;
    biguint<BitSize> y = 0U;

    while ((d & 0x0000'0001) == 0) {
      d = d >> 1;
    }

    for (int32_t k = 0; k < NPRIMELITY_TESTS; ++k) {
      for (int32_t i = 0; i < BINT_UNIT_SIZE(BitSize); ++i) {
        a[i] = ramdom_.generate_u32();
      }
      a = (a + 1) % n;
      t = d;
      y = mod_power(a, t, n);

      while ((t != (n - 1)) && (y != 0x0000'0001) && (y != (n - 1))) {
        y = (y * y) % n;
        t = t << 1;
      }
      
      if ((y != n - 1) && (t & 0x0000'0001) == 0) { 
        return false; 
      }
    }
    return true;
  }

 private:
  const biguint<BitSize> mod_power(biguint<BitSize> &base, biguint<BitSize> exp, const biguint<BitSize> &mod) noexcept {
    biguint<BitSize> out = 1;
  
    while (exp > 0) {
      if ((exp & 0x0000'0001) == 0x0000'0001) {
        out = (out * base) % mod;
      }
      base = (base * base) % mod;
      exp = exp >> 1;
    }
    return out;
  }

  random ramdom_;
};

}
#endif

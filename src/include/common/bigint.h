/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef BIGINT_H
#define BIGINT_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

namespace cryptography {

#define BIT32_MSB       0x8000'0000
#define BIT32_LSB       0x0000'0001

#define MASK_BIT32_LSB  0x7FFF'FFFF
#define MASK_BIT32_MSB  0xFFFF'FFFE

#define BIT32_MAX       0xFFFF'FFFF

#define BINT_BYTE_SIZE(x) ((x) >> 3)
#define BINT_UNIT_SIZE(x) ((x) >> 5)

template <int32_t BitSize> class biguint;
template <int32_t BitSize> class bigarithmetic;

template <int32_t BitSize>
class biguint {
 public:
  biguint() noexcept : value_{0} {};

  biguint(biguint &inst) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  biguint(biguint &&inst) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  biguint(const uint32_t value[BINT_UNIT_SIZE(BitSize)]) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), value, BINT_UNIT_SIZE(BitSize));
  };

  ~biguint() {};

  /***************************/
  /* Substitution functions. */
  /***************************/
  const biguint operator=(const uint32_t value) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), value, 1);
    return *this;
  };

  const biguint operator=(const uint32_t value[BINT_UNIT_SIZE(BitSize)]) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), value, BINT_UNIT_SIZE(BitSize));
    return *this;
  };

  const biguint operator=(const biguint &inst) noexcept {
    copy(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return *this;
  };

  /***********************/
  /* Addition functions. */
  /***********************/
  const biguint operator+(const uint32_t value) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.add(out.value_, BINT_UNIT_SIZE(BitSize), &value, 1);
    return out;
  };

  const biguint operator+(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.add(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /**************************/
  /* Subtraction functions. */
  /**************************/
  const biguint operator-(const uint32_t value) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.sub(out.value_, BINT_UNIT_SIZE(BitSize), &value, 1);
    return out;
  };

  const biguint operator-(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.sub(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /*****************************/
  /* Multiplication functions. */
  /*****************************/
  const biguint operator*(const uint32_t value) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.mult(out.value_, BINT_UNIT_SIZE(BitSize), &value, 1);
    return out;
  };

  const biguint operator*(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.mult(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /***********************/
  /* Division functions. */
  /***********************/
  const biguint operator/(const uint32_t value) noexcept {
    biguint<BitSize> out = this->value_;
    bigarith_.div(out.value_, BINT_UNIT_SIZE(BitSize), &value, 1);
    return out;
  };

  const biguint operator/(const biguint &inst) noexcept {
    biguint<BitSize> out = this->value_;
    bigarith_.div(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /*********************/
  /* Modulo functions. */
  /*********************/
  const biguint operator%(const uint32_t value) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.modulo(out.value_, BINT_UNIT_SIZE(BitSize), &value, 1);
    return out;
  };

  const biguint operator%(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.modulo(out.value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
    return out;
  };

  /*************************/
  /* Comparison functions. */
  /*************************/
  const bool operator<(const biguint &inst) noexcept { 
    return bigarith_.greater(inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE), this->value_, BINT_UNIT_SIZE(BIT_SIZE));
  };

  const bool operator>(const biguint &inst) noexcept { 
    return bigarith_.greater(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  const bool operator<=(const biguint &inst) noexcept { 
    return bigarith_.no_less(inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE), this->value_, BINT_UNIT_SIZE(BIT_SIZE));
  };

  const bool operator>=(const biguint &inst) noexcept { 
    return bigarith_.no_less(this->value_, BINT_UNIT_SIZE(BitSize), inst.value_, BINT_UNIT_SIZE(inst.BIT_SIZE));
  };

  /********************/
  /* Shift functions. */
  /********************/
  const biguint operator<<(const int32_t shift) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.left_shift(out.value_, shift, BINT_UNIT_SIZE(BitSize));
    return out;
  };

  const biguint operator>>(const int32_t &shift) noexcept {
    biguint<BitSize> out = this->value_;
    bigarith_.right_shift(out.value_, shift, BINT_UNIT_SIZE(BitSize));
    return out;
  };

  /********************/
  /* Other functions. */
  /********************/
  const uint32_t operator[](const uint32_t pos) noexcept { 
    return this->value_[pos];
  };

 private:
  inline void copy(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) const noexcept {
    int32_t end = (xsize <= ysize) ? xsize: ysize;
    int32_t xend = xsize - 1; 
    int32_t yend = ysize - 1; 

    for (int32_t i = 0; i < end; ++i) {
      x[xend - i] = y[yend - i];
    }
  };

  bigarithmetic<BitSize> bigarith_;

  uint32_t value_[BINT_UNIT_SIZE(BitSize)];

  const int32_t BIT_SIZE = BitSize;

  static_assert(0 == (BitSize % 32), "Specify BitSize as a multiple of 32.");
  static_assert(0 != BitSize, "Can not specify 0 for BitSize.");
  static_assert(0 < BitSize, "Negative values cannot be specified for BitSize.");
};

template <int32_t BitSize>
class bigarithmetic {
 public:
  bigarithmetic() noexcept {};

  ~bigarithmetic() {};

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

  void sub(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
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

  void mult(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t bitsize = (ysize << 5) - 1;
    int32_t unitpos = 0;
    int32_t bitmask = 0;
    uint32_t buf1[BitSize >> 5] = {0};
    uint32_t out[BitSize >> 5] = {0};

    for (int32_t bitpos = bitsize; bitpos >= 0; --bitpos) {
      unitpos = (ysize - 1) - (bitpos >> 5);
      bitmask = (BIT32_MSB >> (31 - bitpos & 0x1F));

      if (bitmask == (y[unitpos] & bitmask)) {
        for (int32_t i = 0; i < xsize; ++i) {
          buf1[i] = x[i];
        }
        left_shift(buf1, bitpos, xsize);
        add(out, xsize, buf1, xsize);
      }
    }

    for (int32_t i = 0; i < xsize; ++i) {
      x[i] = out[i];
    }
  };

  void div(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t bitsize = (ysize << 5) - 1;
    int32_t moveable = (xsize >= ysize) ? (xsize - ysize) << 5 : (ysize - xsize) << 5;
    uint32_t unitpos = 0;
    uint32_t bitmask = 0;
    uint32_t buf2[BitSize >> 5] = {0};
    uint32_t out[BitSize >> 5] = {0};

    for (int32_t i = 0; i < xsize; ++i) {
      buf2[i] = x[i];
    }

    for (int32_t bitpos = bitsize; bitpos >= 0; --bitpos) {
      unitpos = (ysize - 1) - (bitpos >> 5);
      bitmask = (BIT32_MSB >> (31 - bitpos & 0x1F));

      if (bitmask == (y[unitpos] & bitmask)) {
        break;
      }
      moveable += 1;
    }

    for (int32_t shift = moveable; shift >= 0; --shift) {
      uint32_t buf1[BitSize >> 5] = {0};
      uint32_t lsbbit[BitSize >> 5] = {0};
      lsbbit[(BitSize >> 5) - 1] = BIT32_LSB;

      for (int32_t xpos = xsize - 1, ypos = ysize - 1; xpos >= 0 && ypos >= 0; --xpos, --ypos) {
        buf1[xpos] = y[ypos];
      }
      left_shift(buf1, shift, xsize);

      if (true == no_less(buf2, xsize, buf1, ysize)) {
        sub(buf2, xsize, buf1, xsize);
        left_shift(lsbbit, shift, xsize);
        add(out, xsize, lsbbit, xsize);
        for (int32_t i = 0; i < xsize - 1; ++i) {
          lsbbit[i] = 0x0000'0000;
        }
        lsbbit[(BitSize >> 5) - 1] = BIT32_LSB;
      }
    }

    for (int32_t i = 0; i < xsize; ++i) {
      x[i] = out[i];
    }
  };

  void modulo(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    int32_t bitsize = (ysize << 5) - 1;
    int32_t moveable = (xsize >= ysize) ? (xsize - ysize) << 5 : (ysize - xsize) << 5;
    uint32_t unitpos = 0;
    uint32_t bitmask = 0;
    uint32_t out[BitSize >> 5] = {0};

    for (int32_t i = 0; i < xsize; ++i) {
      out[i] = x[i];
    }

    for (int32_t bitpos = bitsize; bitpos >= 0; --bitpos) {
      unitpos = (ysize - 1) - (bitpos >> 5);
      bitmask = (BIT32_MSB >> (31 - bitpos & 0x1F));

      if (bitmask == (y[unitpos] & bitmask)) {
        break;
      }
      moveable += 1;
    }

    for (int32_t shift = moveable; shift >= 0; --shift) {
      uint32_t buf1[BitSize >> 5] = {0};

      for (int32_t xpos = xsize - 1, ypos = ysize - 1; xpos >= 0 && ypos >= 0; --xpos, --ypos) {
        buf1[xpos] = y[ypos];
      }
      left_shift(buf1, shift, xsize);

      if (true == no_less(out, xsize, buf1, xsize)) {
        sub(out, xsize, buf1, xsize);
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
    for (int32_t pos = 0; pos < xsize; ++pos) {
      if (x[pos] > y[pos]) {
        return true;
      } else if (x[pos] < y[pos]) {
        return false;
      }
    }
    return false;
  }

  bool no_less(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    for (int32_t pos = 0; pos < xsize; ++pos) {
      if (x[pos] > y[pos]) {
        return true;
      } else if (x[pos] < y[pos]) {
        return false;
      }
    }
    return true;
  }

  bool equal(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
    for (int32_t pos = 0; pos < xsize; ++pos) {
      if (x[pos] != y[pos]) {
        return false;
      }
    }
    return true;
  }

 private:
  const int32_t BIT_SIZE = BitSize;

  const int32_t BYTE_SIZE = BINT_BYTE_SIZE(BitSize);

  const int32_t UNIT_SIZE = BINT_UNIT_SIZE(BitSize);


};

}
#endif

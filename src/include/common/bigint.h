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

template <int32_t BitSize> class biguint;
template <int32_t BitSize> class bigarithmetic;

template <int32_t BitSize>
class biguint {
 public:
  biguint() noexcept : value_{0} {};

  biguint(biguint &inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize >> 3);
  };

  biguint(biguint &&inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize >> 3);
  };

  biguint(uint32_t *value) noexcept {
    memcpy(this->value_, value, BitSize >> 3);
  };

  biguint(const uint32_t *value) noexcept {
    memcpy(this->value_, value, BitSize >> 3);
  };

  ~biguint() {};

  void get(uint32_t *value) {
    memcpy(value, this->value_, BitSize >> 3);
  };

  uint32_t* operator=(const uint32_t *value) noexcept {
    memcpy(this->value_, value, BitSize >> 3);
    return this->value_;
  };

  const biguint operator=(const biguint &inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize >> 3);
    return *this;
  };

  const biguint operator+(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.add(out.value_, inst.value_, unit_size_);
    return out;
  };

  const biguint operator-(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.sub(out.value_, inst.value_, unit_size_);
    return out;
  };

  const biguint operator*(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.mult(out.value_, inst.value_, unit_size_);
    return out;
  };

  const biguint operator/(const biguint &inst) noexcept {
    biguint<BitSize> out = this->value_;
    bigarith_.div(out.value_, inst.value_, unit_size_);
    return out;
  };

  const biguint operator%(const biguint &inst) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.rem(out.value_, inst.value_, unit_size_);
    return out;
  };

  const bool operator<(const biguint &inst) noexcept { 
    return bigarith_.greater(inst.value_, this->value_, unit_size_);
  };

  const bool operator>(const biguint &inst) noexcept { 
    return bigarith_.greater(this->value_, inst.value_, unit_size_);
  };

  const bool operator<=(const biguint &inst) noexcept { 
    return bigarith_.no_less(inst.value_, this->value_, unit_size_);
  };

  const bool operator>=(const biguint &inst) noexcept { 
    return bigarith_.no_less(this->value_, inst.value_, unit_size_);
  };

  const biguint operator<<(const int32_t &shift) noexcept { 
    biguint<BitSize> out = this->value_;
    bigarith_.left_shift(out.value_, shift, unit_size_);
    return out;
  };

  const biguint operator>>(const int32_t &shift) noexcept {
    biguint<BitSize> out = this->value_;
    bigarith_.right_shift(out.value_, shift, unit_size_);
    return out;
  };

  const uint32_t operator[](const uint32_t pos) noexcept { 
    return this->value_[pos];
  };

 private:
  bigarithmetic<BitSize> bigarith_;

  const int32_t byte_size_ = BitSize >> 3;

  const int32_t unit_size_ = BitSize >> 5;

  uint32_t value_[BitSize >> 5];

  static_assert(0 == (BitSize % 32), "Specify BitSize as a multiple of 32.");
  static_assert(0 != BitSize, "Can not specify 0 for BitSize.");
};

template <int32_t BitSize>
class bigarithmetic {
 public:
  bigarithmetic() noexcept {};

  ~bigarithmetic() {};

  void add(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
    uint32_t x_msb = 0;
    uint32_t y_msb = 0;
    bool is_overflow = false;

    for (int32_t pos = unitsize - 1; pos >= 0; --pos) {

      /* The process that the value overflowing from     */
      /* the previous data is added to the current data. */
      if (true == is_overflow) {
        if (BIT32_MAX == x[pos]) {
          x_msb = BIT32_MSB;
        }
        x[pos] += BIT32_LSB;
        is_overflow = false;
      }

      /* Check MSB of data. */
      x_msb = (BIT32_MSB == (x[pos] & BIT32_MSB)) ? BIT32_MSB : 0;
      y_msb = (BIT32_MSB == (y[pos] & BIT32_MSB)) ? BIT32_MSB : 0;

      /* Check for overflow and calculate. */
      if (BIT32_MSB == x_msb && BIT32_MSB == y_msb) {
        x[pos] = x[pos] + y[pos];
        is_overflow = true;
      } else if (BIT32_MSB == x_msb && 0 == y_msb) {
        x[pos] = (x[pos] - BIT32_MSB) + y[pos];
        if (BIT32_MSB == (x[pos] & BIT32_MSB)) {
          is_overflow = true;
        } 
        x[pos] += BIT32_MSB;
      } else if (0 == x_msb && BIT32_MSB == y_msb) {
        x[pos] = x[pos] + (y[pos] - BIT32_MSB);
        if (BIT32_MSB == (x[pos] & BIT32_MSB)) {
          is_overflow = true;
        } 
        x[pos] += BIT32_MSB;
      } else {
        x[pos] = x[pos] + y[pos];
      }
    }
  };

  void sub(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
    bool is_overflow = false;

    for (int32_t pos = unitsize - 1; pos >= 0; --pos) {

      /* The process that the value overflowing from     */
      /* the previous data is added to the current data. */
      if (true == is_overflow) {
        if (0 != x[pos]) {
          is_overflow = false;
        } else {
          is_overflow = true;
        }
        x[pos] -= 1;
      }

      /* Check for overflow and calculate. */
      is_overflow = (x[pos] >= y[pos]) ? false : true;
      x[pos] -= y[pos];
    }
  };

  void mult(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
    int32_t bitsize = BitSize - 1;
    int32_t bytesize = (BitSize >> 3) - 1;
    int32_t unitpos = 0;
    int32_t bitmask = 0;
    uint32_t buf1[BitSize >> 5] = {0};
    uint32_t out[BitSize >> 5] = {0};

    for (int32_t bitpos = bitsize; bitpos >= 0; --bitpos) {
      unitpos = (unitsize - 1) - (bitpos >> 5);
      bitmask = (0x8000'0000 >> (31 - bitpos & 0x1F));

      if (bitmask == (y[unitpos] & bitmask)) {
        for (int32_t i = 0; i < unitsize; ++i) {
          buf1[i] = x[i];
        }
        left_shift(buf1, bitpos, unitsize);
        add(out, buf1, unitsize);
      }
    }

    for (int32_t i = 0; i < unitsize; ++i) {
      x[i] = out[i];
    }
  };

  void div(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
    int32_t bitsize = BitSize - 1;
    int32_t bytesize = (BitSize >> 3) - 1;
    int32_t moveable = 0;
    uint32_t unitpos = 0;
    uint32_t bitmask = 0;
    uint32_t buf1[BitSize >> 5] = {0};
    uint32_t buf2[BitSize >> 5] = {0};
    uint32_t lsbbit[BitSize >> 5] = {0};
    uint32_t out[BitSize >> 5] = {0};

    lsbbit[(BitSize >> 5) - 1] = BIT32_LSB;
    for (int32_t i = 0; i < unitsize; ++i) {
      buf2[i] = x[i];
    }

    for (int32_t bitpos = bitsize; bitpos >= 0; --bitpos) {
      unitpos = (unitsize - 1) - (bitpos >> 5);
      bitmask = (0x8000'0000 >> (31 - bitpos & 0x1F));

      if (bitmask == (y[unitpos] & bitmask)) {
        break;
      }
      moveable += 1;
    }

    for (int32_t shift = moveable; shift >= 0; --shift) {
      for (int32_t i = 0; i < unitsize; ++i) {
        buf1[i] = y[i];
      }
      left_shift(buf1, shift, unitsize);

      if (true == no_less(buf2, buf1, unitsize)) {
        sub(buf2, buf1, unitsize);
        left_shift(lsbbit, shift, unitsize);
        add(out, lsbbit, unitsize);
        for (int32_t i = 0; i < unitsize - 1; ++i) {
          lsbbit[i] = 0x0000'0000;
        }
        lsbbit[(BitSize >> 5) - 1] = BIT32_LSB;
      }
    }

    for (int32_t i = 0; i < unitsize; ++i) {
      x[i] = out[i];
    }
  };

  void rem(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
    int32_t bitsize = BitSize - 1;
    int32_t bytesize = (BitSize >> 3) - 1;
    int32_t moveable = 0;
    uint32_t unitpos = 0;
    uint32_t bitmask = 0;
    uint32_t buf1[BitSize >> 5] = {0};
    uint32_t out[BitSize >> 5] = {0};

    for (int32_t i = 0; i < unitsize; ++i) {
      out[i] = x[i];
    }

    for (int32_t bitpos = bitsize; bitpos >= 0; --bitpos) {
      unitpos = (unitsize - 1) - (bitpos >> 5);
      bitmask = (0x8000'0000 >> (31 - bitpos & 0x1F));

      if (bitmask == (y[unitpos] & bitmask)) {
        break;
      }
      moveable += 1;
    }

    for (int32_t shift = moveable; shift >= 0; --shift) {
      for (int32_t i = 0; i < unitsize; ++i) {
        buf1[i] = y[i];
      }
      left_shift(buf1, shift, unitsize);

      if (true == no_less(out, buf1, unitsize)) {
        sub(out, buf1, unitsize);
      }
    }

    for (int32_t i = 0; i < unitsize; ++i) {
      x[i] = out[i];
    }
  };

  void left_shift(uint32_t *x, const int32_t y, const int32_t unitsize) noexcept {
    int32_t bitshift = y & 0x1F;
    int32_t byteshift = y >> 5;
    uint32_t reg[2] = {0};

    /* Bit shift operation to the entire data. */
    if (0 < bitshift) {
      reg[(unitsize - 1) & 0x01] = (x[unitsize - 1] >> (32 - bitshift));
      x[unitsize - 1] <<= bitshift;

      for (int32_t pos = unitsize - 2; pos >= 0; --pos) {
        reg[pos & 0x01] = x[pos] >> (32 - bitshift);  /* switch between odd or even. */
        x[pos] = (x[pos] << bitshift) | reg[(pos + 1) & 0x01];
      }
    }

    if (unitsize > byteshift) {
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

  void right_shift(uint32_t *x, const int32_t y, const int32_t unitsize) noexcept {
    int32_t bitshift = y & 0x1F;
    int32_t byteshift = y >> 5;
    uint32_t reg[2] = {0};

    /* Bit shift operation to the entire data. */
    if (0 < bitshift) {
      reg[0] = (x[0] << (32 - bitshift));
      x[0] >>= bitshift;

      for (int32_t pos = 1; pos < unitsize; ++pos) {
        reg[pos & 0x01] = x[pos] << (32 - bitshift);  /* switch between odd or even. */
        x[pos] = (x[pos] >> bitshift) | reg[(pos + 1) & 0x01];
      }
    }

    if (unitsize > byteshift) {
      /* Byte shift operation to the entire data. */
      for (int32_t pos = unitsize - 1; pos >= unitsize - byteshift; --pos) {
        x[pos] = x[pos - byteshift];
      }

      /* 0 filling process. */
      for (int32_t pos = 0; pos < byteshift; ++pos) {
        x[pos] = 0x0000'0000;
      }
    }
  };

  bool greater(const uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
    for (int32_t pos = 0; pos < unitsize; ++pos) {
      if (x[pos] > y[pos]) {
        return true;
      } else if (x[pos] < y[pos]) {
        return false;
      }
    }
    return false;
  }

  bool no_less(const uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
    for (int32_t pos = 0; pos < unitsize; ++pos) {
      if (x[pos] > y[pos]) {
        return true;
      } else if (x[pos] < y[pos]) {
        return false;
      }
    }
    return true;
  }

  bool equal(const uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept {
    for (int32_t pos = 0; pos < unitsize; ++pos) {
      if (x[pos] != y[pos]) {
        return false;
      }
    }
    return true;
  }
};

}
#endif

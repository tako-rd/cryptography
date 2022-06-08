/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include <stdio.h>
#include <cmath>

#include "common/bignumber.h"


namespace cryptography {

#define BIT32_MSB       0x80000000
#define BIT32_LSB       0x00000001

#define MASK_BIT32_LSB  0x7FFFFFFF
#define MASK_BIT32_MSB  0xFFFFFFFE

#define BIT32_MAX       0xFFFFFFFF

#define CONVERT_BIT_TO_BYTE(x) ((x) >> 3)
#define CONVERT_BIT_TO_UNIT(x) ((x) >> 5)

#define CONVERT_BYTE_TO_BIT(x) ((x) << 3)
#define CONVERT_UNIT_TO_BIT(x) ((x) << 5)

#define CONVERT_BYTE_TO_UNIT(x) ((x) >> 2)
#define CONVERT_UNIT_TO_BYTE(x) ((x) << 2)

#define CONVERT_BYTE_TO_BIT(x) ((x) << 3)
#define CONVERT_UNIT_TO_BIT(x) ((x) << 5)

#define NPRIMELITY_TESTS  20

#define DEFAULT_BIT_SIZE  1024
#define DEFAULT_BYTE_SIZE 128

#define PI                (double)(3.14159265358979)
#define NAPIER            (double)(2.71828182845904)

operation::operation() noexcept {

}

operation::~operation() {}

inline void operation::add(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
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

inline void operation::subtract(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
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
#if 1
inline void operation::multiply(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
  int32_t bitsize = (ysize << 5) - 1;
  int32_t ypos = 0;
  uint32_t bitmask = 0;
  uint32_t *buf = allocator_.allocate(CONVERT_UNIT_TO_BYTE(xsize));
  uint32_t *out = allocator_.allocate(CONVERT_UNIT_TO_BYTE(xsize));

  /* Logic needs improvement. Rush work. */
  memset(buf, 0x00, CONVERT_UNIT_TO_BYTE(xsize));
  memset(out, 0x00, CONVERT_UNIT_TO_BYTE(xsize));

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

  allocator_.deallocate(buf, CONVERT_UNIT_TO_BYTE(xsize));
  allocator_.deallocate(out, CONVERT_UNIT_TO_BYTE(xsize));
};
#else
inline void operation::multiply(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {

};
#endif

#if 1
inline void operation::divide(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
  int32_t bitsize = (ysize << 5) - 1;
  int32_t shiftwidth = (xsize >= ysize) ? (xsize - ysize) << 5 : (ysize - xsize) << 5;
  int32_t xpos = 0;
  int32_t ypos = 0;
  uint32_t bitmask = 0;
  uint32_t *tmp_x = allocator_.allocate(CONVERT_UNIT_TO_BYTE(xsize));
  uint32_t *tmp_y = allocator_.allocate(CONVERT_UNIT_TO_BYTE(xsize));
  uint32_t *out = allocator_.allocate(CONVERT_UNIT_TO_BYTE(xsize));

  memset(tmp_x, 0x00, CONVERT_UNIT_TO_BYTE(xsize));
  memset(out, 0x00, CONVERT_UNIT_TO_BYTE(xsize));

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
    memset(tmp_y, 0x00, CONVERT_UNIT_TO_BYTE(xsize));

    for (xpos = xsize - 1, ypos = ysize - 1; xpos >= 0 && ypos >= 0; --xpos, --ypos) {
      tmp_y[xpos] = y[ypos];
    }
    left_shift(tmp_y, shift, xsize);

    if (true == no_less(tmp_x, xsize, tmp_y, xsize)) {
      subtract(tmp_x, xsize, tmp_y, xsize);

      /* Clear tmp_y. */
      for (int32_t i = 0; i < xsize - 1; ++i) {
        tmp_y[i] = 0x00000000;
      }
      tmp_y[xsize - 1] = BIT32_LSB;

      left_shift(tmp_y, shift, xsize);
      add(out, xsize, tmp_y, xsize);
    }
  }

  for (int32_t i = 0; i < xsize; ++i) {
    x[i] = out[i];
  }

  allocator_.deallocate(tmp_x, CONVERT_UNIT_TO_BYTE(xsize));
  allocator_.deallocate(tmp_y, CONVERT_UNIT_TO_BYTE(xsize));
  allocator_.deallocate(out, CONVERT_UNIT_TO_BYTE(xsize));
};
#else
inline void operation::divide(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {

};
#endif

#if 1
inline void operation::modulo(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
  int32_t bitsize = (ysize << 5) - 1;
  int32_t moveable = (xsize >= ysize) ? (xsize - ysize) << 5 : (ysize - xsize) << 5;
  int32_t xpos = 0;
  int32_t ypos = 0;
  uint32_t bitmask = 0;
  uint32_t *buf1 = allocator_.allocate(CONVERT_UNIT_TO_BYTE(xsize));

  for (int32_t bit = bitsize; bit >= 0; --bit) {
    ypos = (ysize - 1) - (bit >> 5);
    bitmask = (BIT32_MSB >> (31 - bit & 0x1F));

    if (bitmask == (y[ypos] & bitmask)) {
      break;
    }
    moveable += 1;
  }

  for (int32_t shift = moveable; shift >= 0; --shift) {
    memset(buf1, 0x00, CONVERT_UNIT_TO_BYTE(xsize));

    for (xpos = xsize - 1, ypos = ysize - 1; xpos >= 0 && ypos >= 0; --xpos, --ypos) {
      buf1[xpos] = y[ypos];
    }
    left_shift(buf1, shift, xsize);

    if (true == no_less(x, xsize, buf1, xsize)) {
      subtract(x, xsize, buf1, xsize);
    }
  }
  allocator_.deallocate(buf1, CONVERT_UNIT_TO_BYTE(xsize));
};
#else
inline void operation::modulo(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {

};
#endif

inline void operation::left_shift(uint32_t *x, const int32_t shift, const int32_t xsize) noexcept {
  int32_t bitshift = shift & 0x1F;
  int32_t byteshift = shift >> 5;
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
      x[pos] = 0x00000000;
    }
  }
};

inline void operation::right_shift(uint32_t *x, const int32_t shift, const int32_t xsize) noexcept {
  int32_t bitshift = shift & 0x1F;
  int32_t byteshift = shift >> 5;
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
      x[pos] = 0x00000000;
    }
  }
};

inline bool operation::greater(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
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

inline bool operation::no_less(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
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

inline bool operation::equal(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
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

inline void operation::logical_and(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
  int32_t xstart = (xsize >= ysize) ? xsize - ysize : 0;
  int32_t ystart = (xsize >= ysize) ? 0 : ysize - xsize;

  if (xsize > ysize) {
    for (int32_t xpos = 0; xpos < xstart; ++xpos) {
      x[xpos] &= 0x00000000;
    }
  }

  for (int32_t xpos = xstart, ypos = ystart; xpos < xsize && ypos < ysize; ++xpos, ++ypos) {
    x[xpos] &= y[ypos];
  }
}

inline void operation::logical_or(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
  int32_t xstart = (xsize >= ysize) ? xsize - ysize : 0;
  int32_t ystart = (xsize >= ysize) ? 0 : ysize - xsize;

  if (xsize > ysize) {
    for (int32_t xpos = 0; xpos < xstart; ++xpos) {
      x[xpos] |= 0x00000000;
    }
  }

  for (int32_t xpos = xstart, ypos = ystart; xpos < xsize && ypos < ysize; ++xpos, ++ypos) {
    x[xpos] |= y[ypos];
  }
}

void operation::logical_xor(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept {
  int32_t xstart = (xsize >= ysize) ? xsize - ysize : 0;
  int32_t ystart = (xsize >= ysize) ? 0 : ysize - xsize;

  if (xsize > ysize) {
    for (int32_t xpos = 0; xpos < xstart; ++xpos) {
      x[xpos] ^= 0x00000000;
    }
  }

  for (int32_t xpos = xstart, ypos = ystart; xpos < xsize && ypos < ysize; ++xpos, ++ypos) {
    x[xpos] ^= y[ypos];
  }
}

bignumber::bignumber() noexcept {

}

bignumber::bignumber(bignumber &inst) noexcept {
  copy(inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
}

bignumber::bignumber(const bignumber &inst) noexcept {
  copy(inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
}

bignumber::bignumber(bignumber &&inst) noexcept {
  copy(inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
}

bignumber::bignumber(const bignumber &&inst) noexcept {
  copy(inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
}

bignumber::bignumber(const uint32_t value) noexcept {
  copy(&value, 1);
}

bignumber::bignumber(const uint32_t *value, const int32_t bytesize) noexcept {
  copy(value, CONVERT_BYTE_TO_UNIT(bytesize));
}

bignumber::~bignumber() {
  destroy();
}

/*********************/
/* Utillity methods. */
/*********************/
void bignumber::resize(const int32_t bitsize) noexcept {
  if (nullptr == value_ && 0 == bitsize_) {
    /* When memory is not allocated. */
    value_ = allocator_.allocate(CONVERT_BIT_TO_BYTE(bitsize));

  } else if (nullptr != value_ && 0 != bitsize_) {
    /* When memory has been allocated. */

    if (nullptr != value_ && bitsize_ <= bitsize) {
      /* When expanding the size. */
      value_ = allocator_.reallocate(value_, CONVERT_BIT_TO_BYTE(bitsize_), CONVERT_BIT_TO_BYTE(bitsize));

    } else if (nullptr != value_ && bitsize_ > bitsize) {
      /* When reducing the size. */
      uint32_t *value = allocator_.allocate(CONVERT_BIT_TO_BYTE(bitsize));
      memcpy(value, value_, CONVERT_BIT_TO_BYTE(bitsize));
      allocator_.deallocate(value_, CONVERT_BIT_TO_BYTE(bitsize_));
      value_ = value;

    }
  }
  bitsize_ = bitsize;
}

int32_t bignumber::bitsize() noexcept {
  return bitsize_;
}

void bignumber::destroy() noexcept {
  if (nullptr != value_ && bitsize_ != 0) {
    allocator_.deallocate(value_, CONVERT_BIT_TO_BYTE(bitsize_));
    value_ = nullptr;
    bitsize_ = 0;
  }
}

/***************************/
/* Substitution functions. */
/***************************/
bignumber bignumber::operator=(bignumber &inst) noexcept {
  if (nullptr != inst.value_ && 0 != inst.bitsize_) {
    copy(inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return *this;
}

bignumber bignumber::operator=(const bignumber &inst) noexcept {
  if (nullptr != inst.value_ && 0 != inst.bitsize_) {
    copy(inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return *this;
}

/***********************/
/* Addition functions. */
/***********************/
bignumber bignumber::operator+(bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.add(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator+(const bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.add(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

/**************************/
/* Subtraction functions. */
/**************************/
bignumber bignumber::operator-(bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.subtract(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator-(const bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.subtract(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

/*****************************/
/* Multiplication functions. */
/*****************************/
bignumber bignumber::operator*(bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.multiply(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator*(const bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.multiply(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

/***********************/
/* Division functions. */
/***********************/
bignumber bignumber::operator/(bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.divide(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator/(const bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.divide(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

/*********************/
/* Modulo functions. */
/*********************/
bignumber bignumber::operator%(bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.modulo(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator%(const bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.modulo(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

/*************************/
/* Comparison functions. */
/*************************/
bool bignumber::operator==(const bignumber &inst) noexcept {
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    return operation_.equal(this->value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return false;
}

bool bignumber::operator!=(const bignumber &inst) noexcept {
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    return !operation_.equal(this->value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return false;
}

bool bignumber::operator<(const bignumber &inst) noexcept {
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    return operation_.greater(inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_), this->value_, CONVERT_BIT_TO_UNIT(bitsize_));
  }
  return false;
}

bool bignumber::operator>(const bignumber &inst) noexcept {
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    return operation_.greater(this->value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return false;
}

bool bignumber::operator<=(const bignumber &inst) noexcept {
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    return operation_.no_less(inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_), this->value_, CONVERT_BIT_TO_UNIT(bitsize_));
  }
  return false;
}

bool bignumber::operator>=(const bignumber &inst) noexcept {
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    return operation_.no_less(this->value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return false;
}

/******************************/
/* Bitwise operator function. */
/******************************/
bignumber bignumber::operator&(bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.logical_and(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator&(const bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.logical_and(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator|(bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.logical_or(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator|(const bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.logical_or(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator^(bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.logical_xor(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

bignumber bignumber::operator^(const bignumber &inst) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_ && nullptr != inst.value_ && 0 != inst.bitsize_) {
    operation_.logical_xor(out.value_, CONVERT_BIT_TO_UNIT(bitsize_), inst.value_, CONVERT_BIT_TO_UNIT(inst.bitsize_));
  }
  return out;
}

/********************/
/* Shift functions. */
/********************/
bignumber bignumber::operator<<(const int32_t shift) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_) {
    operation_.left_shift(out.value_, shift, CONVERT_BIT_TO_UNIT(bitsize_));
  }
  return out;
}

bignumber bignumber::operator>>(const int32_t &shift) noexcept {
  bignumber out(this->value_, CONVERT_BIT_TO_BYTE(this->bitsize_));
  if (nullptr != value_ && 0 != bitsize_) {
    operation_.right_shift(out.value_, shift, CONVERT_BIT_TO_UNIT(bitsize_));
  }
  return out;
}

/********************/
/* Other functions. */
/********************/
uint32_t& bignumber::operator[](const uint32_t pos) noexcept {
  return this->value_[pos];
}

inline void bignumber::copy(const uint32_t *other, const int32_t othersize) noexcept {
  int32_t end = 0;
  int32_t xend = 0;
  int32_t yend = 0;

  if (nullptr == other || 0 == othersize) { return ; }
  if (nullptr == value_ && 0 == bitsize_) {
    /* When memory is not allocated. */
    value_ = allocator_.allocate(CONVERT_UNIT_TO_BYTE(othersize));
    bitsize_ = CONVERT_UNIT_TO_BIT(othersize);

  } else if (nullptr != value_ && 0 != CONVERT_BIT_TO_UNIT(bitsize_)) {
    /* When memory has been allocated. */
    if (CONVERT_BIT_TO_UNIT(bitsize_) < othersize) {
      value_ = allocator_.reallocate(value_, CONVERT_BIT_TO_BYTE(bitsize_), CONVERT_UNIT_TO_BYTE(othersize));
      bitsize_ = CONVERT_UNIT_TO_BIT(othersize);
    }
  }

  if (nullptr == value_ || 0 == bitsize_) {
    return ;
  }

  xend = (CONVERT_BIT_TO_UNIT(bitsize_) > 0) ? CONVERT_BIT_TO_UNIT(bitsize_) - 1 : othersize - 1;
  yend = othersize - 1;
  end = (0 < xend && CONVERT_BIT_TO_UNIT(bitsize_) <= othersize) ? xend : yend;

  memset(value_, 0x00, CONVERT_BIT_TO_BYTE(bitsize_));
  for (int32_t i = 0; i <= end; ++i) {
    value_[xend - i] = other[yend - i];
  }
}


inline void bignumber::fft() noexcept {

}

inline void bignumber::ifft() noexcept {

}


}

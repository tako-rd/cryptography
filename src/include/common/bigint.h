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

#include <string.h>
#include <stdint.h>

namespace cryptography {

template <int32_t BitSize> class bigint;
template <int32_t BitSize> class biguint;
class bigarithmetic;

template <int32_t BitSize>
class bigint {
 public:
  bigint() noexcept : value_{0} {};

  bigint(bigint &inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize / 8);
  };

  bigint(bigint &&inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize / 8);
  };

  ~bigint() {};

  uint32_t* operator=(uint32_t *value) noexcept {
    memcpy(this->value_, value_, BitSize / 8);
    return this->value_;
  };

  bigint& operator=(bigint &inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize / 8);
    return *this;
  };

  bigint&& operator=(bigint &&inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize / 8);
    return *this;
  };

  bigint& operator+(bigint &inst) noexcept { 
    bigarithmetic::add(this->value_, inst.value_, unit_size_);
    return *this;
  };

  bigint& operator-(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator*(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator/(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator%(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator<(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator>(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator<<(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator>>(bigint &inst) noexcept { 
    return *this;
  };

 private:
  const int32_t byte_size_ = BitSize >> 3;

  const int32_t unit_size_ = BitSize / (sizeof(uint32_t) << 3);

  int32_t value_[BitSize / (sizeof(uint32_t) << 3)];

  static_assert(0 == (BitSize % 32), "Invalid ByteSize.");
  static_assert(0 != BitSize, "Invalid ByteSize.");
};

template <int32_t BitSize>
class biguint {
public:
  biguint() noexcept : value_{0} {};

  biguint(bigint &inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize / 8);
  };

  biguint(bigint &&inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize / 8);
  };

  ~biguint() {};

  uint32_t* operator=(uint32_t *value) noexcept {
    memcpy(this->value_, value_, BitSize / 8);
    return this->value_;
  };

  bigint& operator=(bigint &inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize / 8);
    return *this;
  };

  bigint&& operator=(bigint &&inst) noexcept {
    memcpy(this->value_, inst.value_, BitSize / 8);
    return *this;
  };

  bigint& operator+(bigint &inst) noexcept { 
    bigarithmetic::add(this->value_, inst.value_, unit_size_);
    return *this;
  };

  bigint& operator-(bigint &inst) noexcept { 
    bigarithmetic::sub(this->value_, inst.value_, unit_size_);
    return *this;
  };

  bigint& operator*(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator/(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator%(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator<(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator>(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator<<(bigint &inst) noexcept { 
    return *this;
  };

  bigint& operator>>(bigint &inst) noexcept { 
    return *this;
  };

private:
  const int32_t byte_size_ = BitSize >> 3;

  const int32_t unit_size_ = BitSize / (sizeof(uint32_t) << 3);

  int32_t value_[BitSize / (sizeof(uint32_t) << 3)];

  static_assert(0 == (BitSize % 32), "Invalid ByteSize.");
  static_assert(0 != BitSize, "Invalid ByteSize.");
};

class bigarithmetic {
 public:
  bigarithmetic() noexcept {};

  ~bigarithmetic() {};

  static void add(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept;

  static void sub(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept;

  static void mult(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept;

  static void div(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept;

  static void rem(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept;

  static void left_shift(uint32_t *x, const uint32_t y, const int32_t unitsize) noexcept;

  static void right_shift(uint32_t *x, const uint32_t y, const int32_t unitsize) noexcept;

  static bool bigger_than(uint32_t *x, const uint32_t *y, const int32_t unitsize) noexcept;  
};

}
#endif

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
#include "common/allocator.h"

namespace cryptography {

class bignumber;
class operation;

class operation {
public:
  operation() noexcept;

  ~operation();

  void add(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  void subtract(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  void multiply(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  void divide(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  void modulo(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  void left_shift(uint32_t *x, const int32_t shift, const int32_t xsize) noexcept;

  void right_shift(uint32_t *x, const int32_t shift, const int32_t xsize) noexcept;

  bool greater(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  bool no_less(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  bool equal(const uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  void logical_and(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  void logical_or(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

  void logical_xor(uint32_t *x, const int32_t xsize, const uint32_t *y, const int32_t ysize) noexcept;

private:
  allocator<uint32_t> allocator_;
};

class bignumber {
 public:
  bignumber() noexcept;
  bignumber(bignumber &inst) noexcept;
  bignumber(const bignumber &inst) noexcept;
  bignumber(bignumber &&inst) noexcept;
  bignumber(const bignumber &&inst) noexcept;
  bignumber(const uint32_t value) noexcept;
  bignumber(const uint32_t *value, const int32_t bytesize) noexcept;

  ~bignumber();

  void resize(const int32_t bitsize) noexcept;

  int32_t bitsize() noexcept;

  void destroy() noexcept;

  bignumber operator=(bignumber &inst) noexcept;
  bignumber operator=(const bignumber &inst) noexcept;

  bignumber operator+(bignumber &inst) noexcept;
  bignumber operator+(const bignumber &inst) noexcept;

  bignumber operator-(bignumber &inst) noexcept;
  bignumber operator-(const bignumber &inst) noexcept;

  bignumber operator*(bignumber &inst) noexcept;
  bignumber operator*(const bignumber &inst) noexcept;

  bignumber operator/(bignumber &inst) noexcept;
  bignumber operator/(const bignumber &inst) noexcept;

  bignumber operator%(bignumber &inst) noexcept;
  bignumber operator%(const bignumber &inst) noexcept;

  bool operator==(const bignumber &inst) noexcept;
  bool operator!=(const bignumber &inst) noexcept;

  bool operator<(const bignumber &inst) noexcept;
  bool operator>(const bignumber &inst) noexcept;

  bool operator<=(const bignumber &inst) noexcept;
  bool operator>=(const bignumber &inst) noexcept;

  bignumber operator&(bignumber &inst) noexcept;
  bignumber operator&(const bignumber &inst) noexcept;

  bignumber operator|(bignumber &inst) noexcept;
  bignumber operator|(const bignumber &inst) noexcept;

  bignumber operator^(bignumber &inst) noexcept;
  bignumber operator^(const bignumber &inst) noexcept;

  bignumber operator<<(const int32_t shift) noexcept;
  bignumber operator>>(const int32_t &shift) noexcept;

  uint32_t& operator[](const uint32_t pos) noexcept;

 private:
  void copy(const uint32_t *other, const int32_t othersize) noexcept;

  void fft() noexcept;

  void ifft() noexcept;

  allocator<uint32_t> allocator_;

  operation operation_;

  int32_t bitsize_ = 0;

  uint32_t *value_ = nullptr;
};

}
#endif

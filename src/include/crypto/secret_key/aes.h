/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef AES_H
#define AES_H

#include "crypto/secret_key/secret_key_base.h"

namespace cryptography {

#define SPEED_PRIORITY_AES    1

#if (_M_X64 == 100 || _M_IX86 == 600)
typedef __m128i u128_t;
#elif (_M_ARM == 7)
typedef uint8x16_t u128_t;
#endif

/* Prototype declaration of class. */
class aes_base;
class aes;
class aes_simd;
class aes_ni;

/* Alias declaration */
using AES = aes;
using AESNI = aes_ni;

class aes_base {
 public:
  aes_base() noexcept : padding{0} {};

  ~aes_base() {};

  static const uint32_t UNIT_SIZE = 16;

 private:
  uint32_t padding[4];
};

class aes final : public aes_base, public secret_key_base<aes> { 
 public:
  aes() noexcept : encskeys_{0}, decskeys_{0}, nr_(0), nk_(0), has_subkeys_(false) {};

  ~aes();

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, uint8_t *ctext) noexcept;

  int32_t decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept;

  void clear() noexcept;

 private:
  void expand_key(const uint32_t * const key, uint32_t *encskeys, uint32_t *decskeys) noexcept;

#if !defined(SPEED_PRIORITY_AES)
  uint32_t rot_word(uint32_t word) const noexcept;

  uint32_t sub_word(uint32_t word) const noexcept;

  void sub_bytes(uint8_t *words) const noexcept;

  void inv_sub_bytes(uint8_t *words) const noexcept;

  void shift_rows(uint8_t *words) const noexcept;

  void inv_shift_rows(uint8_t *words) const noexcept;

  void mix_columns(uint8_t *words) const noexcept;

  void inv_mix_columns(uint8_t *words) const noexcept;

  void add_round_key(const uint32_t nr, const uint32_t *key, uint8_t *word) const noexcept;

  uint8_t gf_mult(uint8_t x, uint8_t y) const noexcept;
#endif
  ALIGNAS(32) uint32_t encskeys_[60];

  ALIGNAS(32) uint32_t decskeys_[60];

  int32_t nr_;

  int32_t nk_;

  bool has_subkeys_;
};
#if 0
/* Needs improvement. */
class aes_simd final : public aes_base, public secret_key_base<aes_simd> { 
public:
  aes_simd() noexcept : encskeys_{0}, decskeys_{0}, nr_(0), nk_(0), has_subkeys_(false) {};

  ~aes_simd();

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, uint8_t *ctext) noexcept;

  int32_t decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept;

  void clear() noexcept;

private:
  void expand_key(const uint32_t * const key, uint32_t *encskeys, uint32_t *decskeys) noexcept;

  ALIGNAS(32) uint32_t encskeys_[60];

  ALIGNAS(32) uint32_t decskeys_[60];

  int32_t nr_;

  int32_t nk_;

  bool has_subkeys_;
};
#endif
class aes_ni final : public aes_base, public secret_key_base<aes_ni> { 
public:
  aes_ni() noexcept : encskeys_{0}, decskeys_{0}, nr_(0), has_subkeys_(false) {};

  ~aes_ni();

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, uint8_t *ctext) noexcept;

  int32_t decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept;

  void clear() noexcept;

private:
  void expand_128bit_key(const uint8_t * const key, u128_t *encskeys, u128_t *decskeys) const noexcept;

  void expand_192bit_key(const uint8_t * const key, u128_t *encskeys, u128_t *decskeys) const noexcept;

  void expand_256bit_key(const uint8_t * const key, u128_t *encskeys, u128_t *decskeys) const noexcept;

  u128_t encskeys_[15];

  u128_t decskeys_[15];

  int32_t nr_;

  bool has_subkeys_;
};

}
#endif

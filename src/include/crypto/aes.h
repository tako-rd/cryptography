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

#include "defs.h"

#include "block_cipher.h"

namespace cryptography {

#define SPEED_PRIORITY_AES    1

class aes final : algorithm<aes> { 
 public:
  aes() noexcept : encskeys_{0}, decskeys_{0}, nr_(0), nk_(0), has_subkeys_(false) {};

  ~aes();

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

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

  void add_round_key(const uint32_t nr, uint8_t *word) const noexcept;

  uint8_t gf_mult(uint8_t x, uint8_t y) const noexcept;
#endif

  uint32_t encskeys_[60];

  uint32_t decskeys_[60];

  int32_t nr_;

  int32_t nk_;

  bool has_subkeys_;
};

class aes_ni final : algorithm<aes_ni> { 
public:
  aes_ni() noexcept : encskeys_{0}, decskeys_{0}, nr_(0), nk_(0), has_subkeys_(false) {};

  ~aes_ni();

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

private:
  void expand_128bit_key(const uint8_t * const key, __m128i *encskeys, __m128i *decskeys) const noexcept;

  void expand_192bit_key(const uint8_t * const key, __m128i *encskeys, __m128i *decskeys) const noexcept;

  void expand_256bit_key(const uint8_t * const key, __m128i *encskeys, __m128i *decskeys) const noexcept;

  __m128i encskeys_[15];

  __m128i decskeys_[15];

  int32_t nr_;

  int32_t nk_;

  bool has_subkeys_;
};


}

#endif
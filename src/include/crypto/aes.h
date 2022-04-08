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

#define HIGH_SPEED_AES_MODE    1

class aes final : algorithm<aes> { 
 public:
  aes() noexcept : mode_(AES256), encskeys32bit_{0}, decskeys32bit_{0}, encskeys_{0}, decskeys_{0}, nr_(0), nk_(0), has_subkeys_(false), enable_intrinsic_func_(false) {};

  ~aes();

  int32_t initialize(const uint32_t mode, const uint8_t *key, const uint32_t ksize, bool enable_intrinsic) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

#ifdef ENABLE_FUNCTIONS_FOR_GTEST
  std::vector<uint8_t> get_subkeys_for_unit_test();

  std::vector<uint8_t> get_encskeys_for_unit_test();
#endif

#if 0
  uint32_t calc_mixed_sbox(uint8_t x, uint32_t column);
  
  uint32_t calc_mixed_invsbox(uint8_t x, uint32_t column);
#endif

 private:
  void no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void expand_key(const uint32_t * const key, uint32_t *encskeys, uint32_t *decskeys) const noexcept;

  uint32_t rot_word(uint32_t word) const noexcept;

  uint32_t sub_word(uint32_t word) const noexcept;

#if !defined(HIGH_SPEED_AES_MODE)
  void sub_bytes(uint8_t *words) const noexcept;

  void inv_sub_bytes(uint8_t *words) const noexcept;

  void shift_rows(uint8_t *words) const noexcept;

  void inv_shift_rows(uint8_t *words) const noexcept;

  void mix_columns(uint8_t *words) const noexcept;

  void inv_mix_columns(uint8_t *words) const noexcept;

  void add_round_key(const uint32_t nr, uint8_t *word) const noexcept;

  uint8_t gf_mult(uint8_t x, uint8_t y) const noexcept;
#endif

  uint32_t encskeys32bit_[60];

  uint32_t decskeys32bit_[60];

  __m128i encskeys_[15];

  __m128i decskeys_[15];

  int32_t nr_;

  int32_t nk_;

  uint32_t mode_;

  bool has_subkeys_;

  bool enable_intrinsic_func_;

};

}

#endif
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
#include "bit_utill.h"
#include "byte_utill.h"

#include "block_cipher.h"

namespace cryptography {

class aes final : algorithm<aes> { 
 public:
  aes() noexcept : mode_(AES256), subkeys_{0}, encskeys_{0}, decskeys_{0}, nr_(0), nk_(0), has_subkeys_(false), enable_intrinsic_func_(false) {};

  ~aes();

  int32_t initialize(const uint16_t mode, const uint8_t *key, const uint64_t klen, bool enable_intrinsic) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint64_t plen, uint8_t *ctext, const uint64_t clen) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint64_t clen, uint8_t *ptext, const uint64_t plen) noexcept;

  void clear() noexcept;
#ifdef ENABLE_FUNCTIONS_FOR_GTEST
  std::vector<uint8_t> get_subkeys_for_unit_test();

  std::vector<uint8_t> get_encskeys_for_unit_test();
#endif
 private:
  void no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void expand_key(const union_array_u256_t key, uint32_t *subkeys) const noexcept;

  uint32_t rot_word(const uint32_t word) const noexcept;

  uint32_t sub_word(const uint32_t word) const noexcept;

  void sub_bytes(union_array_u128_t *words) const noexcept;

  void inv_sub_bytes(union_array_u128_t *words) const noexcept;

  void shift_rows(union_array_u128_t *words) const noexcept;

  void inv_shift_rows(union_array_u128_t *words) const noexcept;

  void mix_columns(union_array_u128_t *words) const noexcept;

  void inv_mix_columns(union_array_u128_t *words) const noexcept;

  void add_round_key(const uint32_t nr, union_array_u128_t *word) const noexcept;

  uint8_t gf_mult(uint8_t x, uint8_t y) const noexcept;

  uint32_t subkeys_[60];

  __m128i encskeys_[15];

  __m128i decskeys_[15];

  uint32_t nr_;

  uint32_t nk_;

  uint16_t mode_;

  bool has_subkeys_;

  bool enable_intrinsic_func_;

};

}

#endif
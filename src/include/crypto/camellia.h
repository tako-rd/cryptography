/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef CAMELLIA_H
#define CAMELLIA_H

#include <cstring>
#include <vector>

#include "defs.h"
#include "block_cipher.h"

namespace cryptography {

#define HIGH_SPEED_CAMELLIA_MODE  1

class camellia final : public algorithm<camellia> {
 public:
  camellia() noexcept : mode_(CAMELLIA256), nk_(0), nkl_(0), n6r_(4), kw_{0}, k_{0}, kl_{0}, has_subkeys_(false), enable_intrinsic_func_(false) {};

  ~camellia() {};

  int32_t initialize(const uint32_t mode, const uint8_t *key, const uint32_t klen, bool enable_intrinsic) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t plen, uint8_t *ctext, const uint32_t clen) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t clen, uint8_t *ptext, const uint32_t plen) noexcept;

  void clear() noexcept;
#if 0
  uint32_t calculate_sp32bit(const uint8_t x, const uint32_t sp_number) const noexcept;

  uint64_t calculate_sp64bit(const uint8_t x, const uint32_t sp_number) const noexcept;
#endif
 private:
  void no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void expand_128bit_key(const uint64_t * const key, uint64_t *kw, uint64_t *k, uint64_t *kl) const noexcept;

  void expand_192bit_or_256bit_key(const uint64_t * const key, uint64_t *kw, uint64_t *k, uint64_t *kl) const noexcept;

  uint64_t f_function(uint64_t in, uint64_t key) const noexcept;

  uint64_t fl_function(const uint64_t x, const uint64_t kl) const noexcept;

  uint64_t inv_fl_function(const uint64_t y, const uint64_t kl) const noexcept;

  void s_function(uint8_t *x) const noexcept;
#if !defined(HIGH_SPEED_CAMELLIA_MODE)
  void p_function(uint8_t *x) const noexcept;
#endif
  uint32_t mode_;

  int32_t nk_;

  int32_t nkl_;

  int32_t n6r_;

  uint64_t kw_[4];

  uint64_t k_[24];

  uint64_t kl_[6];

  bool has_subkeys_;

  bool enable_intrinsic_func_;
};

}

#endif
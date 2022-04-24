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

#include "crypto/secret_key/secret_key_base.h"

namespace cryptography {

#define SPEED_PRIORITY_CAMELLIA    1

class camellia final : public secret_key_interface<camellia> {
 public:
  camellia() noexcept : ksize_(0), nk_(0), nkl_(0), n6r_(4), kw_{0}, k_{0}, kl_{0}, has_subkeys_(false) {};

  ~camellia() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

 private:
  void expand_128bit_key(const uint64_t * const key, uint64_t *kw, uint64_t *k, uint64_t *kl) const noexcept;

  void expand_192bit_or_256bit_key(const uint64_t * const key, uint64_t *kw, uint64_t *k, uint64_t *kl) const noexcept;

  uint64_t f_function(uint64_t in, uint64_t key) const noexcept;

  uint64_t fl_function(const uint64_t x, const uint64_t kl) const noexcept;

  uint64_t inv_fl_function(const uint64_t y, const uint64_t kl) const noexcept;

  void s_function(uint8_t *x) const noexcept;
#if !defined(SPEED_PRIORITY_CAMELLIA)
  void p_function(uint8_t *x) const noexcept;
#endif

  uint32_t ksize_;

  int32_t nk_;

  int32_t nkl_;

  int32_t n6r_;

  uint64_t kw_[4];

  uint64_t k_[24];

  uint64_t kl_[6];

  bool has_subkeys_;
};

}

#endif
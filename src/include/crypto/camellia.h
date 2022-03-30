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
#include "bit_utill.h"
#include "byte_utill.h"
#include "block_cipher.h"

namespace cryptography {

class camellia final : public algorithm<camellia> {
 public:
  camellia() noexcept : mode_(CAMELLIA256), n6r_(4), kw_{0}, k_{0}, kl_{0}, has_subkeys_(false), enable_intrinsic_func_(false) {};

  ~camellia() {};

  int32_t initialize(const uint16_t mode, const uint8_t *key, const uint64_t klen, bool enable_intrinsic);

  int32_t encrypt(const char * const ptext, const uint64_t plen, uint8_t *ctext, const uint64_t clen);

  int32_t decrypt(const uint8_t * const ctext, const uint64_t clen, char *ptext, const uint64_t plen);

  void clear() noexcept;

 private:
  void no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void expand_128bit_key(const uint64_t * const key, uint64_t *subkeys) noexcept;

  void expand_192bit_key(const uint64_t * const key, uint64_t *subkeys) noexcept;

  void expand_256bit_key(const uint64_t * const key, uint64_t *subkeys) noexcept;

  uint64_t f_function(const uint64_t in, const uint64_t key) const noexcept;

  uint64_t fl_function(const uint64_t x, const uint64_t kl) const noexcept;

  uint64_t inv_fl_function(const uint64_t y, const uint64_t kl) const noexcept;

  void s_function(uint8_t *state) const noexcept;

  void p_function(uint8_t *state) const noexcept;

  uint16_t mode_;

  uint32_t n6r_;

  uint64_t kw_[4];

  uint64_t k_[24];

  uint64_t kl_[6];

  bool has_subkeys_;

  bool enable_intrinsic_func_;
};

}

#endif
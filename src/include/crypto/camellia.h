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

class camellia final : public algorithm<camellia> {
 public:
  camellia() noexcept : mode_(CAMELLIA256), subkeys_{0}, has_subkeys_(false), enable_intrinsic_func_(false) {};

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

  void expand_key(const union_array_u256_t * const key, uint32_t *subkeys) const noexcept;

  void f_function() noexcept;

  void fl_function() noexcept;

  void inv_fl_function() noexcept;

  void s_function() noexcept;

  void p_function() noexcept;

  uint64_t subkeys_[34];

  uint16_t mode_;

  bool has_subkeys_;

  bool enable_intrinsic_func_;
};

}

#endif
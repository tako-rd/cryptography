/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "algorithm.h"

#ifndef SEED_H
#define SEED_H

namespace cryptography {

#define HIGH_SPEED_SEED_MODE  1

class seed final : public algorithm<seed> {
 public:
  seed() noexcept : mode_(SEED), subkey_{0}, has_subkeys_(false), enable_intrinsic_func_(false) {};

  ~seed() {};

  int32_t initialize(const uint32_t mode, const uint8_t *key, const uint32_t ksize, bool enable_intrinsic) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

 private:
  void no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void expand_key(const uint64_t * const key, uint64_t *skeys) const noexcept;

  uint64_t f_function(uint64_t r, uint64_t k) const noexcept;

  uint32_t g_function(uint32_t r) const noexcept;

  uint32_t mode_;

  uint64_t subkey_[16];

  bool has_subkeys_;

  bool enable_intrinsic_func_;

};

}

#endif

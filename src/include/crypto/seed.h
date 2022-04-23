/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "secret_key_base.h"

#ifndef SEED_H
#define SEED_H

namespace cryptography {

#define SPEED_PRIORITY_SEED   1

class seed final : public secret_key_interface<seed> {
 public:
  seed() noexcept : subkey_{0}, has_subkeys_(false) {};

  ~seed() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

 private:
  void expand_key(uint64_t *key, uint64_t *skeys) const noexcept;

  uint64_t f_function(uint64_t r, uint64_t k) const noexcept;

  uint32_t g_function(uint32_t r) const noexcept;

  uint64_t subkey_[16];

  bool has_subkeys_;
};

}

#endif

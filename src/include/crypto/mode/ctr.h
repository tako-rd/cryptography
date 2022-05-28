/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef CTR_H
#define CTR_H

#include <string.h>

#include "crypto/mode/mode.h"

namespace cryptography {

/* Prototype declaration of class. */
template <typename Cryptosystem, uint32_t UnitSize> class ctr;

/* Alias declaration */
template <typename Cryptosystem, uint32_t UnitSize>
using CTR = ctr<Cryptosystem, UnitSize>;

template <typename Cryptosystem, uint32_t UnitSize>
class ctr : private mode<Cryptosystem, UnitSize> {
 public:
  ctr() noexcept : iv_{0}, has_iv_(false) {};

  ~ctr() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

 private:
  void inc_counter(uint8_t *counter) const noexcept;

  Cryptosystem secret_key_cryptosystem_;

  pkcs7 pkcs7_;

  uint8_t iv_[UnitSize];

  bool has_iv_;
};

}
#endif


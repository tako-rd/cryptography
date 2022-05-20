/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef ECB_H
#define ECB_H

#include "crypto/mode/mode.h"

namespace cryptography {

/* Prototype declaration of class. */
template <typename Cryptosystem, uint32_t UnitSize> class ecb;

/* Alias declaration */
template <typename Cryptosystem, uint32_t UnitSize>
using ECB = ecb<Cryptosystem, UnitSize>;

template <typename Cryptosystem, uint32_t UnitSize>
class ecb : private mode<Cryptosystem, UnitSize> {
 public:
  ecb() noexcept {};

  ~ecb() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv = nullptr, const uint32_t ivsize = 0) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;
};

}

#endif

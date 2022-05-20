/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef CFB_H
#define CFB_H

#include <string.h>

#include "crypto/mode/mode.h"

namespace cryptography {

/* Prototype declaration of class. */
template <typename Cryptosystem, uint32_t UnitSize> class cfb;

/* Alias declaration */
template <typename Cryptosystem, uint32_t UnitSize>
using CFB = cfb<Cryptosystem, UnitSize>;

template <typename Cryptosystem, uint32_t UnitSize>
class cfb : private mode<Cryptosystem, UnitSize> {
 public:
  cfb() noexcept : iv_{0} {};

  ~cfb() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

 private:
  uint8_t iv_[UnitSize];
};

}
#endif

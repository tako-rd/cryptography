/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef PUBLIC_KEY_BASE_H
#define PUBLIC_KEY_BASE_H

#include <stdint.h>
#include <type_traits>

#include "common/simd.h"

namespace cryptography {

/*****************************************************/
/* A template for the public key cryptosystem class. */
/*****************************************************/

template <typename PublicKeyCryptosystem>
class public_key_base {
 public:
  public_key_base() {};

  ~public_key_base() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept {
    return (PublicKeyCryptosystem &)(*this).initialize(key, ksize);
  };

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
    return (PublicKeyCryptosystem &)(*this).encrypt(ptext, psize, ctext, csize);
  };

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
    return (PublicKeyCryptosystem &)(*this).decrypt(ctext, csize, ptext, psize);
  };

  void clear() {
    (PublicKeyCryptosystem &)(*this).clear();
  };

};

}
#endif

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

template <typename PublicKeyCryptosystem> class public_key_base;

template <typename PublicKeyCryptosystem,  
  bool IsValidSharedKeyCryptosystem = std::is_base_of<public_key_base<PublicKeyCryptosystem>, 
                                                      PublicKeyCryptosystem>::value>
class public_key_cryptosystem {
  static_assert(IsValidSharedKeyCryptosystem, 
                "*** ERROR : An invalid public key cryptosystem has been specified.");
};

template <typename PublicKeyCryptosystem>
class public_key_cryptosystem<PublicKeyCryptosystem, true> {
 public:
  public_key_cryptosystem() noexcept {};

  ~public_key_cryptosystem() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept {
    return pkc_.initialize(key, ksize);
  };

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
    return pkc_.encrypt(ptext, psize, ctext, csize);
  };

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
    return pkc_.decrypt(ctext, csize, ptext, psize);
  };

  void clear() const noexcept {
    pkc_.clear();
  };

 private:
   PublicKeyCryptosystem pkc_;
};

/*****************************************************/
/* A template for the public key cryptosystem class. */
/*****************************************************/

template <typename PublicKeyCryptosystem>
class public_key_base {
 public:
  public_key_base() noexcept {};

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

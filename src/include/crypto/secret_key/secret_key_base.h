/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef SECRET_KEY_BASE_H
#define SECRET_KEY_BASE_H

#include <stdint.h>
#include <type_traits>

#include "common/simd.h"

namespace cryptography {

template <typename SecretKeyCryptosystem,  
  bool IsValidSharedKeyCryptosystem = std::is_base_of<secret_key_base<SecretKeyCryptosystem>, 
                                                      SecretKeyCryptosystem>::value>
class secret_key_cryptosystem {
  static_assert(IsValidSharedKeyCryptosystem, 
                "*** ERROR : An invalid secret key cryptosystem has been specified.");
};

template <typename SecretKeyCryptosystem>
class secret_key_cryptosystem<SecretKeyCryptosystem, true> {
 public:
  secret_key_cryptosystem() noexcept {};

  ~secret_key_cryptosystem() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept {
    return skc_.initialize(key, ksize);
  };

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
    return skc_.encrypt(ptext, psize, ctext, csize);
  };

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
    return skc_.decrypt(ctext, csize, ptext, psize);
  };

  void clear() const noexcept {
    skc_.clear();
  };

 private:
  SecretKeyCryptosystem skc_;
};

/*****************************************************/
/* A template for the secret key cryptosystem class. */
/*****************************************************/

template <typename SecretKeyCryptosystem>
class secret_key_base {
public:
  secret_key_base() {};

  ~secret_key_base() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept {
    return (SecretKeyCryptosystem &)(*this).initialize(key, ksize);
  };

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
    return (SecretKeyCryptosystem &)(*this).encrypt(ptext, psize, ctext, csize);
  };

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
    return (SecretKeyCryptosystem &)(*this).decrypt(ctext, csize, ptext, psize);
  };

  void clear() {
    (SecretKeyCryptosystem &)(*this).clear();
  };
};

}

#endif
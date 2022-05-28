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

#include "common/defs.h"
#include "common/simd.h"

namespace cryptography {

template <typename SecretKeyCryptosystem> class secret_key_base;

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

  int32_t encrypt(const uint8_t * const ptext, uint8_t *ctext) noexcept {
    return skc_.encrypt(ptext, ctext);
  };

  int32_t decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept {
    return skc_.decrypt(ctext, ptext);
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

  int32_t encrypt(const uint8_t * const ptext, uint8_t *ctext) noexcept {
    return (SecretKeyCryptosystem &)(*this).encrypt(ptext, ctext);
  };

  int32_t decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept {
    return (SecretKeyCryptosystem &)(*this).decrypt(ctext, ptext);
  };

  void clear() {
    (SecretKeyCryptosystem &)(*this).clear();
  };
};

}

#endif
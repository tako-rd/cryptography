/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "defs.h"

#ifndef ALGORITHM_H
#define ALGORITHM_H

namespace cryptography {

template <typename SharedKeyCryptosystem,  
          bool IsValidSharedKeyCryptosystem = 
            std::is_base_of<secret_key_interface<SharedKeyCryptosystem>, 
                            SharedKeyCryptosystem>::value>
class secret_key {
  static_assert(IsValidSharedKeyCryptosystem, 
                "*** ERROR : An invalid shared key cryptosystem of block cipher has been specified.");
};

template <typename SharedKeyCryptosystem>
class secret_key<SharedKeyCryptosystem, true> {
 public:
  secret_key() {};

  ~secret_key() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept {
    return skc_.initialize(key, ksize);
  };

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
    return skc_.encrypt(ptext, psize, ctext, csize);
  };

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
    return skc_.decrypt(ctext, csize, ptext, psize);
  };

  void clear() {
    skc_.clear();
  };

 private:
  SharedKeyCryptosystem skc_;
};

template <typename SharedKeyCryptosystem>
class secret_key_interface {
public:
  secret_key_interface() {};

  ~secret_key_interface() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept {
    return (SharedKeyCryptosystem &)(*this).initialize(key, ksize);
  };

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
    return (SharedKeyCryptosystem &)(*this).encrypt(ptext, psize, ctext, csize);
  };

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
    return (SharedKeyCryptosystem &)(*this).decrypt(ctext, csize, ptext, psize);
  };

  void clear() {
    (SharedKeyCryptosystem &)(*this).clear();
  };
};

}

#endif
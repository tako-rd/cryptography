/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef SECRET_KEY_H
#define SECRET_KEY_H

#include <stdint.h>
#include <type_traits>

#include "crypto/mode/mode.h"
#include "crypto/mode/ecb.h"
#include "crypto/mode/cbc.h"
#include "crypto/mode/cfb.h"
#include "crypto/mode/ofb.h"
#include "crypto/mode/ctr.h"

namespace cryptography {

/*!
 * Use as follows.
 *  secret_key<DES, CBC> des_cbc;
 *  secret_key<AES, ECB> aes_ecb;
 *  .. etc
**/
template <typename SecretKeyCryptosystem, template <typename T, uint32_t U> class Mode>
class secret_key {
 public:
  secret_key() {};

  ~secret_key() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
    return cryptosystem_.initialize(key, ksize, iv, ivsize);
  };

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
    return cryptosystem_.encrypt(ptext, psize, ctext, csize);
  };

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
    return cryptosystem_.decrypt(ctext, csize, ptext, psize);
  };

  void clear() {
    cryptosystem_.clear();
  };

 private:
  Mode<SecretKeyCryptosystem, SecretKeyCryptosystem::unit_size> cryptosystem_;
};

}

#endif

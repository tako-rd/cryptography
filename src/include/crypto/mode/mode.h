/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef MODE_H
#define MODE_H

#include <stdint.h>

#include "crypto/secret_key/aes.h"
#include "crypto/secret_key/des.h"
#include "crypto/secret_key/camellia.h"
#include "crypto/secret_key/cast128.h"
#include "crypto/secret_key/cast256.h"
#include "crypto/secret_key/rc6.h"
#include "crypto/secret_key/seed.h"
#include "crypto/secret_key/twofish.h"

namespace cryptography {

template <typename Cryptosystem, uint32_t UnitSize>
class mode {
 public:
  mode() {};

  ~mode() {};

  int32_t initialize(const uint8_t key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {};

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {};

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {};

  void clear() noexcept {};

 protected:
   Cryptosystem secret_key_cryptosystem_;
};

}

#endif

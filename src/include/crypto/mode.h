/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <stdint.h>

//#include "aes.h"
//#include "des.h"
//#include "camellia.h"
//#include "cast128.h"
//#include "cast256.h"
//#include "rc6.h"
//#include "seed.h"
//#include "twofish.h"

#ifndef MODE_H
#define MODE_H

namespace cryptography {

template <typename Cryptosystem, uint32_t UnitSize>
class mode {
 public:
  mode() {};

  ~mode() {};

  int32_t initialize(uint8_t *iv, const uint32_t iv_size) noexcept {};

  int32_t encrypt(uint8_t *ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {};

  int32_t decrypt(uint8_t *ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {};

 protected:
  Cryptosystem secret_key_cryptosystem_;
};

}

#endif

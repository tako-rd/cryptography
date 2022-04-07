/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "rc6.h"

namespace cryptography {

int32_t rc6::initialize(const uint32_t mode, const uint8_t *key, const uint32_t klen, bool enable_intrinsic) noexcept {
  return 1;
}

int32_t rc6::encrypt(const uint8_t * const ptext, const uint32_t plen, uint8_t *ctext, const uint32_t clen) noexcept {
  return 1;
}

int32_t rc6::decrypt(const uint8_t * const ctext, const uint32_t clen, uint8_t *ptext, const uint32_t plen) noexcept {
  return 1;
}

void rc6::clear() noexcept {

}

}
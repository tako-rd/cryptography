/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "crypto/public_key/rsa.h"
#include "common/bit_utill.h"
#include "common/endian.h"

namespace cryptography {

int32_t rsa::initialize(const int32_t bit) noexcept {
  return 1;
}

int32_t rsa::encrypt(uint32_t *ptext, const int32_t psize, uint32_t *ctext, const int32_t csize) noexcept {
  return 1;
}

int32_t rsa::decrypt(uint32_t *ctext, const int32_t csize, uint32_t *ptext, const int32_t psize) noexcept {
  return 1;
}

void rsa::clear() noexcept {

}

void rsa_key::create(const int32_t bit) noexcept {
  
}

void rsa_key::destroy(const int32_t bit) noexcept {

}

}
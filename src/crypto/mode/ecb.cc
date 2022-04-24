/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "crypto/mode/ecb.h"

namespace cryptography {

#define SUCCESS           0
#define FAILURE           1

template int32_t ecb<aes, 16>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<aes, 16>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<aes, 16>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

template <typename Cryptosystem, uint32_t UnitSize>
int32_t ecb<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept {
  return (*this).secret_key_cryptosystem_.initialize(key, ksize);
}

template <typename Cryptosystem, uint32_t UnitSize>
int32_t ecb<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  if (0 != psize % UnitSize && 0 != csize % UnitSize) { return FAILURE; }
  for (uint32_t byte = 0; byte < csize; byte += UnitSize) {
    (*this).secret_key_cryptosystem_.encrypt(&ptext[byte], UnitSize, &ctext[byte], UnitSize);
  }
  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
int32_t ecb<Cryptosystem, UnitSize>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  if (0 != csize % UnitSize && 0 != psize % UnitSize) { return FAILURE; }
  for (uint32_t byte = 0; byte < csize; byte += UnitSize) {
    (*this).secret_key_cryptosystem_.decrypt(&ctext[byte], UnitSize, &ptext[byte], UnitSize);
  }
  return SUCCESS;
}

};
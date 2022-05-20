/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "crypto/mode/ofb.h"

namespace cryptography {

#define SUCCESS           0
#define FAILURE           1

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ofb<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
  if (FAILURE == (*this).secret_key_cryptosystem_.initialize(key, ksize)) {
    return FAILURE;
  }

  if (UnitSize != ivsize) {
    return FAILURE;
  }
  memcpy(iv_, iv, UnitSize);

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ofb<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  int32_t byte = 0;
  int32_t end = (int32_t)(psize / UnitSize) * UnitSize;
  uint8_t mask[UnitSize] = {0};
  uint8_t buf[UnitSize] = {0};

  if (0 != csize % UnitSize || ((uint32_t)(psize / UnitSize) >= (uint32_t)(csize / UnitSize))) { return FAILURE; }

  (*this).secret_key_cryptosystem_.encrypt(iv_, UnitSize, mask, UnitSize);
  for (uint32_t i = 0; i < UnitSize; ++i) {
    ctext[i] = ptext[i] ^ mask[i];
  }

  for (byte = UnitSize; byte < end; byte += UnitSize) {
    (*this).secret_key_cryptosystem_.encrypt(mask, UnitSize, mask, UnitSize);
    for (uint32_t i = 0; i < UnitSize; ++i) {
      ctext[byte + i] = ptext[byte + i] ^ mask[i];
    }
  }

  for (int32_t i = 0, j = byte; j < psize; ++i, ++j) {
    buf[i] = ptext[j];
  }
  pkcs7_.add(buf, psize, UnitSize);

  (*this).secret_key_cryptosystem_.encrypt(mask, UnitSize, mask, UnitSize);
  for (uint32_t i = 0; i < UnitSize; ++i) {
    ctext[byte + i] = buf[i] ^ mask[i];
  }

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ofb<Cryptosystem, UnitSize>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  int32_t byte = 0;
  uint8_t mask[UnitSize] = {0};

  if (0 != csize % UnitSize || 0 != psize % UnitSize || csize > psize) { return FAILURE; }

  (*this).secret_key_cryptosystem_.encrypt(iv_, UnitSize, mask, UnitSize);
  for (uint32_t i = 0; i < UnitSize; ++i) {
    ptext[i] = ctext[i] ^ mask[i];
  }

  for (byte = UnitSize; byte < psize; byte += UnitSize) {
    (*this).secret_key_cryptosystem_.encrypt(mask, UnitSize, mask, UnitSize);
    for (uint32_t i = 0; i < UnitSize; ++i) {
      ptext[byte + i] = ctext[byte + i] ^ mask[i];
    }
  }
  if (0 != pkcs7_.remove(&ptext[byte - UnitSize], UnitSize)) { return FAILURE; };

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline void ofb<Cryptosystem, UnitSize>::clear() noexcept {
  (*this).secret_key_cryptosystem_.clear();
  memset(iv_, 0x00, UnitSize);
}

/********************************************************************************/
/* Declaration of materialization.                                              */
/* This class does not accept anything other than the following instantiations: */
/********************************************************************************/

/* AES */
template int32_t ofb<aes, aes::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<aes, aes::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<aes, aes::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<aes, aes::unit_size>::clear() noexcept;

/* AES-NI */
template int32_t ofb<aes_ni, aes_ni::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<aes_ni, aes_ni::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<aes_ni, aes_ni::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<aes_ni, aes_ni::unit_size>::clear() noexcept;

/* Camellia */
template int32_t ofb<camellia, camellia::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<camellia, camellia::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<camellia, camellia::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<camellia, camellia::unit_size>::clear() noexcept;

/* Cast128 */
template int32_t ofb<cast128, cast128::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<cast128, cast128::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<cast128, cast128::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<cast128, cast128::unit_size>::clear() noexcept;

/* Cast256 */
template int32_t ofb<cast256, cast256::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<cast256, cast256::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<cast256, cast256::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<cast256, cast256::unit_size>::clear() noexcept;

/* DES */
template int32_t ofb<des, des::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<des, des::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<des, des::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<des, des::unit_size>::clear() noexcept;

/* RC6 */
template int32_t ofb<rc6, rc6::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<rc6, rc6::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<rc6, rc6::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<rc6, rc6::unit_size>::clear() noexcept;

/* Seed */
template int32_t ofb<seed, seed::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<seed, seed::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<seed, seed::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<seed, seed::unit_size>::clear() noexcept;

/* twofish */
template int32_t ofb<twofish, twofish::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<twofish, twofish::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<twofish, twofish::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<twofish, twofish::unit_size>::clear() noexcept;

}

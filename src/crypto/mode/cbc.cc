/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "crypto/mode/cbc.h"

namespace cryptography {

#define SUCCESS           0
#define FAILURE           1

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t cbc<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
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
inline int32_t cbc<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  int32_t byte = 0;
  int32_t end = (int32_t)(psize / UnitSize) * UnitSize;
  uint8_t buf[UnitSize] = {0};

  if (0 != csize % UnitSize || ((uint32_t)(psize / UnitSize) >= (uint32_t)(csize / UnitSize))) { return FAILURE; }

  for (int32_t i = 0; i < UnitSize; ++i) {
    buf[i] = ptext[i] ^ iv_[i];
  }
  (*this).secret_key_cryptosystem_.encrypt(buf, UnitSize, ctext, UnitSize);

  for (byte = UnitSize; byte < end; byte += UnitSize) {
    for (uint32_t i = 0; i < UnitSize; ++i) {
      buf[i] = ptext[byte + i] ^ ctext[byte + i - UnitSize];
    }
    (*this).secret_key_cryptosystem_.encrypt(buf, UnitSize, &ctext[byte], UnitSize);
  }

  pkcs7_.add(buf, psize, UnitSize);
  if (0 < byte) {
    int32_t j = 0, k = byte;
    for ( ; k < psize; ++j, ++k) {
      buf[j] = ptext[k] ^ ctext[k - UnitSize];
    }

    for ( ; j < UnitSize; ++j, ++k) {
      buf[j] = buf[j] ^ ctext[k - UnitSize];
    }
  } else {
    for (int32_t j = 0, k = byte ; j < psize; ++j, ++k) {
      buf[j] = buf[j] ^ ctext[k - UnitSize];
    }
  }
  (*this).secret_key_cryptosystem_.encrypt(buf, UnitSize, &ctext[byte], UnitSize);

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t cbc<Cryptosystem, UnitSize>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  int32_t byte = 0;
  uint8_t buf[UnitSize] = {0};

  if (0 != csize % UnitSize || 0 != psize % UnitSize || csize > psize) { return FAILURE; }

  (*this).secret_key_cryptosystem_.decrypt(ctext, UnitSize, ptext, UnitSize);
  for (uint32_t i = 0; i < UnitSize; ++i) {
    ptext[i] = ptext[i] ^ iv_[i];
  }

  for (byte = UnitSize; byte < csize; byte += UnitSize) {
    (*this).secret_key_cryptosystem_.decrypt(&ctext[byte], UnitSize, &ptext[byte], UnitSize);

    for (uint32_t i = 0; i < UnitSize; ++i) {
      ptext[byte + i] = ptext[byte + i] ^ ctext[byte + i - UnitSize];
    }
  }
  if (0 != pkcs7_.remove(&ptext[byte - UnitSize], UnitSize)) { return FAILURE; };

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline void cbc<Cryptosystem, UnitSize>::clear() noexcept {
  (*this).secret_key_cryptosystem_.clear();
  memset(iv_, 0x00, UnitSize);
}

/********************************************************************************/
/* Declaration of materialization.                                              */
/* This class does not accept anything other than the following instantiations: */
/********************************************************************************/

/* AES */
template int32_t cbc<aes, aes::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cbc<aes, aes::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<aes, aes::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cbc<aes, aes::unit_size>::clear() noexcept;

/* AES-NI */
template int32_t cbc<aes_ni, aes_ni::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cbc<aes_ni, aes_ni::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<aes_ni, aes_ni::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cbc<aes_ni, aes_ni::unit_size>::clear() noexcept;

/* Camellia */
template int32_t cbc<camellia, camellia::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cbc<camellia, camellia::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<camellia, camellia::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cbc<camellia, camellia::unit_size>::clear() noexcept;

/* Cast128 */
template int32_t cbc<cast128, cast128::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cbc<cast128, cast128::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<cast128, cast128::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cbc<cast128, cast128::unit_size>::clear() noexcept;

/* Cast256 */
template int32_t cbc<cast256, cast256::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cbc<cast256, cast256::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<cast256, cast256::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cbc<cast256, cast256::unit_size>::clear() noexcept;

/* DES */
template int32_t cbc<des, des::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cbc<des, des::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<des, des::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cbc<des, des::unit_size>::clear() noexcept;

/* RC6 */
template int32_t cbc<rc6, rc6::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cbc<rc6, rc6::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<rc6, rc6::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cbc<rc6, rc6::unit_size>::clear() noexcept;

/* Seed */
template int32_t cbc<seed, seed::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cbc<seed, seed::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<seed, seed::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cbc<seed, seed::unit_size>::clear() noexcept;

/* twofish */
template int32_t cbc<twofish, twofish::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cbc<twofish, twofish::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<twofish, twofish::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cbc<twofish, twofish::unit_size>::clear() noexcept;

}
/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "crypto/mode/ecb.h"
#include <stdio.h>
namespace cryptography {

#define SUCCESS           0
#define FAILURE           1

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ecb<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept {
  return (*this).secret_key_cryptosystem_.initialize(key, ksize);
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ecb<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  int32_t byte = 0;
  int32_t end = (int32_t)(psize / UnitSize) * UnitSize;
  uint8_t buf[UnitSize] = {0};

  /* The input ciphertext buffer must be a multiple of UnitSize and UnitSize bytes larger than plaintext. */
  if (0 != csize % UnitSize || ((uint32_t)(psize / UnitSize) >= (uint32_t)(csize / UnitSize))) { return FAILURE; }

  /* Encrypts for the number of bytes equal to the unit byte. */
  for (byte = 0; byte < end; byte += UnitSize) {
    (*this).secret_key_cryptosystem_.encrypt(&ptext[byte], UnitSize, &ctext[byte], UnitSize);
  }

  /* Encrypts less than the remaining unit bytes. */
  for (int32_t i = 0, j = byte; j < psize; ++i, ++j) {
    buf[i] = ptext[j];
  }
  pkcs7_.add(buf, psize, UnitSize);
  (*this).secret_key_cryptosystem_.encrypt(buf, UnitSize, &ctext[byte], UnitSize);

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ecb<Cryptosystem, UnitSize>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  int32_t byte = 0;
  uint8_t buf[UnitSize] = {0};

  /* The ciphertext should always be a multiple of UnitSize and requires a buffer of equivalent size. */
  if (0 != csize % UnitSize || 0 != psize % UnitSize || csize > psize) { return FAILURE; }

  for (byte = 0; byte < csize; byte += UnitSize) {
    (*this).secret_key_cryptosystem_.decrypt(&ctext[byte], UnitSize, &ptext[byte], UnitSize);
  }
  if (0 != pkcs7_.remove(&ptext[byte - UnitSize], UnitSize)) { return FAILURE; };

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline void ecb<Cryptosystem, UnitSize>::clear() noexcept {
  (*this).secret_key_cryptosystem_.clear();
}


/********************************************************************************/
/* Declaration of materialization.                                              */
/* This class does not accept anything other than the following instantiations: */
/********************************************************************************/

/* AES */
template int32_t ecb<aes, aes::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<aes, aes::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<aes, aes::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ecb<aes, aes::unit_size>::clear() noexcept;

/* AES-NI */
template int32_t ecb<aes_ni, aes_ni::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<aes_ni, aes_ni::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<aes_ni, aes_ni::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ecb<aes_ni, aes_ni::unit_size>::clear() noexcept;

/* Camellia */
template int32_t ecb<camellia, camellia::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<camellia, camellia::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<camellia, camellia::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ecb<camellia, camellia::unit_size>::clear() noexcept;

/* Cast128 */
template int32_t ecb<cast128, cast128::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<cast128, cast128::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<cast128, cast128::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ecb<cast128, cast128::unit_size>::clear() noexcept;

/* Cast256 */
template int32_t ecb<cast256, cast256::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<cast256, cast256::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<cast256, cast256::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ecb<cast256, cast256::unit_size>::clear() noexcept;

/* DES */
template int32_t ecb<des, des::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<des, des::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<des, des::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ecb<des, des::unit_size>::clear() noexcept;

/* RC6 */
template int32_t ecb<rc6, rc6::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<rc6, rc6::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<rc6, rc6::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ecb<rc6, rc6::unit_size>::clear() noexcept;

/* Seed */
template int32_t ecb<seed, seed::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<seed, seed::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<seed, seed::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ecb<seed, seed::unit_size>::clear() noexcept;

/* twofish */
template int32_t ecb<twofish, twofish::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ecb<twofish, twofish::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ecb<twofish, twofish::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ecb<twofish, twofish::unit_size>::clear() noexcept;

};
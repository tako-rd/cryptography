/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "crypto/mode/ctr.h"
#include "common/endian.h"

namespace cryptography {

#define SUCCESS           0
#define FAILURE           1

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ctr<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
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
inline int32_t ctr<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  uint8_t counter[UnitSize] = {0};
  uint8_t mask[UnitSize] = {0};

  if (0 != psize % UnitSize && 0 != csize % UnitSize) { return FAILURE; }

  memcpy(counter, iv_, UnitSize);

  (*this).secret_key_cryptosystem_.encrypt(counter, UnitSize, mask, UnitSize);
  for (uint32_t i = 0; i < UnitSize; ++i) {
    ctext[i] = ptext[i] ^ mask[i];
  }

  for (uint32_t byte = UnitSize; byte < psize; byte += UnitSize) {
    inc_counter(counter);
    (*this).secret_key_cryptosystem_.encrypt(counter, UnitSize, mask, UnitSize);

    for (uint32_t i = 0; i < UnitSize; ++i) {
      ctext[byte + i] = ptext[byte + i] ^ mask[i];
    }
  }

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ctr<Cryptosystem, UnitSize>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  uint8_t counter[UnitSize] = {0};
  uint8_t mask[UnitSize] = {0};

  if (0 != csize % UnitSize && 0 != psize % UnitSize) { return FAILURE; }

  memcpy(counter, iv_, UnitSize);

  (*this).secret_key_cryptosystem_.encrypt(counter, UnitSize, mask, UnitSize);
  for (uint32_t i = 0; i < UnitSize; ++i) {
    ptext[i] = ctext[i] ^ mask[i];
  }

  for (uint32_t byte = UnitSize; byte < psize; byte += UnitSize) {
    inc_counter(counter);
    (*this).secret_key_cryptosystem_.encrypt(counter, UnitSize, mask, UnitSize);

    for (uint32_t i = 0; i < UnitSize; ++i) {
      ptext[byte + i] = ctext[byte + i] ^ mask[i];
    }
  }

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline void ctr<Cryptosystem, UnitSize>::inc_counter(uint8_t *counter) const noexcept {
  constexpr uint32_t u64size = UnitSize / 8;
  constexpr uint32_t u64msb = (UnitSize / 8) - 1;
  uint64_t cnt_u64[u64size] = {0};
  uint32_t pos = u64msb;

  endian<BIG, uint64_t, UnitSize>::convert(counter, cnt_u64);

  if (1 == u64size) {
    cnt_u64[u64msb] += 1;
    /* Take care with wraparound. */
  } else {
    while (true) {
      if (0xFFFF'FFFF'FFFF'FFFF == cnt_u64[pos]) {
        cnt_u64[pos] = 0;
        pos = (0 == pos) ? u64msb : pos - 1;
      } else {
        cnt_u64[u64msb] += 1;
        break;
      }
    }
  }

  endian<BIG, uint64_t, UnitSize>::convert(cnt_u64, counter);
}

/********************************************************************************/
/* Declaration of materialization.                                              */
/* This class does not accept anything other than the following instantiations: */
/********************************************************************************/

/* AES */
template int32_t ctr<aes, aes::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<aes, aes::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<aes, aes::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<aes, aes::unit_size>::inc_counter(uint8_t *counter) const noexcept;

/* AES-NI */
template int32_t ctr<aes_ni, aes_ni::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<aes_ni, aes_ni::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<aes_ni, aes_ni::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<aes_ni, aes_ni::unit_size>::inc_counter(uint8_t *counter) const noexcept;

/* Camellia */
template int32_t ctr<camellia, camellia::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<camellia, camellia::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<camellia, camellia::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<camellia, camellia::unit_size>::inc_counter(uint8_t *counter) const noexcept;

/* Cast128 */
template int32_t ctr<cast128, cast128::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<cast128, cast128::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<cast128, cast128::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<cast128, cast128::unit_size>::inc_counter(uint8_t *counter) const noexcept;

/* Cast256 */
template int32_t ctr<cast256, cast256::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<cast256, cast256::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<cast256, cast256::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<cast256, cast256::unit_size>::inc_counter(uint8_t *counter) const noexcept;

/* DES */
template int32_t ctr<des, des::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<des, des::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<des, des::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<des, des::unit_size>::inc_counter(uint8_t *counter) const noexcept;

/* RC6 */
template int32_t ctr<rc6, rc6::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<rc6, rc6::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<rc6, rc6::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<rc6, rc6::unit_size>::inc_counter(uint8_t *counter) const noexcept;

/* Seed */
template int32_t ctr<seed, seed::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<seed, seed::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<seed, seed::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<seed, seed::unit_size>::inc_counter(uint8_t *counter) const noexcept;

/* twofish */
template int32_t ctr<twofish, twofish::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<twofish, twofish::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<twofish, twofish::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<twofish, twofish::unit_size>::inc_counter(uint8_t *counter) const noexcept;

}
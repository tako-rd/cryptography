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

#define SUCCESS                         0
#define FAILURE                         1

#if defined(ENABLE_SSE2) && defined(ENABLE_SSE3)
# define ENCRYPT_XOR(ptxt, msk, out)    _mm_storeu_si128((__m128i *)(out), _mm_xor_si128(_mm_lddqu_si128((__m128i *)(ptxt)), _mm_lddqu_si128((__m128i *)(msk))));
# define DECRYPT_XOR(ctxt, msk, out)    _mm_storeu_si128((__m128i *)(out), _mm_xor_si128(_mm_lddqu_si128((__m128i *)(ctxt)), _mm_lddqu_si128((__m128i *)(msk))));
#else
# define ENCRYPT_XOR(ptxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ptxt + i) ^ *(msk + i); }
# define DECRYPT_XOR(ctxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ctxt + i) ^ *(msk + i); }
#endif

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ctr<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
  if (FAILURE == secret_key_cryptosystem_.initialize(key, ksize)) {
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
  int64_t byte = 0;
  int64_t end = (int64_t)(psize / UnitSize) * UnitSize;
  uint8_t counter[UnitSize] = {0};
  uint8_t mask[UnitSize] = {0};
  uint8_t buf[UnitSize] = {0};

  if (0 != csize % UnitSize || ((uint32_t)(psize / UnitSize) >= (uint32_t)(csize / UnitSize))) { return FAILURE; }

  memcpy(counter, iv_, UnitSize);
  secret_key_cryptosystem_.encrypt(counter, mask);
  ENCRYPT_XOR(ptext, mask, ctext);

  for (byte = UnitSize; byte < end; byte += UnitSize) {
    inc_counter(counter);
    secret_key_cryptosystem_.encrypt(counter, mask);
    ENCRYPT_XOR(&ptext[byte], mask, &ctext[byte]);
  }

  for (int64_t i = 0, j = byte; j < psize; ++i, ++j) {
    buf[i] = ptext[j];
  }
  pkcs7_.add(buf, psize, UnitSize);

  inc_counter(counter);
  secret_key_cryptosystem_.encrypt(counter, mask);
  ENCRYPT_XOR(buf, mask, &ctext[byte]);

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ctr<Cryptosystem, UnitSize>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  int64_t byte = 0;
  uint8_t counter[UnitSize] = {0};
  uint8_t mask[UnitSize] = {0};

  if (0 != csize % UnitSize || 0 != psize % UnitSize || csize > psize) { return FAILURE; }

  memcpy(counter, iv_, UnitSize);
  secret_key_cryptosystem_.encrypt(counter, mask);
  DECRYPT_XOR(ctext, mask, ptext);

  for (byte = UnitSize; byte < psize; byte += UnitSize) {
    inc_counter(counter);
    secret_key_cryptosystem_.encrypt(counter, mask);
    DECRYPT_XOR(&ctext[byte], mask, &ptext[byte]);
  }
  if (0 != pkcs7_.remove(&ptext[byte - UnitSize], UnitSize)) { return FAILURE; };

  return SUCCESS;
}


template <typename Cryptosystem, uint32_t UnitSize>
inline void ctr<Cryptosystem, UnitSize>::clear() noexcept {
  secret_key_cryptosystem_.clear();
  memset(iv_, 0x00, UnitSize);
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
template int32_t ctr<AES, AES::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<AES, AES::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<AES, AES::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<AES, AES::UNIT_SIZE>::clear() noexcept;
template void ctr<AES, AES::UNIT_SIZE>::inc_counter(uint8_t *counter) const noexcept;

/* Camellia */
template int32_t ctr<Camellia, Camellia::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<Camellia, Camellia::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<Camellia, Camellia::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<Camellia, Camellia::UNIT_SIZE>::clear() noexcept;
template void ctr<Camellia, Camellia::UNIT_SIZE>::inc_counter(uint8_t *counter) const noexcept;

/* CAST128 */
template int32_t ctr<CAST128, CAST128::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<CAST128, CAST128::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<CAST128, CAST128::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<CAST128, CAST128::UNIT_SIZE>::clear() noexcept;
template void ctr<CAST128, CAST128::UNIT_SIZE>::inc_counter(uint8_t *counter) const noexcept;

/* CAST256 */
template int32_t ctr<CAST256, CAST256::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<CAST256, CAST256::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<CAST256, CAST256::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<CAST256, CAST256::UNIT_SIZE>::clear() noexcept;
template void ctr<CAST256, CAST256::UNIT_SIZE>::inc_counter(uint8_t *counter) const noexcept;

/* DES */
template int32_t ctr<DES, DES::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<DES, DES::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<DES, DES::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<DES, DES::UNIT_SIZE>::clear() noexcept;
template void ctr<DES, DES::UNIT_SIZE>::inc_counter(uint8_t *counter) const noexcept;

/* RC6 */
template int32_t ctr<RC6, RC6::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<RC6, RC6::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<RC6, RC6::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<RC6, RC6::UNIT_SIZE>::clear() noexcept;
template void ctr<RC6, RC6::UNIT_SIZE>::inc_counter(uint8_t *counter) const noexcept;

/* SEED */
template int32_t ctr<SEED, SEED::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<SEED, SEED::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<SEED, SEED::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<SEED, SEED::UNIT_SIZE>::clear() noexcept;
template void ctr<SEED, SEED::UNIT_SIZE>::inc_counter(uint8_t *counter) const noexcept;

/* Twofish */
template int32_t ctr<Twofish, Twofish::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<Twofish, Twofish::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<Twofish, Twofish::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<Twofish, Twofish::UNIT_SIZE>::clear() noexcept;
template void ctr<Twofish, Twofish::UNIT_SIZE>::inc_counter(uint8_t *counter) const noexcept;

}
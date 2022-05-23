/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "crypto/mode/cfb.h"

namespace cryptography {

#define SUCCESS           0
#define FAILURE           1

#if defined(ENABLE_SSE2) && defined(ENABLE_SSE3)
# define ENCRYPT_XOR(ptxt, msk, out)    _mm_storeu_si128((__m128i *)(out), _mm_xor_si128(_mm_lddqu_si128((__m128i *)(ptxt)), _mm_lddqu_si128((__m128i *)(msk))));
# define DECRYPT_XOR(ctxt, msk, out)    _mm_storeu_si128((__m128i *)(out), _mm_xor_si128(_mm_lddqu_si128((__m128i *)(ctxt)), _mm_lddqu_si128((__m128i *)(msk))));
#else
# define ENCRYPT_XOR(ptxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ptxt + i) ^ *(msk + i); }
# define DECRYPT_XOR(ctxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ctxt + i) ^ *(msk + i); }
#endif

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t cfb<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
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
inline int32_t cfb<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  int64_t byte = 0;
  int64_t end = (int64_t)(psize / UnitSize) * UnitSize;
  uint8_t mask[UnitSize] = {0};
  uint8_t buf[UnitSize] = {0};

  if (0 != csize % UnitSize || ((uint32_t)(psize / UnitSize) >= (uint32_t)(csize / UnitSize))) { return FAILURE; }

  secret_key_cryptosystem_.encrypt(iv_, mask);
  ENCRYPT_XOR(ptext, mask, ctext);

  for (byte = UnitSize; byte < end; byte += UnitSize) {
    secret_key_cryptosystem_.encrypt(&ctext[byte - UnitSize], mask);
    ENCRYPT_XOR(&ptext[byte], mask, &ctext[byte]);
  }

  for (int64_t i = 0, j = byte; j < psize; ++i, ++j) {
    buf[i] = ptext[j];
  }
  pkcs7_.add(buf, psize, UnitSize);

  secret_key_cryptosystem_.encrypt(&ctext[byte - UnitSize], mask);
  ENCRYPT_XOR(buf, mask, &ctext[byte]);

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t cfb<Cryptosystem, UnitSize>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  int64_t byte = 0;
  uint8_t mask[UnitSize] = {0};

  if (0 != csize % UnitSize || 0 != psize % UnitSize || csize > psize) { return FAILURE; }

  secret_key_cryptosystem_.encrypt(iv_, mask);
  DECRYPT_XOR(ctext, mask, ptext);

  for (byte = UnitSize; byte < psize; byte += UnitSize) {
    secret_key_cryptosystem_.encrypt(&ctext[byte - UnitSize], mask);
    DECRYPT_XOR(&ctext[byte], mask, &ptext[byte]);
  }
  if (0 != pkcs7_.remove(&ptext[byte - UnitSize], UnitSize)) { return FAILURE; };

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline void cfb<Cryptosystem, UnitSize>::clear() noexcept {
  secret_key_cryptosystem_.clear();
  memset(iv_, 0x00, UnitSize);
}

/********************************************************************************/
/* Declaration of materialization.                                              */
/* This class does not accept anything other than the following instantiations: */
/********************************************************************************/

/* AES */
template int32_t cfb<AES, AES::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<AES, AES::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<AES, AES::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cfb<AES, AES::UNIT_SIZE>::clear() noexcept;

/* Camellia */
template int32_t cfb<Camellia, Camellia::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<Camellia, Camellia::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<Camellia, Camellia::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cfb<Camellia, Camellia::UNIT_SIZE>::clear() noexcept;

/* CAST128 */
template int32_t cfb<CAST128, CAST128::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<CAST128, CAST128::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<CAST128, CAST128::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cfb<CAST128, CAST128::UNIT_SIZE>::clear() noexcept;

/* CAST256 */
template int32_t cfb<CAST256, CAST256::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<CAST256, CAST256::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<CAST256, CAST256::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cfb<CAST256, CAST256::UNIT_SIZE>::clear() noexcept;

/* DES */
template int32_t cfb<DES, DES::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<DES, DES::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<DES, DES::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cfb<DES, DES::UNIT_SIZE>::clear() noexcept;

/* RC6 */
template int32_t cfb<RC6, RC6::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<RC6, RC6::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<RC6, RC6::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cfb<RC6, RC6::UNIT_SIZE>::clear() noexcept;

/* SEED */
template int32_t cfb<SEED, SEED::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<SEED, SEED::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<SEED, SEED::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cfb<SEED, SEED::UNIT_SIZE>::clear() noexcept;

/* Twofish */
template int32_t cfb<Twofish, Twofish::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<Twofish, Twofish::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<Twofish, Twofish::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cfb<Twofish, Twofish::UNIT_SIZE>::clear() noexcept;

}
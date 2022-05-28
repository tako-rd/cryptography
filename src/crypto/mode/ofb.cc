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

#define SUCCESS                         0x0000'0000
#define UNSET_IV_ERROR                  ((int32_t)module_code_t::MODE       | (int32_t)retcode_t::UNSET_IV)
#define STRING_SIZE_ERROR               ((int32_t)module_code_t::MODE       | (int32_t)retcode_t::INVALID_STRING_SIZE)
#define IV_SIZE_ERROR                   ((int32_t)module_code_t::MODE       | (int32_t)retcode_t::INVALID_IV_SIZE)
#define PADDING_ERROR                   ((int32_t)module_code_t::MODE       | (int32_t)retcode_t::INVALID_PADDING)

#if defined(ENABLE_SSE2) && defined(ENABLE_SSE3)
# define ENCRYPT_XOR(ptxt, msk, out)    _mm_storeu_si128((__m128i *)(out), _mm_xor_si128(_mm_lddqu_si128((__m128i *)(ptxt)), _mm_lddqu_si128((__m128i *)(msk))));
# define DECRYPT_XOR(ctxt, msk, out)    _mm_storeu_si128((__m128i *)(out), _mm_xor_si128(_mm_lddqu_si128((__m128i *)(ctxt)), _mm_lddqu_si128((__m128i *)(msk))));
#else
# define ENCRYPT_XOR(ptxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ptxt + i) ^ *(msk + i); }
# define DECRYPT_XOR(ctxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ctxt + i) ^ *(msk + i); }
#endif

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ofb<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
  int32_t retcode = 0;

  retcode = secret_key_cryptosystem_.initialize(key, ksize);
  if (SUCCESS != retcode) {
    return retcode;
  }

  if (UnitSize != ivsize) {
    return IV_SIZE_ERROR;
  }
  memcpy(iv_, iv, UnitSize);
  has_iv_ = true;

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ofb<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  int64_t byte = 0;
  int64_t end = (int64_t)(psize / UnitSize) * UnitSize;
  uint8_t mask[UnitSize] = {0};
  uint8_t buf[UnitSize] = {0};

  if (0 != csize % UnitSize || ((uint32_t)(psize / UnitSize) >= (uint32_t)(csize / UnitSize))) { return STRING_SIZE_ERROR; }
  if (false == has_iv_) { return UNSET_IV_ERROR; }

  secret_key_cryptosystem_.encrypt(iv_, mask);
  ENCRYPT_XOR(ptext, mask, ctext);

  for (byte = UnitSize; byte < end; byte += UnitSize) {
    secret_key_cryptosystem_.encrypt(mask, mask);
    ENCRYPT_XOR(&ptext[byte], mask, &ctext[byte]);
  }

  for (int64_t i = 0, j = byte; j < psize; ++i, ++j) {
    buf[i] = ptext[j];
  }
  pkcs7_.add(buf, psize, UnitSize);

  secret_key_cryptosystem_.encrypt(mask, mask);
  ENCRYPT_XOR(buf, mask, &ctext[byte]);

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t ofb<Cryptosystem, UnitSize>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  int64_t byte = 0;
  uint8_t mask[UnitSize] = {0};

  if (0 != csize % UnitSize || 0 != psize % UnitSize || csize > psize) { return STRING_SIZE_ERROR; }
  if (false == has_iv_) { return UNSET_IV_ERROR; }

  secret_key_cryptosystem_.encrypt(iv_, mask);
  DECRYPT_XOR(ctext, mask, ptext);

  for (byte = UnitSize; byte < psize; byte += UnitSize) {
    secret_key_cryptosystem_.encrypt(mask, mask);
    DECRYPT_XOR(&ctext[byte], mask, &ptext[byte]);
  }
  if (0 != pkcs7_.remove(&ptext[byte - UnitSize], UnitSize)) { return PADDING_ERROR; };

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline void ofb<Cryptosystem, UnitSize>::clear() noexcept {
  secret_key_cryptosystem_.clear();
  memset(iv_, 0x00, UnitSize);
  has_iv_ = false;
}

/********************************************************************************/
/* Declaration of materialization.                                              */
/* This class does not accept anything other than the following instantiations: */
/********************************************************************************/

/* AES */
template int32_t ofb<AES, AES::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<AES, AES::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<AES, AES::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<AES, AES::UNIT_SIZE>::clear() noexcept;

/* AES-NI */
template int32_t ofb<AESNI, AESNI::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<AESNI, AESNI::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<AESNI, AESNI::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<AESNI, AESNI::UNIT_SIZE>::clear() noexcept;

/* Camellia */
template int32_t ofb<Camellia, Camellia::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<Camellia, Camellia::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<Camellia, Camellia::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<Camellia, Camellia::UNIT_SIZE>::clear() noexcept;

/* CAST128 */
template int32_t ofb<CAST128, CAST128::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<CAST128, CAST128::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<CAST128, CAST128::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<CAST128, CAST128::UNIT_SIZE>::clear() noexcept;

/* CAST256 */
template int32_t ofb<CAST256, CAST256::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<CAST256, CAST256::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<CAST256, CAST256::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<CAST256, CAST256::UNIT_SIZE>::clear() noexcept;

/* DES */
template int32_t ofb<DES, DES::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<DES, DES::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<DES, DES::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<DES, DES::UNIT_SIZE>::clear() noexcept;

/* RC6 */
template int32_t ofb<RC6, RC6::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<RC6, RC6::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<RC6, RC6::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<RC6, RC6::UNIT_SIZE>::clear() noexcept;

/* SEED */
template int32_t ofb<SEED, SEED::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<SEED, SEED::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<SEED, SEED::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<SEED, SEED::UNIT_SIZE>::clear() noexcept;

/* Twofish */
template int32_t ofb<Twofish, Twofish::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ofb<Twofish, Twofish::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ofb<Twofish, Twofish::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ofb<Twofish, Twofish::UNIT_SIZE>::clear() noexcept;

}

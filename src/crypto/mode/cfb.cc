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

#if (defined(ENABLE_SSE2) && defined(ENABLE_SSE3)) && (_M_X64 == 100 || _M_IX86 == 600) 
# define ENCRYPT_XOR128(ptxt, msk, out)   _mm_storeu_si128((__m128i *)(out), _mm_xor_si128(_mm_lddqu_si128((__m128i *)(ptxt)), _mm_lddqu_si128((__m128i *)(msk))));
# define DECRYPT_XOR128(ctxt, msk, out)   _mm_storeu_si128((__m128i *)(out), _mm_xor_si128(_mm_lddqu_si128((__m128i *)(ctxt)), _mm_lddqu_si128((__m128i *)(msk))));

# define ENCRYPT_XOR64(ptxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ptxt + i) ^ *(msk + i); }
# define DECRYPT_XOR64(ctxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ctxt + i) ^ *(msk + i); }

# define ENCRYPT_XOR(ptxt, msk, out)      if (UnitSize == 16) { ENCRYPT_XOR128(ptxt, msk, out); } else { ENCRYPT_XOR64(ptxt, msk, out); }
# define DECRYPT_XOR(ctxt, msk, out)      if (UnitSize == 16) { DECRYPT_XOR128(ctxt, msk, out); } else { DECRYPT_XOR64(ctxt, msk, out); }
#elif defined(ENABLE_ARMNEON) && (_M_ARM == 7)
# define ENCRYPT_XOR128(ptxt, msk, out)   vst1q_u8(out, veorq_u8(vld1q_u8((ptxt)), vld1q_u8((msk))));
# define DECRYPT_XOR128(ctxt, msk, out)   vst1q_u8(out, veorq_u8(vld1q_u8((ctxt)), vld1q_u8((msk))));

# define ENCRYPT_XOR64(ptxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ptxt + i) ^ *(msk + i); }
# define DECRYPT_XOR64(ctxt, msk, out)    for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ctxt + i) ^ *(msk + i); }

# define ENCRYPT_XOR(ptxt, msk, out)      if (UnitSize == 16) { ENCRYPT_XOR128(ptxt, msk, out); } else { ENCRYPT_XOR64(ptxt, msk, out); }
# define DECRYPT_XOR(ctxt, msk, out)      if (UnitSize == 16) { DECRYPT_XOR128(ctxt, msk, out); } else { DECRYPT_XOR64(ctxt, msk, out); }
#else
# define ENCRYPT_XOR(ptxt, msk, out)      for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ptxt + i) ^ *(msk + i); }
# define DECRYPT_XOR(ctxt, msk, out)      for (int64_t i = 0; i < UnitSize; ++i) { *(out + i) = *(ctxt + i) ^ *(msk + i); }
#endif

template <typename Cryptosystem, uint32_t UnitSize>
inline int32_t cfb<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
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
inline int32_t cfb<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  int64_t byte = 0;
  int64_t end = (int64_t)(psize / UnitSize) * UnitSize;
  uint8_t mask[UnitSize] = {0};
  uint8_t buf[UnitSize] = {0};

  if (0 != csize % UnitSize || ((uint32_t)(psize / UnitSize) >= (uint32_t)(csize / UnitSize))) { return STRING_SIZE_ERROR; }
  if (false == has_iv_) { return UNSET_IV_ERROR; }

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

  if (0 != csize % UnitSize || 0 != psize % UnitSize || csize > psize) { return STRING_SIZE_ERROR; }
  if (false == has_iv_) { return UNSET_IV_ERROR; }

  secret_key_cryptosystem_.encrypt(iv_, mask);
  DECRYPT_XOR(ctext, mask, ptext);

  for (byte = UnitSize; byte < psize; byte += UnitSize) {
    secret_key_cryptosystem_.encrypt(&ctext[byte - UnitSize], mask);
    DECRYPT_XOR(&ctext[byte], mask, &ptext[byte]);
  }
  if (0 != pkcs7_.remove(&ptext[byte - UnitSize], UnitSize)) { return PADDING_ERROR; };

  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
inline void cfb<Cryptosystem, UnitSize>::clear() noexcept {
  secret_key_cryptosystem_.clear();
  memset(iv_, 0x00, UnitSize);
  has_iv_ = false;
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

/* AES-NI */
template int32_t cfb<AESNI, AESNI::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<AESNI, AESNI::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<AESNI, AESNI::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void cfb<AESNI, AESNI::UNIT_SIZE>::clear() noexcept;

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
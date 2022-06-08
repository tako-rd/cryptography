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
inline int32_t ctr<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
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
inline int32_t ctr<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  int64_t byte = 0;
  int64_t end = (int64_t)(psize / UnitSize) * UnitSize;
  uint8_t counter[UnitSize] = {0};
  uint8_t mask[UnitSize] = {0};
  uint8_t buf[UnitSize] = {0};

  if (0 != csize % UnitSize || ((uint32_t)(psize / UnitSize) >= (uint32_t)(csize / UnitSize))) { return STRING_SIZE_ERROR; }
  if (false == has_iv_) { return UNSET_IV_ERROR; }

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

  if (0 != csize % UnitSize || 0 != psize % UnitSize || csize > psize) { return STRING_SIZE_ERROR; }
  if (false == has_iv_) { return UNSET_IV_ERROR; }

  memcpy(counter, iv_, UnitSize);
  secret_key_cryptosystem_.encrypt(counter, mask);
  DECRYPT_XOR(ctext, mask, ptext);

  for (byte = UnitSize; byte < psize; byte += UnitSize) {
    inc_counter(counter);
    secret_key_cryptosystem_.encrypt(counter, mask);
    DECRYPT_XOR(&ctext[byte], mask, &ptext[byte]);
  }
  if (0 != pkcs7_.remove(&ptext[byte - UnitSize], UnitSize)) { return PADDING_ERROR; };

  return SUCCESS;
}


template <typename Cryptosystem, uint32_t UnitSize>
inline void ctr<Cryptosystem, UnitSize>::clear() noexcept {
  secret_key_cryptosystem_.clear();
  memset(iv_, 0x00, UnitSize);
  has_iv_ = false;
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
      if (0xFFFFFFFFFFFFFFFF == cnt_u64[pos]) {
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

/* AES-NI */
template int32_t ctr<AESNI, AESNI::UNIT_SIZE>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t ctr<AESNI, AESNI::UNIT_SIZE>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t ctr<AESNI, AESNI::UNIT_SIZE>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;
template void ctr<AESNI, AESNI::UNIT_SIZE>::clear() noexcept;
template void ctr<AESNI, AESNI::UNIT_SIZE>::inc_counter(uint8_t *counter) const noexcept;

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

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

template <typename Cryptosystem, uint32_t UnitSize>
int32_t cfb<Cryptosystem, UnitSize>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept {
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
int32_t cfb<Cryptosystem, UnitSize>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  uint8_t mask[UnitSize] = {0};

  if (0 != psize % UnitSize && 0 != csize % UnitSize) { return FAILURE; }

  (*this).secret_key_cryptosystem_.encrypt(iv_, UnitSize, mask, UnitSize);
  for (uint32_t i = 0; i < UnitSize; ++i) {
    ctext[i] = ptext[i] ^ mask[i];
  }

  for (uint32_t byte = UnitSize; byte < psize; byte += UnitSize) {
    (*this).secret_key_cryptosystem_.encrypt(&ctext[byte - UnitSize], UnitSize, mask, UnitSize);
    for (uint32_t i = 0; i < UnitSize; ++i) {
      ctext[byte + i] = ptext[byte + i] ^ mask[i];
    }
  }
  return SUCCESS;
}

template <typename Cryptosystem, uint32_t UnitSize>
int32_t cfb<Cryptosystem, UnitSize>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  uint8_t mask[UnitSize] = {0};

  if (0 != csize % UnitSize && 0 != psize % UnitSize) { return FAILURE; }

  (*this).secret_key_cryptosystem_.encrypt(iv_, UnitSize, mask, UnitSize);
  for (uint32_t i = 0; i < UnitSize; ++i) {
    ptext[i] = ctext[i] ^ mask[i];
  }

  for (uint32_t byte = UnitSize; byte < psize; byte += UnitSize) {
    (*this).secret_key_cryptosystem_.encrypt(&ctext[byte - UnitSize], UnitSize, mask, UnitSize);
    for (uint32_t i = 0; i < UnitSize; ++i) {
      ptext[byte + i] = ctext[byte + i] ^ mask[i];
    }
  }
  return SUCCESS;
}

/********************************************************************************/
/* Declaration of materialization.                                              */
/* This class does not accept anything other than the following instantiations: */
/********************************************************************************/

/* AES */
template int32_t cfb<aes, aes::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<aes, aes::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<aes, aes::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

/* AES-NI */
template int32_t cfb<aes_ni, aes_ni::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<aes_ni, aes_ni::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<aes_ni, aes_ni::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

/* Camellia */
template int32_t cfb<camellia, camellia::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<camellia, camellia::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<camellia, camellia::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

/* Cast128 */
template int32_t cfb<cast128, cast128::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<cast128, cast128::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<cast128, cast128::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

/* Cast256 */
template int32_t cfb<cast256, cast256::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<cast256, cast256::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<cast256, cast256::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

/* DES */
template int32_t cfb<des, des::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<des, des::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<des, des::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

/* RC6 */
template int32_t cfb<rc6, rc6::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<rc6, rc6::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<rc6, rc6::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

/* Seed */
template int32_t cfb<seed, seed::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<seed, seed::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<seed, seed::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

/* twofish */
template int32_t cfb<twofish, twofish::unit_size>::initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *, const uint32_t) noexcept;
template int32_t cfb<twofish, twofish::unit_size>::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cfb<twofish, twofish::unit_size>::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;


#if 0
int32_t cfb::initialize(const uint16_t type, uint8_t *iv, const uint64_t iv_size) noexcept {
  type_ = type_t(type & EXTRACT_TYPE);
  switch(type_) {
    case DEFAULT:
      unit_size_ = AES_UNIT_SIZE;
    case SIMPLE_DES:
      unit_size_ = DES_UNIT_SIZE;
      break;
    case AES128:
    case AES192:
    case AES256:
      unit_size_ = AES_UNIT_SIZE;
      break;
    default:
      break;
  }

  if (unit_size_ != iv_size) {
    return FAILURE;
  }
  iv_ = iv;

  return SUCCESS;
}

int32_t cfb::enc_preprocess(uint8_t *ptext, const uint64_t psize, uint8_t *cbuf, const uint64_t cbsize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (cbsize != unit_size_) {
    return FAILURE;
  }

  if (false == is_processing_) {
    input_ = ptext;
    key_size_ = psize;
    is_processing_ = true;
  } 

  if (0 == cursor_) {
    for (uint64_t outcsr = 0; outcsr < cursor_end; ++outcsr) {
      cbuf[outcsr] = iv_[outcsr];
    }
  } else {
    for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
      cbuf[outcsr] = key_[incsr - unit_size_];
    }
  }
  return SUCCESS;
}

int32_t cfb::enc_postprocess(uint8_t *cbuf, const uint64_t cbsize, uint8_t *ctext, const uint64_t csize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (cbsize != unit_size_ && csize != key_size_) {
    return FAILURE;
  }

  if (0 == cursor_) {
    key_ = ctext; 
  }

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ctext[outcsr] = input_[outcsr] ^ cbuf[incsr];
  }

  cursor_ += unit_size_;
  if (cursor_ >= key_size_) {
    key_ = nullptr;
    key_size_ = 0;
    input_ = nullptr;
    is_processing_ = false;
    cursor_ = 0;

    return PROCEND;
  }
  return SUCCESS;
}

int32_t cfb::dec_preprocess(uint8_t *ctext, const uint64_t csize, uint8_t *pbuf, const uint64_t pbsize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (pbsize != unit_size_) {
    return FAILURE;
  }

  if (false == is_processing_) {
    input_ = ctext;
    key_size_ = csize;
    is_processing_ = true;
  } 

  if (0 == cursor_) {
    for (uint64_t outcsr = 0; outcsr < cursor_end; ++outcsr) {
      pbuf[outcsr] = iv_[outcsr];
    }
  } else {
    for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
      pbuf[outcsr] = ctext[incsr - unit_size_];
    }
  }
  return SUCCESS;
}

int32_t cfb::dec_postprocess(uint8_t *pbuf, const uint64_t pbsize, uint8_t *ptext, const uint64_t psize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (pbsize != unit_size_ && psize != key_size_) {
    return FAILURE;
  }

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ptext[outcsr] = input_[outcsr] ^ pbuf[incsr];
  }

  cursor_ += unit_size_;
  if (cursor_ >= key_size_) {
    key_ = nullptr;
    key_size_ = 0;
    input_ = nullptr;
    is_processing_ = false;
    cursor_ = 0;

    return PROCEND;
  }
  return SUCCESS;
}
#endif

}
/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "cbc.h"
#include "aes.h"
#include "camellia.h"
#include "cast128.h"
#include "cast256.h"
#include "rc6.h"
#include "seed.h"
#include "twofish.h"

namespace cryptography {

#define DES_UNIT_SIZE     8
#define AES_UNIT_SIZE     16

#define SUCCESS           0
#define FAILURE           1
#define PROCEND           2

#if 0
template int32_t cbc<aes, uint32_t>::initialize(const uint16_t type, uint8_t *iv, const uint64_t iv_size) noexcept;
template int32_t cbc<aes, uint32_t>::enc_preprocess(uint8_t *ptext, const uint64_t psize, uint8_t *cbuf, const uint64_t cbsize) noexcept;
template int32_t cbc<aes, uint32_t>::enc_postprocess(uint8_t *cbuf, const uint64_t cbsize, uint8_t *ctext, const uint64_t csize) noexcept;
template int32_t cbc<aes, uint32_t>::dec_preprocess(uint8_t *ctext, const uint64_t csize, uint8_t *pbuf, const uint64_t pbsize) noexcept;
template int32_t cbc<aes, uint32_t>::dec_postprocess(uint8_t *pbuf, const uint64_t pbsize, uint8_t *ptext, const uint64_t psize) noexcept;
#endif

template int32_t cbc<aes, uint32_t>::initialize(uint8_t *iv, const uint32_t iv_size) noexcept;
template int32_t cbc<aes, uint32_t>::encrypt(uint8_t *ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;
template int32_t cbc<aes, uint32_t>::decrypt(uint8_t *ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

template <typename SharedKeyCryptosystem, typename UnitSize>
int32_t cbc<SharedKeyCryptosystem, UnitSize>::initialize(uint8_t *iv, const uint32_t iv_size) noexcept {
  return SUCCESS;
}

template <typename SharedKeyCryptosystem, typename UnitSize>
int32_t cbc<SharedKeyCryptosystem, UnitSize>::encrypt(uint8_t *ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  uint32_t unit_size = unit_size_;
  uint8_t buffer[16] = {0};

  for (uint32_t byte = 0; byte < psize; byte += unit_size) {
    (*this).secret_key_cryptosystem_.encrypt(ptext[byte], unit_size, ctext[byte], unit_size);
  }

  return SUCCESS;
}

template <typename SharedKeyCryptosystem, typename UnitSize>
int32_t cbc<SharedKeyCryptosystem, UnitSize>::decrypt(uint8_t *ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  uint32_t unit_size = unit_size_;
  uint8_t buffer[16] = {0};

  for (uint32_t byte = 0; byte < psize; byte += unit_size) {
    (*this).secret_key_cryptosystem_.decrypt(ctext[byte], unit_size, ptext[byte], unit_size);
  }

  return SUCCESS;
}


#if 0
template <typename SharedKeyCryptosystem, typename UnitSize>
int32_t cbc<SharedKeyCryptosystem, typename UnitSize>::initialize(const uint16_t type, uint8_t *iv, const uint64_t iv_size) noexcept {
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

template <typename SharedKeyCryptosystem, typename UnitSize>
int32_t cbc<SharedKeyCryptosystem, typename UnitSize>::enc_preprocess(uint8_t *ptext, const uint64_t psize, uint8_t *cbuf, const uint64_t cbsize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (cbsize != unit_size_) {
    return FAILURE;
  }

  if (false == is_processing_) {
    key_size_ = psize;
    is_processing_ = true;
  } 

  if (0 == cursor_) { 
    for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
      cbuf[outcsr] = ptext[incsr] ^ iv_[outcsr];
    }
  } else {
    for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
      cbuf[outcsr] = ptext[incsr] ^ key_[incsr - unit_size_];
    }
  }
  return SUCCESS;
}

template <typename SharedKeyCryptosystem, typename UnitSize>
int32_t cbc<SharedKeyCryptosystem, typename UnitSize>::enc_postprocess(uint8_t *cbuf, const uint64_t cbsize, uint8_t *ctext, const uint64_t csize) noexcept {
  uint64_t cursor_end = cursor_ + unit_size_;

  if (cbsize != unit_size_ && csize != key_size_) {
    return FAILURE;
  }

  if (0 == cursor_) {
    key_ = ctext; 
  }

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ctext[outcsr] = cbuf[incsr];
  }

  cursor_ += unit_size_;
  if (cursor_ >= key_size_) {
    key_ = nullptr;
    key_size_ = 0;
    is_processing_ = false;
    cursor_ = 0;

    return PROCEND;
  }
  return SUCCESS;
}

template <typename SharedKeyCryptosystem, typename UnitSize>
int32_t cbc<SharedKeyCryptosystem, typename UnitSize>::dec_preprocess(uint8_t *ctext, const uint64_t csize, uint8_t *pbuf, const uint64_t pbsize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (pbsize != unit_size_) {
    return FAILURE;
  }

  if (false == is_processing_) {
    key_ = ctext;
    key_size_ = csize;
    is_processing_ = true;
  } 

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    pbuf[outcsr] = ctext[incsr];
  }
  return SUCCESS;
}

template <typename SharedKeyCryptosystem, typename UnitSize>
int32_t cbc<SharedKeyCryptosystem, typename UnitSize>::dec_postprocess(uint8_t *pbuf, const uint64_t pbsize, uint8_t *ptext, const uint64_t psize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (pbsize != unit_size_ && psize != key_size_) {
    return FAILURE;
  }

  if (0 == cursor_) {
    for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
      ptext[outcsr] = pbuf[incsr] ^ iv_[incsr];
    }
  } else {
    for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
      ptext[outcsr] = pbuf[incsr] ^ key_[outcsr - unit_size_];
    }
  }

  cursor_ += unit_size_;
  if (cursor_ >= key_size_) {
    key_ = nullptr;
    key_size_ = 0;
    is_processing_ = false;
    cursor_ = 0;

    return PROCEND;
  }
  return SUCCESS;
}
#endif
}
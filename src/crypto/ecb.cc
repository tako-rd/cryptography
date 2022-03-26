/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "ecb.h"

namespace cryptography {

#define DES_UNIT_SIZE     8
#define AES_UNIT_SIZE     16

int32_t ecb::initialize(const uint16_t type, uint8_t *, const uint64_t) noexcept {
  type_ = type_t(type & EXTRACT_TYPE);
  switch(type_) {
    case DEFAULT:
      unit_size_ = AES_UNIT_SIZE;
    case DES:
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
  return MODE_PROC_SUCCESS;
}

int32_t ecb::enc_preprocess(uint8_t *ptext, const uint64_t psize, uint8_t *cbuf, const uint64_t cbsize) noexcept {
  uint64_t cursor_end = cursor_ + unit_size_;

  if (false == is_processing_) {
    inlen_ = psize;
    is_processing_ = true;
  } 

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    cbuf[outcsr] = (uint8_t)ptext[incsr];
  }
  return MODE_PROC_SUCCESS;
}

int32_t ecb::enc_postprocess(uint8_t *cbuf, const uint64_t cbsize, uint8_t *ctext, const uint64_t csize) noexcept {
  uint64_t cursor_end = cursor_ + unit_size_;

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ctext[outcsr] = cbuf[incsr];
  }

  cursor_ += unit_size_;
  if (cursor_ >= inlen_) {
    cursor_ = 0;
    inlen_ = 0;
    is_processing_ = false;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

int32_t ecb::dec_preprocess(uint8_t *ctext, const uint64_t csize, uint8_t *pbuf, const uint64_t pbsize) noexcept {
  uint64_t cursor_end = cursor_ + unit_size_;

  if (false == is_processing_) {
    inlen_ = csize;
    is_processing_ = true;
  } 

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    pbuf[outcsr] = ctext[incsr];
  }
  return MODE_PROC_SUCCESS;
}

int32_t ecb::dec_postprocess(uint8_t *pbuf, const uint64_t pbsize, uint8_t *ptext, const uint64_t psize) noexcept {
  uint64_t cursor_end = cursor_ + unit_size_;

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ptext[outcsr] = pbuf[incsr];
  }

  cursor_ += unit_size_;
  if (cursor_ >= inlen_) {
    cursor_ = 0;
    inlen_ = 0;
    is_processing_ = false;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

};
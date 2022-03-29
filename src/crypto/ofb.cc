/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "ofb.h"

namespace cryptography {

#define DES_UNIT_SIZE     8
#define AES_UNIT_SIZE     16

int32_t ofb::initialize(const uint16_t type, uint8_t *iv, const uint64_t iv_size) noexcept {
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
    return MODE_PROC_FAILURE;
  }
  iv_ = iv;

  return MODE_PROC_SUCCESS;
}

int32_t ofb::enc_preprocess(uint8_t *ptext, const uint64_t psize, uint8_t *cbuf, const uint64_t cbsize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (cbsize != unit_size_) {
    return MODE_PROC_FAILURE;
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
      cbuf[outcsr] = key_[outcsr];
    }
  }
  return MODE_PROC_SUCCESS;
}

int32_t ofb::enc_postprocess(uint8_t *cbuf, const uint64_t cbsize, uint8_t *ctext, const uint64_t csize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (cbsize != unit_size_ && csize != key_size_) {
    return MODE_PROC_FAILURE;
  }

  key_ = cbuf;
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

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

int32_t ofb::dec_preprocess(uint8_t *ctext, const uint64_t csize, uint8_t *pbuf, const uint64_t pbsize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (pbsize != unit_size_) {
    return MODE_PROC_FAILURE;
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
      pbuf[outcsr] = key_[outcsr];
    }
  }
  return MODE_PROC_SUCCESS;
}

int32_t ofb::dec_postprocess(uint8_t *pbuf, const uint64_t pbsize, uint8_t *ptext, const uint64_t psize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (pbsize != unit_size_ && psize != key_size_) {
    return MODE_PROC_FAILURE;
  }

  key_ = pbuf;
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

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

}
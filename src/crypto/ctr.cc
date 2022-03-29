/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "ctr.h"

namespace cryptography {

#define DES_UNIT_SIZE     8
#define AES_UNIT_SIZE     16

int32_t ctr::initialize(const uint16_t type, uint8_t *iv, const uint64_t iv_size) noexcept {
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

int32_t ctr::enc_preprocess(uint8_t *ptext, const uint64_t psize, uint8_t *cbuf, const uint64_t cbsize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (cbsize != unit_size_) {
    return MODE_PROC_FAILURE;
  }

  if (false == is_processing_) {
    input_ = ptext;
    key_size_ = psize;
    is_processing_ = true;
    keycsr_ = unit_size_ - 1;
  }

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    cbuf[outcsr] = iv_[outcsr];
  }
  return MODE_PROC_SUCCESS;
}

int32_t ctr::enc_postprocess(uint8_t *cbuf, const uint64_t cbsize, uint8_t *ctext, const uint64_t csize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;
  uint64_t keycsr = keycsr_;

  if (cbsize != unit_size_ && csize != key_size_) {
    return MODE_PROC_FAILURE;
  }

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ctext[outcsr] = input_[outcsr] ^ cbuf[incsr];
  }

  while (true) {
    if (0xFF == iv_[keycsr]) {
      iv_[keycsr] = 0;
      --keycsr;
    } else {
      ++iv_[keycsr];
      ++counter_;
      keycsr = keycsr_;
      break;
    }
  }

  cursor_ += unit_size_;
  if (cursor_ >= key_size_) {
    iv_restore();

    key_size_ = 0;
    input_ = nullptr;
    is_processing_ = false;
    keycsr_ = 0;
    cursor_ = 0;
    counter_ = 0;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

int32_t ctr::dec_preprocess(uint8_t *ctext, const uint64_t csize, uint8_t *pbuf, const uint64_t pbsize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;

  if (pbsize != unit_size_) {
    return MODE_PROC_FAILURE;
  }

  if (false == is_processing_) {
    input_ = ctext;
    key_size_ = csize;
    is_processing_ = true;
    keycsr_ = unit_size_ - 1;
  }

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    pbuf[outcsr] = iv_[outcsr];
  }
  return MODE_PROC_SUCCESS;
}

int32_t ctr::dec_postprocess(uint8_t *pbuf, const uint64_t pbsize, uint8_t *ptext, const uint64_t psize) noexcept {
  const uint64_t cursor_end = cursor_ + unit_size_;
  uint64_t keycsr = keycsr_;

  if (pbsize != unit_size_ && psize != key_size_) {
    return MODE_PROC_FAILURE;
  }

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ptext[outcsr] = input_[outcsr] ^ pbuf[incsr];
  }

  while (true) {
    if (0xFF == iv_[keycsr]) {
      iv_[keycsr] = 0;
      --keycsr;
    } else {
      ++iv_[keycsr];
      ++counter_;
      keycsr = keycsr_;
      break;
    }
  }

  cursor_ += unit_size_;
  if (cursor_ >= key_size_) {
    iv_restore();

    key_size_ = 0;
    input_ = nullptr;
    is_processing_ = false;
    keycsr_ = 0;
    cursor_ = 0;
    counter_ = 0;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

inline void ctr::iv_restore() noexcept {
  uint64_t keycsr = unit_size_ - 1;

  while (0 != counter_) {
    if (0x00 == iv_[keycsr]) {
      iv_[keycsr] = 0xFF;
      while (true) {
        --keycsr;
        if (0x00 == iv_[keycsr]) {
          iv_[keycsr] = 0xFF;
        } else {
          --iv_[keycsr];
          keycsr = unit_size_ - 1;
          break;
        }
      }
    } else {
      --iv_[keycsr];
    }
    --counter_;
  }
}

}
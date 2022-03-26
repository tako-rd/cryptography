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

#define DES_SPLIT_LENGHT     8
#define AES_SPLIT_LENGHT     16

int32_t ctr::initialize(const uint16_t type, uint8_t *iv, const uint64_t ivlen) noexcept {
  type_ = type_t(type & EXTRACT_TYPE);
  switch(type_) {
    case DEFAULT:
      splen_ = AES_SPLIT_LENGHT;
    case DES:
      splen_ = DES_SPLIT_LENGHT;
      break;
    case AES128:
    case AES192:
    case AES256:
      splen_ = AES_SPLIT_LENGHT;
      break;
    default:
      break;
  }

  if (splen_ != ivlen) {
    return MODE_PROC_FAILURE;
  }
  iv_ = iv;

  return MODE_PROC_SUCCESS;
}

int32_t ctr::enc_preprocess(uint8_t *ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen) noexcept {
  const uint64_t cursor_end = cursor_ + splen_;

  if (false == is_processing_) {
    input_ = ptext;
    key_len_ = plen;
    is_processing_ = true;
    keycsr_ = splen_ - 1;
  }

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    cbuf[outcsr] = iv_[outcsr];
  }
  return MODE_PROC_SUCCESS;
}

int32_t ctr::enc_postprocess(uint8_t *cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen) noexcept {
  const uint64_t cursor_end = cursor_ + splen_;
  uint64_t keycsr = keycsr_;

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

  cursor_ += splen_;
  if (cursor_ >= key_len_) {
    iv_restore();

    key_len_ = 0;
    input_ = nullptr;
    is_processing_ = false;
    keycsr_ = 0;
    cursor_ = 0;
    counter_ = 0;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

int32_t ctr::dec_preprocess(uint8_t *ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen) noexcept {
  const uint64_t cursor_end = cursor_ + splen_;

  if (false == is_processing_) {
    input_ = ctext;
    key_len_ = clen;
    is_processing_ = true;
    keycsr_ = splen_ - 1;
  }

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    pbuf[outcsr] = iv_[outcsr];
  }
  return MODE_PROC_SUCCESS;
}

int32_t ctr::dec_postprocess(uint8_t *pbuf, const uint64_t pblen, uint8_t *ptext, const uint64_t plen) noexcept {
  const uint64_t cursor_end = cursor_ + splen_;
  uint64_t keycsr = keycsr_;

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

  cursor_ += splen_;
  if (cursor_ >= key_len_) {
    iv_restore();

    key_len_ = 0;
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
  uint64_t keycsr = splen_ - 1;
  uint64_t quotient = counter_;
  uint64_t surplus = counter_;

  while (0 != counter_) {
    if (0x00 == iv_[keycsr]) {
      iv_[keycsr] = 0xFF;
      while (true) {
        --keycsr;
        if (0x00 == iv_[keycsr]) {
          iv_[keycsr] = 0xFF;
        } else {
          --iv_[keycsr];
          keycsr = splen_ - 1;
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
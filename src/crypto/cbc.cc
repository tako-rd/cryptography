/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "cbc.h"

namespace cryptography {

#define DES_SPLIT_LENGHT     8
#define AES_SPLIT_LENGHT     16

int32_t cbc::initialize(const uint16_t type, uint8_t *iv, const uint64_t ivlen) noexcept {
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

int32_t cbc::enc_preprocess(uint8_t *ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen) noexcept {
  const uint64_t cursor_end = cursor_ + splen_;

  if (false == is_processing_) {
    key_len_ = plen;
    is_processing_ = true;
  } 

  if (0 == cursor_) { 
    for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
      cbuf[outcsr] = ptext[incsr] ^ iv_[outcsr];
    }
  } else {
    for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
      cbuf[outcsr] = ptext[incsr] ^ key_[incsr - splen_];
    }
  }
  return MODE_PROC_SUCCESS;
}

int32_t cbc::enc_postprocess(uint8_t *cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen) noexcept {
  uint64_t cursor_end = cursor_ + splen_;

  if (0 == cursor_) {
    key_ = ctext;
  }

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ctext[outcsr] = cbuf[incsr];
  }

  cursor_ += splen_;
  if (cursor_ >= key_len_) {
    key_ = nullptr;
    key_len_ = 0;
    is_processing_ = false;
    cursor_ = 0;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

int32_t cbc::dec_preprocess(uint8_t *ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen) noexcept {
  const uint64_t cursor_end = cursor_ + splen_;

  if (false == is_processing_) {
    key_ = ctext;
    key_len_ = clen;
    is_processing_ = true;
  } 

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    pbuf[outcsr] = ctext[incsr];
  }
  return MODE_PROC_SUCCESS;
}

int32_t cbc::dec_postprocess(uint8_t *pbuf, const uint64_t pblen, uint8_t *ptext, const uint64_t plen) noexcept {
  const uint64_t cursor_end = cursor_ + splen_;

  if (0 == cursor_) {
    for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
      ptext[outcsr] = pbuf[incsr] ^ iv_[incsr];
    }
  } else {
    for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
      ptext[outcsr] = pbuf[incsr] ^ key_[outcsr - splen_];
    }
  }

  cursor_ += splen_;
  if (cursor_ >= key_len_) {
    key_ = nullptr;
    key_len_ = 0;
    is_processing_ = false;
    cursor_ = 0;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

}
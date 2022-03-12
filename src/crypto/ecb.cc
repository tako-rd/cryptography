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

#define DES_SPLIT_LENGHT     8
#define AES_SPLIT_LENGHT     16

/* ECB mode */
void ecb::initialize(const uint16_t type, const uint8_t *, const uint64_t) noexcept {
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
}

int32_t ecb::enc_preprocess(const char * const ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen) noexcept {
  uint64_t cursor_end = cursor_ + splen_;

  if (false == is_processing_) {
    inlen_ = plen;
    is_processing_ = true;
  } 

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    cbuf[outcsr] = (uint8_t)ptext[incsr];
  }
  return MODE_PROC_SUCCESS;
}

int32_t ecb::enc_postprocess(const uint8_t * const cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen) noexcept {
  uint64_t cursor_end = cursor_ + splen_;

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ctext[outcsr] = cbuf[incsr];
  }

  cursor_ += splen_;
  if (cursor_ >= inlen_) {
    cursor_ = 0;
    inlen_ = 0;
    is_processing_ = false;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

int32_t ecb::dec_preprocess(const uint8_t * const ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen) noexcept {
  uint64_t cursor_end = cursor_ + splen_;

  if (false == is_processing_) {
    inlen_ = clen;
    is_processing_ = true;
  } 

  for (uint64_t incsr = cursor_, outcsr = 0; incsr < cursor_end; ++incsr, ++outcsr) {
    pbuf[outcsr] = ctext[incsr];
  }
  return MODE_PROC_SUCCESS;
}

int32_t ecb::dec_postprocess(const char * const pbuf, const uint64_t pblen, char *ptext, const uint64_t plen) noexcept {
  uint64_t cursor_end = cursor_ + splen_;

  for (uint64_t incsr = 0, outcsr = cursor_; outcsr < cursor_end; ++incsr, ++outcsr) {
    ptext[outcsr] = pbuf[incsr];
  }

  cursor_ += splen_;
  if (cursor_ >= inlen_) {
    cursor_ = 0;
    inlen_ = 0;
    is_processing_ = false;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

};
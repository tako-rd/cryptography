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

#define SPLIT_TEXT_LENGHT_FOR_DES     8
#define SPLIT_TEXT_LENGHT_FOR_AES     16

/* ECB mode */
void ecb::initialize(const uint16_t type, const uint8_t *, const uint64_t) {
  type_ = type_t(type & EXTRACT_TYPE);
  switch(type_) {
    case DEFAULT:
      splen_ = 16;
    case DES:
      splen_ = 8;
      break;
    case AES128:
    case AES192:
    case AES256:
      splen_ = 16;
      break;
    default:
      break;
  }
}

void ecb::enc_preprocess(const char * const ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen) {
  uint64_t cursor_end = cursor_ + splen_;

  if (false == is_processing_) {
    plen_ = plen;
    blen_ = cblen;
    is_processing_ = true;
  } 

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    cbuf[bytes] = (uint8_t)ptext[bytes];
  }
}

int32_t ecb::enc_postprocess(const uint8_t * const cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen) {
  uint64_t cursor_end = cursor_ + splen_;

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    ctext[bytes] = cbuf[bytes];
  }

  cursor_ += splen_;
  if (cursor_ <= plen_) {
    plen_ = 0;
    blen_ = 0;
    is_processing_ = false;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

void ecb::dec_preprocess(const uint8_t * const ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen) {
  uint64_t cursor_end = cursor_ + splen_;

  if (false == is_processing_) {
    clen_ = clen;
    blen_ = pblen;
    is_processing_ = true;
  } 

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    pbuf[bytes] = ctext[bytes];
  }
}

int32_t ecb::dec_postprocess(const char * const pbuf, const uint64_t pblen, char *ptext, const uint64_t plen) {
  uint64_t cursor_end = cursor_ + splen_;

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    ptext[bytes] = pbuf[bytes];
  }

  cursor_ += splen_;
  if (cursor_ <= plen_) {
    plen_ = 0;
    blen_ = 0;
    is_processing_ = false;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

};
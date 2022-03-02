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

#define SPLIT_TEXT_LENGHT_FOR_DES     8
#define SPLIT_TEXT_LENGHT_FOR_AES     16

void cbc::initialize(const uint16_t type, const uint8_t *iv, const uint64_t ivlen) {
  type_ = type_t(type & EXTRACT_TYPE);
  switch(type_) {
    case DEFAULT:
      splen_ = SPLIT_TEXT_LENGHT_FOR_AES;
    case DES:
      splen_ = SPLIT_TEXT_LENGHT_FOR_DES;
      break;
    case AES128:
    case AES192:
    case AES256:
      splen_ = SPLIT_TEXT_LENGHT_FOR_AES;
      break;
    default:
      break;
  }

  if (splen_ != ivlen) {
    return ;
  }

  for (uint64_t i = 0; i < splen_; ++i) {
    iv_.u8[i] = iv[i];
  }
}

void cbc::enc_preprocess(const char * const ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen) {
  const uint64_t cursor_end = cursor_ + splen_;
  union_array_u128_t text = {0};

  if (false == is_processing_) {
    plen_ = plen;
    blen_ = cblen;
    is_processing_ = true;

    key_.u64[0] = iv_.u64[0];
    key_.u64[1] = iv_.u64[1];
  } 

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    text.u8[bytes] = (uint8_t)ptext[bytes];
  }

  key_.u64[0] = text.u64[0] ^ key_.u64[0];
  key_.u64[0] = text.u64[1] ^ key_.u64[1];

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    cbuf[bytes] = key_.u8[bytes];
  }
}

int32_t cbc::enc_postprocess(const uint8_t * const cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen) {
  uint64_t cursor_end = cursor_ + splen_;

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    ctext[bytes] = cbuf[bytes];
  }

  cursor_ += splen_;
  if (cursor_ <= plen_) {
    plen_ = 0;
    blen_ = 0;

    iv_.u64[0] = 0;
    iv_.u64[1] = 0;

    key_.u64[0] = 0;
    key_.u64[1] = 0;

    is_processing_ = false;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

void cbc::dec_preprocess(const uint8_t * const ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen) {
  const uint64_t cursor_end = cursor_ + splen_;

  if (false == is_processing_) {
    plen_ = clen;
    blen_ = pblen;
    is_processing_ = true;

    key_.u64[0] = iv_.u64[0];
    key_.u64[1] = iv_.u64[1];
  } 

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    pbuf[bytes] = ctext[bytes];
  }
}

int32_t cbc::dec_postprocess(const char * const pbuf, const uint64_t pblen, char *ptext, const uint64_t plen) {
  const uint64_t cursor_end = cursor_ + splen_;
  union_array_u128_t text = {0};

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    text.u8[bytes] = (uint8_t)pbuf[bytes];
  }

  key_.u64[0] = text.u64[0] ^ key_.u64[0];
  key_.u64[0] = text.u64[1] ^ key_.u64[1];

  for (uint64_t bytes = cursor_; bytes < cursor_end; ++bytes) {
    ptext[bytes] = key_.u8[bytes];
  }

  cursor_ += splen_;
  if (cursor_ <= plen_) {
    plen_ = 0;
    blen_ = 0;

    iv_.u64[0] = 0;
    iv_.u64[1] = 0;

    key_.u64[0] = 0;
    key_.u64[1] = 0;

    is_processing_ = false;

    return MODE_PROC_END;
  }
  return MODE_PROC_SUCCESS;
}

}
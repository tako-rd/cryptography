/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef ECB_H
#define ECB_H

#include "defs.h"
#include "mode.h"

namespace cryptography {

class ecb : mode<ecb> {
 public:
  ecb() : type_(DEFAULT), is_processing_(false), inlen_(0), cursor_(0), splen_(0) {};

  ~ecb() {};

  int32_t initialize(const uint16_t type, uint8_t *, const uint64_t) noexcept;

  int32_t enc_preprocess(uint8_t *ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen) noexcept;

  int32_t enc_postprocess(uint8_t *cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen) noexcept;

  int32_t dec_preprocess(uint8_t *ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen) noexcept;

  int32_t dec_postprocess(uint8_t *pbuf, const uint64_t pblen, uint8_t *ptext, const uint64_t plen) noexcept;

 private:
  type_t type_;

  bool is_processing_;

  uint64_t inlen_;

  uint64_t cursor_;

  uint64_t splen_;
};

}

#endif

/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef CFB_H
#define CFB_H

#include "defs.h"
#include "mode.h"

namespace cryptography {

class cfb : mode<cfb> {
 public:
  cfb() {};

  ~cfb() {};

  int32_t initialize(const uint16_t type, uint8_t *iv, const uint64_t ivlen) noexcept;

  int32_t enc_preprocess(uint8_t *ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen) noexcept;

  int32_t enc_postprocess(uint8_t *cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen) noexcept;

  int32_t dec_preprocess(uint8_t *ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen) noexcept;

  int32_t dec_postprocess(uint8_t *pbuf, const uint64_t pblen, uint8_t *ptext, const uint64_t plen) noexcept;

 private:

};

}

#endif

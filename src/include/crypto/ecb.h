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
  ecb() : type_(DEFAULT), is_processing_(false), plen_(0), clen_(0), blen_(0), cursor_(0), splen_(0) {};

  ~ecb() {};

  void initialize(const uint16_t type, const uint8_t *, const uint64_t);

  void enc_preprocess(const char * const ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen);

  int32_t enc_postprocess(const uint8_t * const cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen);

  void dec_preprocess(const uint8_t * const ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen);

  int32_t dec_postprocess(const char * const pbuf, const uint64_t pblen, char *ptext, const uint64_t plen);

private:
  type_t type_;

  bool is_processing_;

  uint64_t plen_;

  uint64_t clen_;

  uint64_t blen_;

  uint64_t cursor_;

  uint64_t splen_;
};

}

#endif

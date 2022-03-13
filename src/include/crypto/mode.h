/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "defs.h"

#ifndef MODE_H
#define MODE_H

namespace cryptography {

typedef enum mode_proc_status {
  MODE_PROC_SUCCESS = 0,
  MODE_PROC_END,
  MODE_PROC_FAILURE,
  MODE_PROC_STATUS_COUNT,
} mode_status_t;

template <typename Mode>
class mode {
public:
  mode() {};

  ~mode() {};

  int32_t initialize(const uint16_t type, uint8_t *iv, const uint64_t ivlen) {
    return static_cast<Mode &>(this)->initialize(type, iv, ivlen);
  };

  int32_t enc_preprocess(uint8_t *ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen) {
    return static_cast<Mode &>(this)->enc_preprocess(ptext, plen, cbuf, cblen);
  };

  int32_t enc_postprocess(uint8_t *cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen) {
    return static_cast<Mode &>(this)->enc_postprocess(cbuf, cblen, ctext, clen);
  };

  int32_t dec_preprocess(uint8_t *ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen) {
    return static_cast<Mode &>(this)->dec_preprocess(ctext, clen, pbuf, pblen);
  };

  int32_t dec_postprocess(uint8_t *pbuf, const uint64_t pblen, uint8_t *ptext, const uint64_t plen) {
    return static_cast<Mode &>(this)->dec_postprocess(pbuf, pblen, ptext, plen);
  };
};

class ofb : mode<ofb> {
 public:
 private:

};

class ctr : mode<ctr> {
 public:
 private:

};

}

#endif

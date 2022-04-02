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

  int32_t initialize(const uint16_t type, uint8_t *iv, const uint32_t iv_size) noexcept {
    return static_cast<Mode &>(this)->initialize(type, iv, iv_size);
  };

  int32_t enc_preprocess(uint8_t *ptext, const uint32_t psize, uint8_t *cbuf, const uint32_t cbsize) noexcept {
    return static_cast<Mode &>(this)->enc_preprocess(ptext, psize, cbuf, cbsize);
  };

  int32_t enc_postprocess(uint8_t *cbuf, const uint32_t cbsize, uint8_t *ctext, const uint32_t csize) noexcept {
    return static_cast<Mode &>(this)->enc_postprocess(cbuf, cbsize, ctext, csize);
  };

  int32_t dec_preprocess(uint8_t *ctext, const uint32_t csize, uint8_t *pbuf, const uint32_t pbsize) noexcept {
    return static_cast<Mode &>(this)->dec_preprocess(ctext, csize, pbuf, pbsize);
  };

  int32_t dec_postprocess(uint8_t *pbuf, const uint32_t pbsize, uint8_t *ptext, const uint32_t psize) noexcept {
    return static_cast<Mode &>(this)->dec_postprocess(pbuf, pbsize, ptext, psize);
  };

  
};

}

#endif

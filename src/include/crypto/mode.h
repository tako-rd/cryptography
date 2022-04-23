/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "secret_key.h"

#ifndef MODE_H
#define MODE_H

namespace cryptography {

template <typename Mode,
          bool IsValidMode = std::is_base_of<mode_interface<Mode>, Mode>::value>
class mode {
  static_assert(IsValidMode, "*** ERROR : An invalid mode of operation has been specified.");
};

template <typename Mode>
class mode<Mode, true> {
 public:
  mode() {};

  ~mode() {};

  int32_t initialize(const uint16_t type, uint8_t *iv, const uint32_t iv_size) noexcept {
    return mode_.initialize(type, iv, iv_size);
  };

  int32_t enc_preprocess(uint8_t *ptext, const uint32_t psize, uint8_t *cbuf, const uint32_t cbsize) noexcept {
    return mode_.enc_preprocess(ptext, psize, cbuf, cbsize);
  };

  int32_t enc_postprocess(uint8_t *cbuf, const uint32_t cbsize, uint8_t *ctext, const uint32_t csize) noexcept {
    return mode_.enc_postprocess(cbuf, cbsize, ctext, csize);
  };

  int32_t dec_preprocess(uint8_t *ctext, const uint32_t csize, uint8_t *pbuf, const uint32_t pbsize) noexcept {
    return mode_.dec_preprocess(ctext, csize, pbuf, pbsize);
  };

  int32_t dec_postprocess(uint8_t *pbuf, const uint32_t pbsize, uint8_t *ptext, const uint32_t psize) noexcept {
    return mode_.dec_postprocess(pbuf, pbsize, ptext, psize);
  };

 private:
  Mode mode_;
};

template <typename Mode>
class mode_interface {
 public:
  mode_interface() {};

  ~mode_interface() {};

  int32_t initialize(const uint16_t type, uint8_t *iv, const uint32_t iv_size) noexcept {
    return (Mode &)(*this).initialize(type, iv, iv_size);
  };

  int32_t enc_preprocess(uint8_t *ptext, const uint32_t psize, uint8_t *cbuf, const uint32_t cbsize) noexcept {
    return (Mode &)(*this).enc_preprocess(ptext, psize, cbuf, cbsize);
  };

  int32_t enc_postprocess(uint8_t *cbuf, const uint32_t cbsize, uint8_t *ctext, const uint32_t csize) noexcept {
    return (Mode &)(*this).enc_postprocess(cbuf, cbsize, ctext, csize);
  };

  int32_t dec_preprocess(uint8_t *ctext, const uint32_t csize, uint8_t *pbuf, const uint32_t pbsize) noexcept {
    return (Mode &)(*this).dec_preprocess(ctext, csize, pbuf, pbsize);
  };

  int32_t dec_postprocess(uint8_t *pbuf, const uint32_t pbsize, uint8_t *ptext, const uint32_t psize) noexcept {
    return (Mode &)(*this).dec_postprocess(pbuf, pbsize, ptext, psize);
  };
};

}

#endif

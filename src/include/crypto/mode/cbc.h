/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef CBC_H
#define CBC_H

#include "mode.h"

namespace cryptography {

template <typename SharedKeyCryptosystem, typename UnitSize>
class cbc : mode<SharedKeyCryptosystem, UnitSize> {
 public:
  cbc() : unit_size_(0) {} ; 

  ~cbc() {}; 

  int32_t initialize(uint8_t *iv, const uint32_t iv_size) noexcept;

  int32_t encrypt(uint8_t *ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(uint8_t *ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

#if 0
  cbc() : type_(DEFAULT), iv_(nullptr), key_(nullptr), key_size_(0), is_processing_(false), cursor_(0), unit_size_(0) {} ; 

  ~cbc() {}; 

  int32_t initialize(const uint16_t type, uint8_t *iv, const uint64_t iv_size) noexcept;

  int32_t enc_preprocess(uint8_t *ptext, const uint64_t psize, uint8_t *cbuf, const uint64_t cbsize) noexcept;

  int32_t enc_postprocess(uint8_t *cbuf, const uint64_t cbsize, uint8_t *ctext, const uint64_t csize) noexcept;

  int32_t dec_preprocess(uint8_t *ctext, const uint64_t csize, uint8_t *pbuf, const uint64_t pbsize) noexcept;

  int32_t dec_postprocess(uint8_t *pbuf, const uint64_t pbsize, uint8_t *ptext, const uint64_t psize) noexcept;
#endif
 private:
  uint8_t *iv_;
   
  UnitSize unit_size_;

#if 0
  type_t type_;

  uint8_t *iv_;

  uint8_t *key_;

  uint64_t key_size_;

  bool is_processing_;

  uint64_t cursor_;

#endif
};

};

#endif

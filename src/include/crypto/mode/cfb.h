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

#include <string.h>

#include "crypto/mode/mode.h"

namespace cryptography {

/* Prototype declaration of class. */
template <typename Cryptosystem, uint32_t UnitSize> class cfb;

/* Alias declaration */
template <typename Cryptosystem, uint32_t UnitSize>
using CFB = cfb<Cryptosystem, UnitSize>;

template <typename Cryptosystem, uint32_t UnitSize>
class cfb : private mode<Cryptosystem, UnitSize> {
 public:
  cfb() noexcept {};

  ~cfb() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

 private:
  uint8_t iv_[UnitSize];
};

#if 0
class cfb : mode<cfb> {
 public:
  cfb() : type_(DEFAULT), iv_(nullptr), key_(nullptr), key_size_(0), input_(nullptr), is_processing_(false), cursor_(0), unit_size_(0) {};

  ~cfb() {};

  int32_t initialize(const uint16_t type, uint8_t *iv, const uint64_t iv_size) noexcept;

  int32_t enc_preprocess(uint8_t *ptext, const uint64_t psize, uint8_t *cbuf, const uint64_t cbsize) noexcept;

  int32_t enc_postprocess(uint8_t *cbuf, const uint64_t cbsize, uint8_t *ctext, const uint64_t csize) noexcept;

  int32_t dec_preprocess(uint8_t *ctext, const uint64_t csize, uint8_t *pbuf, const uint64_t pbsize) noexcept;

  int32_t dec_postprocess(uint8_t *pbuf, const uint64_t pbsize, uint8_t *ptext, const uint64_t psize) noexcept;

 private:
  type_t type_;

  uint8_t *iv_;

  uint8_t *key_;

  uint64_t key_size_;

  uint8_t *input_;

  bool is_processing_;

  uint64_t cursor_;

  uint64_t unit_size_;
};
#endif
}

#endif

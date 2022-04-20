/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "defs.h"

#ifndef ALGORITHM_H
#define ALGORITHM_H

namespace cryptography {

template <typename Algorithm>
class algorithm {
public:
  algorithm() {};

  ~algorithm() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) {
    return static_cast<Algorithm &>(*this).initialize(key, ksize);
  }

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) {
    return static_cast<Algorithm &>(*this).encrypt(ptext, psize, ctext, csize);
  };

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) {
    return static_cast<Algorithm &>(*this).decrypt(ctext, csize, ptext, psize);
  };

  void clear() {
    static_cast<Algorithm &>(*this).clear();
  };
};

}

#endif
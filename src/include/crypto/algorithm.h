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

  int32_t initialize(const uint16_t mode, const uint8_t *key, const uint64_t klen, const bool en_intrinsic) {
    return static_cast<Algorithm &>(this)->initialize(mode, key, klen, en_intrinsic);
  }

  int32_t encrypt(const char * const ptext, const uint64_t plen, 
               uint8_t *ctext, const uint64_t clen) {
    return static_cast<Algorithm &>(this)->encrypt(ptext, plen, ctext, clen);
  };

  int32_t decrypt(const uint8_t * const ctext, const uint64_t clen, 
               char *ptext, const uint64_t plen) {
    return static_cast<Algorithm &>(this)->decrypt(ctext, clen, ptext, plen);
  };

  void clear() {
    static_cast<Algorithm &>(this)->clear();
  };
};

}

#endif
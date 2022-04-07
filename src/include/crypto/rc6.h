/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "algorithm.h"

#ifndef RC6_H
#define RC6_H

namespace cryptography {

class rc6 final : public algorithm<rc6> {
 public:
  rc6() noexcept {};

  ~rc6() {};

  int32_t initialize(const uint32_t mode, const uint8_t *key, const uint32_t klen, bool enable_intrinsic) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t plen, uint8_t *ctext, const uint32_t clen) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t clen, uint8_t *ptext, const uint32_t plen) noexcept;

  void clear() noexcept;

 private:

};

}

#endif
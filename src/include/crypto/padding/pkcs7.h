/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef PKCS7_H
#define PKCS7_H

#include <stdint.h>

namespace cryptography {

class pkcs7 {
 public:
  pkcs7() noexcept {};

  ~pkcs7() {};

  int32_t add(uint8_t *ptext, const uint32_t psize, const uint32_t usize) noexcept;

  int32_t remove(uint8_t *ctext, const uint32_t usize) noexcept;
};

}
#endif

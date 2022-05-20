/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "crypto/padding/pkcs7.h"

namespace cryptography {

#define SUCCESS   0
#define FAILURE   1

int32_t pkcs7::add(uint8_t *ptext, const uint32_t psize, const uint32_t usize) const noexcept {
  uint32_t pdsize = usize - (psize % usize);
  
  for (uint32_t byte = 0; byte < pdsize; ++byte) {
    ptext[(usize - 1) - byte] = pdsize;
  }
  return SUCCESS;
}

int32_t pkcs7::remove(uint8_t *ptext, const uint32_t usize) const noexcept {
  uint32_t pdsize = 0;

  if (pdsize < 0x01 || usize < pdsize) {
    return FAILURE;
  }

  pdsize = ptext[usize - 1];
  for (uint32_t byte = 0; byte < pdsize; ++byte) {
    ptext[(usize - 1) - byte] = 0x00;
  }
  return SUCCESS;
}

}

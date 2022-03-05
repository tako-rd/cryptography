/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef PADDING_H
#define PADDING_H

#include "defs.h"

namespace cryptography {

typedef enum padding_type {
  NO_PADDING = 0,
  ZERO,
  PKCS1,
  PKCS5,
  PKCS7,
  PKCS8,
  PKCS9,
  PKCS10,
  PKCS11,
  PKCS12,
  ISO10126,
  SSL3,
  OAEP_PADDING,
} pdtype_t;

class padding {
 public:
  padding() : type_(ZERO), unit_size_(0) {};

  ~padding() {};

  void initialize(const pdtype_t type, uint32_t unit_size);

  int32_t set(const char * const raw, const uint64_t rawlen, char *buf, const uint64_t buflen);

  int32_t remove(const char * const padded, const uint64_t paddedlen, char *buf, const uint64_t buflen);

 private:
  int32_t set_pkcs5(const char * const raw, const uint64_t rawlen, const uint64_t plen, const uint64_t pend, char *buf) const noexcept;

  int32_t remove_pkcs5(const char * const padded, const uint64_t paddedlen, char *buf) const noexcept;
   
  int32_t set_pkcs7(const char * const raw, const uint64_t rawlen, const uint64_t plen, const uint64_t pend, char *buf) const noexcept;

  int32_t remove_pkcs7(const char * const padded, const uint64_t paddedlen, char *buf) const noexcept;

  pdtype_t type_;

  uint32_t unit_size_;

};

}
#endif
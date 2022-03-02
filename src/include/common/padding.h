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
  ZERO_BYTE_PADDING,
  PKCS5_PADDING,
  PKCS7_PADDING,
  ISO10126_PADDING,
  SSL3_PADDING,
  OAEP_PADDING,
} pdtype_t;

class padding {
 public:
  padding() : type_(ZERO_BYTE_PADDING), unit_size_(0) {};

  ~padding() {};

  void initialize(const pdtype_t type, uint32_t unit_size);

  void set(const char *raw, const uint64_t rawlen, char *padded, const uint64_t paddedlen);

  void remove(const char *padded, const uint64_t paddedlen, char *raw, const uint64_t rawlen);

 private:
  void set_zero_padding(const char *raw, const uint64_t rawlen, char *padded, const uint64_t paddedlen) const noexcept;

  void remove_zero_padding(const char *padded, const uint64_t paddedlen, char *raw, const uint64_t rawlen) const noexcept;

  pdtype_t type_;

  uint32_t unit_size_;

};

}
#endif
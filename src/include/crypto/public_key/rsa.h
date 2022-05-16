/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef RSA_H
#define RSA_H

#include "common/defs.h"
#include "common/endian.h"
#include "common/bignumber.h"

namespace cryptography {

#define RSA_KEY_512BIT          512
#define RSA_KEY_1024BIT         1024
#define RSA_KEY_2048BIT         2048
#define RSA_KEY_4096BIT         4096
#define RSA_KEY_16384BIT        16384
#define RSA_KEY_32768BIT        32768
#define RSA_KEY_65536BIT        65536
#define RSA_KEY_131072BIT       131072
#define RSA_KEY_262144BIT       262144
#define RSA_KEY_524288BIT       524288
#define RSA_KEY_1048576BIT      1048576
#define RSA_KEY_2097152BIT      2097152
#define RSA_KEY_4194304BIT      4194304
#define RSA_KEY_8388608BIT      8388608
#define RSA_KEY_16777216BIT     16777216
#define RSA_KEY_33554432BIT     33554432
#define RSA_KEY_67108864BIT     67108864
#define RSA_KEY_134217728BIT    134217728
#define RSA_KEY_268435456BIT    268435456
#define RSA_KEY_536870912BIT    536870912
#define RSA_KEY_1073741824BIT   1073741824
#define RSA_KEY_2147483648BIT   2147483648

/* Prototype declaration of class. */
class rsa_base;
class rsa;
class rsa_key;

/* Alias declaration */
using RSA = rsa;

class rsa_base {
 public:
  rsa_base() noexcept {};

  ~rsa_base() {};
};

class rsa final : public rsa_base {
 public:
  rsa() noexcept {};

  ~rsa() {};

  int32_t initialize(const int32_t bit) noexcept;

  int32_t encrypt(uint32_t *ptext, const int32_t psize, uint32_t *ctext, const int32_t csize) noexcept;

  int32_t decrypt(uint32_t *ctext, const int32_t csize, uint32_t *ptext, const int32_t psize) noexcept;

  void clear() noexcept;

 private:

};

class rsa_key {
 public:
  rsa_key() noexcept {};

  ~rsa_key() {};

  void create(const int32_t bit) noexcept;

  void destroy(const int32_t bit) noexcept;

 private:

};

}
#endif

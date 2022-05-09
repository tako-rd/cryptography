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

/* Prototype declaration of class. */
class rsa_base;
class rsa;
class rsa_key;

/* Alias declaration */
using RSA = rsa;

class rsa_base {
 public:
  rsa_base() {};

  ~rsa_base() {};

};

class rsa final : public rsa_base {
 public:
  rsa() noexcept {};

  ~rsa() {};


 private:


};

class rsa_key {
 public:
  rsa_key() noexcept {};

  ~rsa_key() {};

 private:

};

}
#endif

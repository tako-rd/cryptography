/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef RC6_H
#define RC6_H

#include "crypto/secret_key/secret_key_base.h"

namespace cryptography {

/* Prototype declaration of class. */
class rc6_base;
class rc6;

/* Alias declaration */
using RC6 = rc6;

class rc6_base {
 public:
  rc6_base() noexcept {};

  ~rc6_base() {};

  static const uint32_t UNIT_SIZE = 16;
};

class rc6 final : public rc6_base, public secret_key_base<rc6> {
 public:
  rc6() noexcept : subkeys_{0}, ksize_(0), has_subkeys_(false) {};

  ~rc6();

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, uint8_t *ctext) noexcept;

  int32_t decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept;

  void clear() noexcept;

 private:
  void expand_key(uint32_t *key, uint32_t *skeys, const uint32_t ksize) noexcept;

  uint32_t subkeys_[44];

  uint32_t ksize_;

  bool has_subkeys_;
};

}

#endif
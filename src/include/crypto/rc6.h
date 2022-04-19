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
  rc6() noexcept : subkeys_{0}, ksize_(0), has_subkeys_(false), enable_intrinsic_func_(false) {};

  ~rc6() {};

  int32_t initialize(const uint32_t mode, const uint8_t *key, const uint32_t ksize, bool enable_intrinsic) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

 private:
  void no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void expand_key(uint32_t *key, uint32_t *skeys, const uint32_t ksize) noexcept;

  uint32_t subkeys_[44];

  uint32_t ksize_;

  bool has_subkeys_;

  bool enable_intrinsic_func_;
};

}

#endif
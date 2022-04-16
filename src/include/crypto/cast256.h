/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "defs.h"
#include "block_cipher.h"

#ifndef CAST256_H
#define CAST256_H

namespace cryptography {

class cast256 final : public algorithm<cast256> {
public:
  cast256() noexcept : mode_(CAST256), km_{0}, kr_{0}, has_subkeys_(false), enable_intrinsic_func_(false) {};

  ~cast256() {};

  int32_t initialize(const uint32_t mode, const uint8_t *key, const uint32_t ksize, bool enable_intrinsic) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

private:
  void no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept;

  void intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept;

  void expand_key(const uint32_t * const key, uint32_t *km, uint32_t *kr) noexcept;

  uint32_t f1_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t f2_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t f3_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t mode_;

  uint32_t km_[48];

  uint32_t kr_[48];

  bool has_subkeys_;

  bool enable_intrinsic_func_;
};

}

#endif

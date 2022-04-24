/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef CAST256_H
#define CAST256_H

#include "crypto/secret_key/secret_key_base.h"

namespace cryptography {

class cast256 final : public secret_key_interface<cast256> {
public:
  cast256() noexcept : km_{0}, kr_{0}, has_subkeys_(false) {};

  ~cast256() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

private:
  void expand_key(const uint32_t * const key, uint32_t *km, uint32_t *kr) noexcept;

  uint32_t f1_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t f2_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t f3_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t km_[48];

  uint32_t kr_[48];

  bool has_subkeys_;
};

}

#endif

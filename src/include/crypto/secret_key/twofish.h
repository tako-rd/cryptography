/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef TWOFISH_H
#define TWOFISH_H

#include "crypto/secret_key/secret_key_base.h"

namespace cryptography {

class twofish_base {
 public:
  twofish_base() {};

  ~twofish_base() {};

  static const uint32_t unit_size = 16;
};

class twofish final : public twofish_base, public secret_key_interface<twofish> {
 public:
  twofish() noexcept : subkey_{0}, has_subkeys_(false) {};

  ~twofish() {};

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept;

  int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept;

  void clear() noexcept;

 private:
  void expand_key(const uint32_t * const key, uint32_t *skeys) noexcept;

  void f_function(uint32_t r0, uint32_t r1, int32_t round, uint32_t *f) const noexcept;

  uint32_t g_function(uint32_t x) const noexcept;

  uint32_t h_function(uint32_t x, uint32_t *l, uint32_t type) const noexcept;

  uint8_t gf_mult(uint8_t x, uint8_t y, uint32_t mod) const noexcept;

#if 0
  uint8_t fix_q(uint8_t x, const uint8_t * const t0, const uint8_t * const t1, const uint8_t * const t2, const uint8_t * const t3) const noexcept;
#endif

  void fix_s(uint32_t *s, uint32_t type) noexcept;

  int32_t k_;

  uint32_t subkey_[40];

  bool has_subkeys_;

#if 0
  uint8_t q0_[256];

  uint8_t q1_[256];
#endif

  uint32_t mds_sbox0_[256];

  uint32_t mds_sbox1_[256];

  uint32_t mds_sbox2_[256];

  uint32_t mds_sbox3_[256];
};

}

#endif
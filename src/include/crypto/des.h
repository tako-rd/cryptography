/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef __DES_H__
#define __DES_H__

#include <cstring>
#include <vector>

#include "defs.h"
#include "block_cipher.h"

namespace cryptography {

class des final : public algorithm<des> {
 public:

  des() : mode_(DES), encrypto_subkeys_{0}, decrypto_subkeys_{0}, has_subkeys_(false), enable_intrinsic_func_(false) {};

  ~des();

  int32_t initialize(const uint16_t mode, const uint8_t *key, const uint64_t klen, bool enable_intrinsic);

  int32_t encrypt(const char * const ptext, const uint64_t plen, uint8_t *ctext, const uint64_t clen);

  int32_t decrypt(const uint8_t * const ctext, const uint64_t clen, char *ptext, const uint64_t plen);

  void clear();

 private:

  void no_intrinsic_encrypt(const char * const ptext, uint8_t *ctext) const noexcept;

  void no_intrinsic_decrypt(const uint8_t * const ctext, char *ptext) const noexcept;

  void intrinsic_encrypt(const char * const ptext, uint8_t *ctext) const noexcept;

  void intrinsic_decrypt(const uint8_t * const ctext, char *ptext) const noexcept;

  void create_encrypto_subkeys(const uint64_t key, uint64_t *subkeys);

  void create_decrypto_subkeys(const uint64_t key, uint64_t *subkeys);

  void permuted_choice1(const uint64_t key, uint32_t &left, uint32_t &right) const noexcept;

  void permuted_choice2(const uint32_t left, const uint32_t right, uint64_t &subkey) const noexcept;

  void initialize_permute(union_array_u64_t *text) const noexcept;

  void finalize_permute(union_array_u64_t *text) const noexcept;

  void round(const uint64_t subkey, const uint32_t rtext, uint32_t &roundtext) const noexcept;

  void expand(const uint32_t rtext, uint64_t &etext) const noexcept;

  void permute(const uint32_t rtext, uint32_t &ptext) const noexcept;

  uint64_t encrypto_subkeys_[16];

  uint64_t decrypto_subkeys_[16];

  uint16_t mode_;

  bool has_subkeys_;

  bool enable_intrinsic_func_;
};

}

#endif
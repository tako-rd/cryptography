/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef BLOCK_CIPHER_H
#define BLOCK_CIPHER_H

#include "defs.h"
#include "mode.h"
#include "algorithm.h"

namespace cryptography {

typedef enum block_cipher_status {
  BLOCK_CIPHER_SUCCESS = 0,
  BLOCK_CIPHER_END,
  BLOCK_CIPHER_FAILURE,
  BLOCK_CIPHER_STATUS_COUNT,
} bc_status_t;

template <typename Mode, typename Algorithm, 
          bool IsValidMode = std::is_base_of<mode<Mode>, Mode>::value, 
          bool IsValidAlgorithm = std::is_base_of<algorithm<Algorithm>, Algorithm>::value>
class block_cipher {
 public:
  /* If a class that does not inherit mode is specified in mode_name. */
  static_assert(IsValidMode,      "*** ERROR : An invalid block cipher mode of operation has been specified.");
  static_assert(IsValidAlgorithm, "*** ERROR : An invalid algorithm of block cipher has been specified.");
};

template <typename Mode, typename Algorithm>
class block_cipher<Mode, typename Algorithm, true, true> {
 public:
  block_cipher() {};

  ~block_cipher() {};

  bc_status_t initialize(const uint16_t mode, const uint8_t *key, const uint64_t klen, const uint8_t *iv, const uint64_t ivlen, const bool en_intrinsic) {
    algorithm_.initialize(mode, key, klen, en_intrinsic);
    mode_.initialize(mode, iv, ivlen);
  };

  bc_status_t encrypt(const char * const ptext, const uint64_t plen, uint8_t *ctext, const uint64_t clen) {
    return algorithm_.encrypt(ptext, plen, ctext, clen);
  };

  bc_status_t decrypt(const uint8_t * const ctext, const uint64_t clen, char *ptext, const uint64_t plen) {
    return algorithm_.decrypt(ctext, clen, ptext, plen);
  };

  void clear() {
    algorithm_.clear();
  }

  bc_status_t enc_preprocess(const char * const in, const uint64_t inlen, uint8_t *out, const uint64_t outlen) {
    return mode_.enc_preprocess(in, inlen, out, outlen);
  };

  bc_status_t enc_postprocess(const uint8_t * const in, const uint64_t inlen, char *out, const uint64_t outlen) {
    return mode_.enc_postprocess(in, inlen, out, outlen);
  };

  bc_status_t dec_preprocess(const char * const in, const uint64_t inlen, uint8_t *out, const uint64_t outlen) {
    return mode_.dec_preprocess(in, inlen, out, outlen);

  };

  bc_status_t dec_postprocess(const uint8_t * const in, const uint64_t inlen, char *out, const uint64_t outlen) {
    return mode_.dec_postprocess(in, inlen, out, outlen);
  };


 private:
   Mode mode_;

   Algorithm algorithm_;
};

}

#endif

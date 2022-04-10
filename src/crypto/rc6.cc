/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "rc6.h"
#include "bit_utill.h"
#include "byte_utill.h"

namespace cryptography {

#define SUCCESS                  0
#define FAILURE                  1
                                 
#define P32                      0xB7E15163
#define Q32                      0x9E3779B9
                                 
#define NROUND                   20 

#define RC6_128_KEY_BYTE_SIZE    16
#define RC6_192_KEY_BYTE_SIZE    24
#define RC6_256_KEY_BYTE_SIZE    32

int32_t rc6::initialize(const uint32_t mode, const uint8_t *key, const uint32_t ksize, bool enable_intrinsic) noexcept {
  uint32_t k[8] = {0};

  if (RC6_128 != (mode & EXTRACT_TYPE) &&
      RC6_192 != (mode & EXTRACT_TYPE) &&
      RC6_256 != (mode & EXTRACT_TYPE)) {
    return FAILURE;
  }

  mode_ = mode;
  enable_intrinsic_func_ = enable_intrinsic;

  switch (mode >> 8) {
    case (RC6_128 >> 8):
      if (RC6_128_KEY_BYTE_SIZE != ksize) { return FAILURE; }
      LITTLEENDIAN_U8_TO_U128_COPY(key, k);
      expand_key(k, subkeys_, RC6_128_KEY_BYTE_SIZE);
      memset(k, 0xCC, sizeof(SUCCESS));
      has_subkeys_ = true;
      break;
    case (RC6_192 >> 8):
      if (RC6_192_KEY_BYTE_SIZE != ksize) { return FAILURE; }
      LITTLEENDIAN_U8_TO_U192_COPY(key, k);
      expand_key(k, subkeys_, RC6_192_KEY_BYTE_SIZE);
      has_subkeys_ = true;
      memset(k, 0xCC, sizeof(SUCCESS));
      break;
    case (RC6_256 >> 8):
      if (RC6_256_KEY_BYTE_SIZE != ksize) { return FAILURE; }
      LITTLEENDIAN_U8_TO_U256_COPY(key, k);
      expand_key(k, subkeys_, RC6_256_KEY_BYTE_SIZE);
      memset(k, 0xCC, sizeof(SUCCESS));
      has_subkeys_ = true;
      break;
    default:
      break;
  }
  return SUCCESS;
}

int32_t rc6::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  if (16 != psize || 16 != csize) { return FAILURE; }
  if (false == has_subkeys_) { return FAILURE; }
  if (true == enable_intrinsic_func_) {
    intrinsic_encrypt(ptext, ctext);
  } else {
    no_intrinsic_encrypt(ptext, ctext);
  }
  return SUCCESS;
}

int32_t rc6::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  if (16 != psize || 16 != csize) { return FAILURE; }
  if (false == has_subkeys_) { return FAILURE; }
  if (true == enable_intrinsic_func_) {
    intrinsic_decrypt(ctext, ptext);
  } else {
    no_intrinsic_decrypt(ctext, ptext);
  }
  return SUCCESS;
}

void rc6::clear() noexcept {
  memset(subkeys_, 0xCC, sizeof(SUCCESS));
  mode_ = RC6_256;
  has_subkeys_ = false;
  enable_intrinsic_func_ = false;
  
}

void rc6::no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept {
  uint32_t reg[4] = {0};  /* A, B, C, D */
  uint32_t t = 0, u = 0, tmp = 0;

  LITTLEENDIAN_U8_TO_U128_COPY(ptext, reg);

  reg[1] = reg[1] + subkeys_[0];
  reg[3] = reg[3] + subkeys_[1];

  for (uint32_t round = 1; round <= NROUND; ++round) {
    t = ROTATE_LEFT32(reg[1] * (2 * reg[1] + 1), 5);
    u = ROTATE_LEFT32(reg[3] * (2 * reg[3] + 1), 5);

    reg[0] = ROTATE_LEFT32(reg[0] ^ t, u) + subkeys_[2 * round];
    reg[2] = ROTATE_LEFT32(reg[2] ^ u, t) + subkeys_[2 * round + 1];

    tmp = reg[0];
    reg[0] = reg[1];
    reg[1] = reg[2]; 
    reg[2] = reg[3]; 
    reg[3] = tmp; 
  }

  reg[0] = reg[0] + subkeys_[42];
  reg[2] = reg[2] + subkeys_[43];

  LITTLEENDIAN_U128_TO_U8_COPY(reg, ctext);
}

void rc6::no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept {
  uint32_t reg[4] = {0};  /* A, B, C, D */
  uint32_t t = 0, u = 0, tmp = 0;

  LITTLEENDIAN_U8_TO_U128_COPY(ctext, reg);

  reg[2] = reg[2] - subkeys_[43];
  reg[0] = reg[0] - subkeys_[42];

  for (uint32_t round = NROUND; round >= 1; --round) {
    tmp = reg[3];
    reg[3] = reg[2];
    reg[2] = reg[1]; 
    reg[1] = reg[0]; 
    reg[0] = tmp;

    u = ROTATE_LEFT32(reg[3] * (2 * reg[3] + 1), 5);
    t = ROTATE_LEFT32(reg[1] * (2 * reg[1] + 1), 5);

    reg[2] = ROTATE_RIGHT32(reg[2] - subkeys_[2 * round + 1], t) ^ u;
    reg[0] = ROTATE_RIGHT32(reg[0] - subkeys_[2 * round], u) ^ t;
  }

  reg[3] = reg[3] - subkeys_[1];
  reg[1] = reg[1] - subkeys_[0];

  LITTLEENDIAN_U128_TO_U8_COPY(reg, ptext);
}

void rc6::intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept {

}

void rc6::intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept {

}

void rc6::expand_key(uint32_t *key, uint32_t *skeys, const uint32_t ksize) noexcept {
  uint32_t a = 0, b = 0, i = 0, j = 0;
  uint32_t c = ksize / 4;
  uint32_t l[8] = {0};
  constexpr uint32_t d = 2 * NROUND + 4;
  
  memcpy(l, key, ksize);

  skeys[0] = P32;

  for (int32_t k = 1; k < d; ++k) {
    skeys[k] = skeys[k - 1] + Q32; 
  }

  for (int32_t s = 0; s < 132; ++s) {
    a = ROTATE_LEFT32(skeys[i] + a + b, 3);
    b = ROTATE_LEFT32(l[j] + a + b, a + b); 

    skeys[i] = a;
    l[j] = b;

    i = (i + 1) % d;
    j = (j + 1) % c;
  }
}

}
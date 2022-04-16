/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "twofish.h"
#include "bit_utill.h"
#include "byte_utill.h"

namespace cryptography {

#define SUCCESS                       0
#define FAILURE                       1

#define TWOFISH_128BIT_KVALUE         2
#define TWOFISH_192BIT_KVALUE         3
#define TWOFISH_256BIT_KVALUE         4

#define TWOFISH_128BIT_KEY_BYTE_SIZE  4
#define TWOFISH_192BIT_KEY_BYTE_SIZE  6
#define TWOFISH_256BIT_KEY_BYTE_SIZE  8

#define TWOFISH_ROUND_MAX             15

#define TWOFISH_RHO                   16843009  /**< 2^24 + 2^16 + 2^8 + 2^0 */

#define ROTR4(x, shift)               (uint8_t)(((x) >> (shift) | ((x) << (4 - shift))) & 0xFF)

static const uint8_t q0t0[16] = {
  0x08, 0x01, 0x07, 0x0D, 0x06, 0x0F, 0x03, 0x02, 0x00, 0x0B, 0x05, 0x09, 0x0E, 0x0C, 0x0A, 0x04
};

static const uint8_t q0t1[16] = {
  0x0E, 0x0C, 0x0B, 0x08, 0x01, 0x02, 0x03, 0x05, 0x0F, 0x04, 0x0A, 0x06, 0x07, 0x00, 0x09, 0x0D
};

static const uint8_t q0t2[16] = {
  0x0B, 0x0A, 0x05, 0x0E, 0x06, 0x0D, 0x09, 0x00, 0x0C, 0x08, 0x0F, 0x03, 0x02, 0x04, 0x07, 0x01
};

static const uint8_t q0t3[16] = {
  0x0D, 0x07, 0x0F, 0x04, 0x01, 0x02, 0x06, 0x0E, 0x09, 0x0B, 0x03, 0x00, 0x08, 0x05, 0x0C, 0x0A
};

static const uint8_t q1t0[16] = {
  0x02, 0x08, 0x0B, 0x0D, 0x0F, 0x07, 0x06, 0x0E, 0x03, 0x01, 0x09, 0x04, 0x00, 0x0A, 0x0C, 0x05
};

static const uint8_t q1t1[16] = {
  0x01, 0x0E, 0x02, 0x0B, 0x04, 0x0C, 0x03, 0x07, 0x06, 0x0D, 0x0A, 0x05, 0x0F, 0x09, 0x00, 0x08
};

static const uint8_t q1t2[16] = {
  0x04, 0x0C, 0x07, 0x05, 0x01, 0x06, 0x09, 0x0A, 0x00, 0x0E, 0x0D, 0x08, 0x02, 0x0B, 0x03, 0x0F
};

static const uint8_t q1t3[16] = {
  0x0B, 0x09, 0x05, 0x01, 0x0C, 0x03, 0x0D, 0x0E, 0x06, 0x04, 0x07, 0x0F, 0x02, 0x00, 0x08, 0x0A
};

int32_t twofish::initialize(const uint32_t mode, const uint8_t *key, const uint32_t ksize, bool enable_intrinsic) noexcept {
  uint32_t k[8] = {0};

  if (TWOFISH != (mode & EXTRACT_TYPE)) {
    return FAILURE;
  }

  mode_ = mode;
  enable_intrinsic_func_ = enable_intrinsic;

  switch (mode >> 8) {
    case (TWOFISH >> 8):
      if (TWOFISH_128BIT_KEY_BYTE_SIZE != ksize) { return FAILURE; }
      LITTLEENDIAN_U8_TO_U128_COPY(key, k);
      expand_key(k, subkey_);
      memset(k, 0xCC, sizeof(k));
      has_subkeys_ = true;
      break;
    default:
      break;
  }
  return SUCCESS;
}

int32_t twofish::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) noexcept {
  if (16 != psize || 16 != csize) { return FAILURE; }
  if (false == has_subkeys_) { return FAILURE; }
  if (true == enable_intrinsic_func_) {
    intrinsic_encrypt(ptext, ctext);
  } else {
    no_intrinsic_encrypt(ptext, ctext);
  }
  return SUCCESS;
}

int32_t twofish::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) noexcept {
  if (16 != psize || 16 != csize) { return FAILURE; }
  if (false == has_subkeys_) { return FAILURE; }
  if (true == enable_intrinsic_func_) {
    intrinsic_decrypt(ctext, ptext);
  } else {
    no_intrinsic_decrypt(ctext, ptext);
  }
  return SUCCESS;
}

void twofish::clear() noexcept {

}

inline void twofish::no_intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept {
  uint32_t tmpp[4] = {0};
  uint32_t out[4] = {0};
  uint32_t f[2] = {0};

  LITTLEENDIAN_U8_TO_U128_COPY(ptext, tmpp);

  tmpp[0] ^= subkey_[0];
  tmpp[1] ^= subkey_[1];
  tmpp[2] ^= subkey_[2];
  tmpp[3] ^= subkey_[3];

  for (int32_t i = 0; i <= TWOFISH_ROUND_MAX; ++i) {
    f_function(tmpp[0], tmpp[1], i, f);
    f[0] = tmpp[2] ^ f[0];
    f[1] = tmpp[3] ^ f[1];

    tmpp[2] = tmpp[0];
    tmpp[3] = tmpp[1];
    tmpp[0] = f[0];
    tmpp[1] = f[1];
  }

  out[0] = tmpp[2];
  out[1] = tmpp[3];
  out[2] = tmpp[0];
  out[3] = tmpp[1];

  out[0] ^= subkey_[4];
  out[1] ^= subkey_[5];
  out[2] ^= subkey_[6];
  out[3] ^= subkey_[7];

  LITTLEENDIAN_U128_TO_U8_COPY(out, ctext);
}

inline void twofish::no_intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept {
  uint32_t tmpp[4] = {0};
  uint32_t out[4] = {0};
  uint32_t f[2] = {0};

  LITTLEENDIAN_U8_TO_U128_COPY(ctext, tmpp);

  tmpp[0] ^= subkey_[4];
  tmpp[1] ^= subkey_[5];
  tmpp[2] ^= subkey_[6];
  tmpp[3] ^= subkey_[7];

  for (int32_t i = TWOFISH_ROUND_MAX; i >= 0; --i) {
    f_function(tmpp[0], tmpp[1], i, f);
    f[0] = tmpp[2] ^ f[0];
    f[1] = tmpp[3] ^ f[1];

    tmpp[2] = tmpp[0];
    tmpp[3] = tmpp[1];
    tmpp[0] = f[0];
    tmpp[1] = f[1];
  }

  out[0] = tmpp[2];
  out[1] = tmpp[3];
  out[2] = tmpp[0];
  out[3] = tmpp[1];

  out[0] ^= subkey_[0];
  out[1] ^= subkey_[1];
  out[2] ^= subkey_[2];
  out[3] ^= subkey_[3];

  LITTLEENDIAN_U128_TO_U8_COPY(out, ptext);
}

inline void twofish::intrinsic_encrypt(const uint8_t * const ptext, uint8_t *ctext) const noexcept {

}

inline void twofish::intrinsic_decrypt(const uint8_t * const ctext, uint8_t *ptext) const noexcept {

}

inline void twofish::expand_key(const uint32_t * const key, uint32_t *skeys) noexcept {
  uint32_t me[4] = {0};
  uint32_t mo[4] = {0};
  uint32_t s[4] = {0};
  uint32_t a = 0;
  uint32_t b = 0;
  uint32_t tmpsbox = 0;

  for (uint32_t i = 0; i < 256; ++i) {
    q0_[i] = fix_q((uint8_t)i, q0t0, q0t1, q0t2, q0t3);
    q1_[i] = fix_q((uint8_t)i, q1t0, q1t1, q1t2, q1t3);
  }

  for (int32_t i = 0; i < k_;) {
    me[i] = key[2 * i];
    mo[i] = key[2 * i + 1];

    s[(k_ - 1) - i] |= (gf_mult(0x01, key[8 * i]) ^ gf_mult(0xA4, key[8 * i + 1]) ^ gf_mult(0x55, key[8 * i + 2]) ^ gf_mult(0x87, key[8 * i + 3]) ^ gf_mult(0x5A, key[8 * i + 4]) ^ gf_mult(0x58, key[8 * i + 5]) ^ gf_mult(0xDB, key[8 * i + 6]) ^ gf_mult(0x9E, key[8 * i + 7])) << 24;
    s[(k_ - 1) - i] |= (gf_mult(0xA4, key[8 * i]) ^ gf_mult(0x56, key[8 * i + 1]) ^ gf_mult(0x82, key[8 * i + 2]) ^ gf_mult(0xF3, key[8 * i + 3]) ^ gf_mult(0x1E, key[8 * i + 4]) ^ gf_mult(0xC6, key[8 * i + 5]) ^ gf_mult(0x68, key[8 * i + 6]) ^ gf_mult(0xE5, key[8 * i + 7])) << 16;
    s[(k_ - 1) - i] |= (gf_mult(0x02, key[8 * i]) ^ gf_mult(0xA1, key[8 * i + 1]) ^ gf_mult(0xFC, key[8 * i + 2]) ^ gf_mult(0xC1, key[8 * i + 3]) ^ gf_mult(0x47, key[8 * i + 4]) ^ gf_mult(0xAE, key[8 * i + 5]) ^ gf_mult(0x3D, key[8 * i + 6]) ^ gf_mult(0x19, key[8 * i + 7])) <<  8;
    s[(k_ - 1) - i] |= (gf_mult(0xA4, key[8 * i]) ^ gf_mult(0x55, key[8 * i + 1]) ^ gf_mult(0x87, key[8 * i + 2]) ^ gf_mult(0x5A, key[8 * i + 3]) ^ gf_mult(0x58, key[8 * i + 4]) ^ gf_mult(0xDB, key[8 * i + 5]) ^ gf_mult(0x9E, key[8 * i + 6]) ^ gf_mult(0x03, key[8 * i + 7])) <<  0;
  }

  for (int32_t i = 0; i < 40; ++i) {
    a = h_function(2 * i * TWOFISH_RHO, me, k_);
    b = ROTATE_LEFT32(h_function((2 * i + 1) * TWOFISH_RHO, mo, k_), 8);
    subkey_[2 * i] = (a + b);
    subkey_[2 * i + 1] = (a + b);
  }

  for (uint32_t i = 0; i < 256; ++i) {
    tmpsbox = h_function((uint8_t)i, s, k_);
    sbox0_[i] = (uint8_t)(tmpsbox >> 24) & 0xFF;
    sbox1_[i] = (uint8_t)(tmpsbox >> 16) & 0xFF;
    sbox2_[i] = (uint8_t)(tmpsbox >>  8) & 0xFF;
    sbox3_[i] = (uint8_t)(tmpsbox >>  0) & 0xFF;
  }
}

inline void twofish::f_function(uint32_t r0, uint32_t r1, int32_t round, uint32_t *f) const noexcept {
  uint32_t t0 = g_function(r0);
  uint32_t t1 = g_function(ROTATE_LEFT32(r1, 8));

  t0 ^= t1;
  t1 ^= t0;

  f[0] = (t0 + t1 + subkey_[2 * round + 8]);
  f[1] = (t0 + 2 * t1 + subkey_[2 * round + 9]);
}

inline uint32_t twofish::g_function(uint32_t x) const noexcept {
  uint8_t xi[4] = {0};
  uint8_t yi[4] = {0};
  uint32_t y = 0;

  LITTLEENDIAN_U32_TO_U8_COPY(x, xi);

  yi[0] = sbox0_[xi[0]];
  yi[1] = sbox1_[xi[1]];
  yi[2] = sbox2_[xi[2]];
  yi[3] = sbox3_[xi[3]];

  y |= gf_mult(0x01, yi[0]) ^ gf_mult(0xEF, yi[1]) ^ gf_mult(0x5B, yi[2]) ^ gf_mult(0x5B, yi[3]) << 24;
  y |= gf_mult(0x5B, yi[0]) ^ gf_mult(0xEF, yi[1]) ^ gf_mult(0xEF, yi[2]) ^ gf_mult(0x01, yi[3]) << 16;
  y |= gf_mult(0xEF, yi[0]) ^ gf_mult(0x5B, yi[1]) ^ gf_mult(0x01, yi[2]) ^ gf_mult(0xEF, yi[3]) <<  8;
  y |= gf_mult(0xEF, yi[0]) ^ gf_mult(0x01, yi[1]) ^ gf_mult(0xEF, yi[2]) ^ gf_mult(0x5B, yi[3]) <<  0;

  return y;
}

inline uint32_t twofish::h_function(uint32_t x, uint32_t *l, uint32_t type) const noexcept {
  uint8_t by[4] = {0};
  uint8_t bl[4][4] = {0};
  uint32_t z = 0;

  LITTLEENDIAN_U32_TO_U8_COPY(x, by);
  LITTLEENDIAN_U32_TO_U8_COPY(l[0], bl[0]);
  LITTLEENDIAN_U32_TO_U8_COPY(l[1], bl[1]);
  LITTLEENDIAN_U32_TO_U8_COPY(l[2], bl[2]);
  LITTLEENDIAN_U32_TO_U8_COPY(l[3], bl[3]);

  switch (type) {
    case 4:
      by[0] = q1_[by[0]] ^ bl[3][0];
      by[1] = q0_[by[1]] ^ bl[3][1];
      by[2] = q0_[by[2]] ^ bl[3][2];
      by[3] = q1_[by[3]] ^ bl[3][3];
    case 3:
      by[0] = q1_[by[0]] ^ bl[2][0];
      by[1] = q1_[by[1]] ^ bl[2][1];
      by[2] = q0_[by[2]] ^ bl[2][2];
      by[3] = q0_[by[3]] ^ bl[2][3];
    case 2:
      by[0] = q1_[q0_[q0_[by[0] ^ bl[1][0]]] ^ bl[0][0]];
      by[1] = q0_[q0_[q1_[by[1] ^ bl[1][1]]] ^ bl[0][1]];
      by[2] = q1_[q1_[q0_[by[2] ^ bl[1][2]]] ^ bl[0][2]];
      by[3] = q0_[q1_[q1_[by[3] ^ bl[1][3]]] ^ bl[0][3]];
      break;
    default:
      break;
  }

  z |= gf_mult(0x01, by[0]) ^ gf_mult(0xEF, by[1]) ^ gf_mult(0x5B, by[2]) ^ gf_mult(0x5B, by[3]) << 24;
  z |= gf_mult(0x5B, by[0]) ^ gf_mult(0xEF, by[1]) ^ gf_mult(0xEF, by[2]) ^ gf_mult(0x01, by[3]) << 16;
  z |= gf_mult(0xEF, by[0]) ^ gf_mult(0x5B, by[1]) ^ gf_mult(0x01, by[2]) ^ gf_mult(0xEF, by[3]) <<  8;
  z |= gf_mult(0xEF, by[0]) ^ gf_mult(0x01, by[1]) ^ gf_mult(0xEF, by[2]) ^ gf_mult(0x5B, by[3]) <<  0;

  return z;
}

inline uint8_t twofish::gf_mult(uint8_t x, uint8_t y) const noexcept {
  uint8_t result = 0;
  uint8_t mask = 0x01;

  while (0x00 != mask) {
    if (0x00 != (y & mask)) {
      result ^= x;
    }
    x = (x << 1) ^ ((0x00 != (x & 0x80)) ? 0x4d : 0x00);
    mask <<= 1;
  }
  return result;
}

inline uint8_t twofish::fix_q(uint8_t x, const uint8_t * const t0, const uint8_t * const t1, const uint8_t * const t2, const uint8_t * const t3) const noexcept {
  uint8_t a0 = 0;
  uint8_t a1 = 0;
  uint8_t b0 = 0;
  uint8_t b1 = 0;

  a0 = x >> 4;
  b0 = x & 0x0F;

  a1 = a0 ^ b0;
  b1 = (a0 ^ ROTR4(b0, 1) ^ 8 * a0) % 16; 

  a0 = t0[a1];
  b0 = t1[b1];

  a1 = a0 ^ b0;
  b1 = (a0 ^ ROTR4(b0, 1) ^ 8 * a0) % 16; 

  a0 = t2[a1];
  b0 = t3[b1];

  return b0 << 16 | a0;
}

}

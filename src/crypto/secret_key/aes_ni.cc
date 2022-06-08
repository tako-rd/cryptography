/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "crypto/secret_key/aes.h"
#include "common/bit.h"

namespace cryptography {

#define AES128_ROUNDS                        10
#define AES192_ROUNDS                        12
#define AES256_ROUNDS                        14

#define AES128_KEY_BYTE_SIZE                 16
#define AES192_KEY_BYTE_SIZE                 24
#define AES256_KEY_BYTE_SIZE                 32

#if (_M_X64 == 100 || _M_IX86 == 600) || (_X86_ == 1 || __x86_64__ == 1)
#define RCON01                               0x00000001
#define RCON02                               0x00000002
#define RCON03                               0x00000004
#define RCON04                               0x00000008
#define RCON05                               0x00000010
#define RCON06                               0x00000020
#define RCON07                               0x00000040
#define RCON08                               0x00000080
#define RCON09                               0x0000001b
#define RCON10                               0x00000036

# define LOAD_128BIT(data)                   _mm_loadu_si128((u128_t*)(data))

# define LOAD_KEY_64BIT(data)                _mm_loadl_epi64((u128_t*)(data))
# define LOAD_KEY_128BIT(data)               _mm_loadu_si128((u128_t*)(data))

# define ENCRYPT_ROUND_FIRST(data, key)      _mm_xor_si128((data), (key))
# define ENCRYPT_ROUND(data, key)            _mm_aesenc_si128((data), (key))
# define ENCRYPT_ROUND_LAST(data, key, out)  _mm_storeu_si128((u128_t*)(out), _mm_aesenclast_si128((data), (key)))

# define DECRYPT_ROUND_FIRST(data, key)      _mm_xor_si128((data), (key))
# define DECRYPT_ROUND(data, key)            _mm_aesdec_si128((data), (key))
# define DECRYPT_ROUND_LAST(data, key, out)  _mm_storeu_si128((u128_t*)(out), _mm_aesdeclast_si128((data), (key)))

# define INVERSE_MIXCOLUMNS(data)            _mm_aesimc_si128((data))

/* k1 = (w3, w2, w1, w0)                     */
/* f(w4) = SubWord(RotWord(w4))              */
/* w4  = w0 ^ f(w3)                          */
/* w5  = w0 ^ w1 ^ f(w3)                     */
/* w6  = w0 ^ w1 ^ w2 ^ f(w3)                */
/* w7  = w0 ^ w1 ^ w2 ^ w3 ^ f(w3)           */
# define EXPAND_128BIT_KEY(k, round, k1, t1, t2, rcon)   \
     t1 = _mm_slli_si128(k1, 4);                         \
     t1 = _mm_xor_si128(k1, t1);                         \
     t2 = _mm_slli_si128(t1, 8);                         \
     t1 = _mm_xor_si128(t1, t2);                         \
     k1 = _mm_aeskeygenassist_si128(k1, rcon);           \
     k1 = _mm_shuffle_epi32(k1, 0xFF);                   \
     k1 = _mm_xor_si128(t1, k1);                         \
     k[round] = k1;

/* k1 = (w3, w2, w1, w0)                     */
/* k1 = ( 0,  0, w5, w4)                     */
/* f(w5) = SubWord(RotWord(w5))              */
/* w6  = w0 ^ f(w5)                          */
/* w7  = w0 ^ w1 ^ f(w5)                     */
/* w8  = w0 ^ w1 ^ w2 ^ f(w5)                */
/* w9  = w0 ^ w1 ^ w2 ^ w3 ^ f(w5)           */
/* w10 = w0 ^ w1 ^ w2 ^ w3 ^ w4 ^ f(w5)      */
/* w11 = w0 ^ w1 ^ w2 ^ w3 ^ w4 ^ w5 ^ f(w5) */
# define EXPAND_192BIT_KEY1(k, round, k1, k2, f, t1, t2, rcon)       \
   f = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(k2, rcon), 0x55); \
   t1 = _mm_slli_si128(k1, 4);                                       \
   t1 = _mm_xor_si128(k1, t1);                                       \
   t2 = _mm_xor_si128(t1, f);                                        \
   t2 = _mm_unpacklo_epi64(k2, t2);                                  \
   k[round] = t2;                                                    \
   t1 = _mm_slli_si128(k2, 8);                                       \
   t2 = _mm_xor_si128(t1, _mm_slli_si128(k2, 12));                   \
   t1 = _mm_shuffle_epi32(k1, 0x00);                                 \
   t2 = _mm_xor_si128(t2, t1);                                       \
   t1 = _mm_shuffle_epi32(k1, 0x55);                                 \
   t2 = _mm_xor_si128(t2, t1);                                       \
   t1 = _mm_shuffle_epi32(k1, 0xAA);                                 \
   t2 = _mm_xor_si128(t2, t1);                                       \
   t1 = _mm_slli_si128(_mm_shuffle_epi32(k1, 0xFF), 4);              \
   t2 = _mm_xor_si128(t2, t1);                                       \
   t2 = _mm_xor_si128(t2, f);                                        \
   k[round + 1] = t2;                                                \
   t1 = _mm_srli_si128(k[round], 8);                                 \
   k1 = _mm_unpacklo_epi64(t1, k[round + 1]);                        \
   k2 = _mm_srli_si128(k[round + 1], 8);

/* k1 = (w9, w8,  w7,  w6)                      */
/* k1 = ( 0,  0, w11, w10)                      */
/* w12 = w6 ^ f(w11)                            */
/* w13 = w6 ^ w7 ^ f(w11)                       */
/* w14 = w6 ^ w7 ^ w8 ^ f(w11)                  */
/* w15 = w6 ^ w7 ^ w8 ^ w9 ^ f(w11)             */
/* w16 = w6 ^ w7 ^ w8 ^ w9 ^ w10 ^ f(w11)       */
/* w17 = w6 ^ w7 ^ w8 ^ w9 ^ w10 ^ w11 ^ f(w11) */
# define EXPAND_192BIT_KEY2(k, round, k1, k2, f, t1, t2, rcon)       \
   f = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(k2, rcon), 0x55); \
   t1 = _mm_slli_si128(k2, 8);                                       \
   t2 = _mm_xor_si128(t1, _mm_slli_si128(k2, 12));                   \
   t1 = _mm_shuffle_epi32(k1, 0x00);                                 \
   t2 = _mm_xor_si128(t2, t1);                                       \
   t1 = _mm_shuffle_epi32(k1, 0x55);                                 \
   t2 = _mm_xor_si128(t2, t1);                                       \
   t1 = _mm_shuffle_epi32(k1, 0xAA);                                 \
   t2 = _mm_xor_si128(t2, t1);                                       \
   t1 = _mm_slli_si128(_mm_shuffle_epi32(k1, 0xFF), 4);              \
   t2 = _mm_xor_si128(t2, t1);                                       \
   k2 = _mm_xor_si128(t2, f);                                        \
   t1 = _mm_xor_si128(k1, _mm_slli_si128(k1, 4));                    \
   t2 = _mm_xor_si128(t1, f);                                        \
   k1 = _mm_unpacklo_epi64(t2, k2);                                  \
   k2 = _mm_srli_si128(k2, 8);                                       \
   k[round] = k1;

/* k1 = (w3, w2, w1, w0)                 */
/* f(w7) = SubWord(RotWord(w7))          */
/* w8    = w0 ^ f(w7)                    */
/* w9    = w0 ^ w1 ^ f(w7)               */
/* w10   = w0 ^ w1 ^ w2 ^ f(w7)          */
/* w11   = w0 ^ w1 ^ w2 ^ w3 ^ f(w7)     */
# define EXPAND_256BIT_KEY1(k, round, k1, k2, f, t1, t2, rcon)       \
   f = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(k2, rcon), 0xFF); \
   t1 = _mm_slli_si128(k1, 4);                                       \
   t2 = _mm_xor_si128(t1, k1);                                       \
   t1 = _mm_slli_si128(t1, 4);                                       \
   t2 = _mm_xor_si128(t1, t2);                                       \
   t1 = _mm_slli_si128(t1, 4);                                       \
   t2 = _mm_xor_si128(t1, t2);                                       \
   k1 = _mm_xor_si128(t2, f);                                        \
   k[round] = k1;

/* k2 = (w7, w6, w5, w4)                 */
/* f'(w11) = SubWord(w11)                */
/* w12     = w4 ^ f'(w11)                */
/* w13     = w4 ^ w5 ^ f'(w11)           */
/* w14     = w4 ^ w5 ^ w6 ^ f'(w11)      */
/* w15     = w4 ^ w5 ^ w6 ^ w7 ^ f'(w11) */
# define EXPAND_256BIT_KEY2(k, round, k1, k2, f, t1, t2)             \
   f = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(k1, 0x00), 0xAA); \
   t1 = _mm_slli_si128(k2, 4);                                       \
   t2 = _mm_xor_si128(t1, k2);                                       \
   t1 = _mm_slli_si128(t1, 4);                                       \
   t2 = _mm_xor_si128(t1, t2);                                       \
   t1 = _mm_slli_si128(t1, 4);                                       \
   t2 = _mm_xor_si128(t1, t2);                                       \
   k2 = _mm_xor_si128(t2, f);                                        \
   k[round] = k2;
#elif (_M_ARM == 7)
static const ALIGNAS(32) uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const ALIGNAS(32) uint32_t rcon[11] = {
  0x00000000, 0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010,
  0x00000020, 0x00000040, 0x00000080, 0x0000001b, 0x00000036,
};

#define AES128_KEY_CONV_SIZE                 4
#define AES192_KEY_CONV_SIZE                 6
#define AES256_KEY_CONV_SIZE                 8

# define LOAD_128BIT(data)                   vld1q_u8((data))

# define LOAD_KEY_128BIT(data)               vreinterpretq_u8_u32(vld1q_u32((data)))

# define ENCRYPT_ROUND_FIRST(data, key)      veorq_s8((data), (key))
# define ENCRYPT_ROUND(data, key)            vaesmcq_u8(vaeseq_u8((data), (key)))
# define ENCRYPT_ROUND_LAST(data, key, out)  vst1q_u8(out, vaeseq_u8((data), (key)))

# define DECRYPT_ROUND_FIRST(data, key)      veorq_s8((data), (key))
# define DECRYPT_ROUND(data, key)            vaesimcq_u8(vaesdq_u8((data), (key)))
# define DECRYPT_ROUND_LAST(data, key, out)  vst1q_u8(out, vaesdq_u8((data), (key)))

# define INVERSE_MIXCOLUMNS(data)            vaesimcq_u8((data))

# define ROT_WORD(data)                      ROTATE_LEFT32(data, 8)
# define SUB_WORD(data, rcon)                ((uint32_t)sbox[((data) >> 24) & 0xFF] << 24 | \
                                              (uint32_t)sbox[((data) >> 16) & 0xFF] << 16 | \
                                              (uint32_t)sbox[((data) >>  8) & 0xFF] <<  8 | \
                                              (uint32_t)sbox[((data))       & 0xFF]) ^ (rcon)

#define EXPAND_KEY(k, t, nk, nr, rcn)             \
  for (uint32_t j = nk; j < 4 * (nr + 1); ++j) {  \
    t = k[j - 1];                                 \
    if (0 == (j % nk)) {                          \
      t = ROTATE_LEFT32(t, 8);                    \
      t = SUB_WORD(t, rcn[j / nk]);               \
    } else if (nk > 6 && 4 == (j % nk)) {         \
      t = SUB_WORD(t, 0);                         \
    }                                             \
    k[j] = k[j - nk] ^ t;                         \
  }

#endif

aes_ni::~aes_ni() {
  memset(encskeys_, 0xCC, sizeof(encskeys_));
  memset(decskeys_, 0xCC, sizeof(decskeys_));
}

int32_t aes_ni::initialize(const uint8_t *key, const uint32_t ksize) noexcept {
  switch (ksize) {
    case AES128_KEY_BYTE_SIZE:
      nr_ = AES128_ROUNDS;
      expand_128bit_key(key, encskeys_, decskeys_);
      has_subkeys_ = true;
      break;
    case AES192_KEY_BYTE_SIZE:
      nr_ = AES192_ROUNDS;
      expand_192bit_key(key, encskeys_, decskeys_);
      has_subkeys_ = true;
      break;
    case AES256_KEY_BYTE_SIZE:
      nr_ = AES256_ROUNDS;
      expand_256bit_key(key, encskeys_, decskeys_);
      has_subkeys_ = true;
      break;
    default:
      return KEY_SIZE_ERROR;
  }
  return SUCCESS;
}

int32_t aes_ni::encrypt(const uint8_t * const ptext, uint8_t *ctext) noexcept {
  u128_t st = LOAD_128BIT(ptext);
  u128_t *encskey = encskeys_;

  if (false == has_subkeys_) { return UNSET_KEY_ERROR; }

  st = ENCRYPT_ROUND_FIRST(st, *encskey);

  st = ENCRYPT_ROUND(st, *(++encskey));
  st = ENCRYPT_ROUND(st, *(++encskey));
  st = ENCRYPT_ROUND(st, *(++encskey));
  st = ENCRYPT_ROUND(st, *(++encskey));
  st = ENCRYPT_ROUND(st, *(++encskey));
  st = ENCRYPT_ROUND(st, *(++encskey));
  st = ENCRYPT_ROUND(st, *(++encskey));
  st = ENCRYPT_ROUND(st, *(++encskey));
  st = ENCRYPT_ROUND(st, *(++encskey));

  if (AES256_ROUNDS == nr_) {
    st = ENCRYPT_ROUND(st, *(++encskey));
    st = ENCRYPT_ROUND(st, *(++encskey));
    st = ENCRYPT_ROUND(st, *(++encskey));
    st = ENCRYPT_ROUND(st, *(++encskey));
  } else if (AES192_ROUNDS == nr_) {
    st = ENCRYPT_ROUND(st, *(++encskey));
    st = ENCRYPT_ROUND(st, *(++encskey));
  }
  ENCRYPT_ROUND_LAST(st, *(++encskey), ctext);

  return SUCCESS;
}

int32_t aes_ni::decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept {
  u128_t st = LOAD_128BIT(ctext);
  u128_t *decskey = &decskeys_[nr_];

  if (false == has_subkeys_) { return UNSET_KEY_ERROR; }

  st = DECRYPT_ROUND_FIRST(st, *decskey);

  if (AES256_ROUNDS == nr_) {
    st = DECRYPT_ROUND(st, *(--decskey));
    st = DECRYPT_ROUND(st, *(--decskey));
    st = DECRYPT_ROUND(st, *(--decskey));
    st = DECRYPT_ROUND(st, *(--decskey));
  } else if (AES192_ROUNDS == nr_) {
    st = DECRYPT_ROUND(st, *(--decskey));
    st = DECRYPT_ROUND(st, *(--decskey));
  }

  st = DECRYPT_ROUND(st, *(--decskey));
  st = DECRYPT_ROUND(st, *(--decskey));
  st = DECRYPT_ROUND(st, *(--decskey));
  st = DECRYPT_ROUND(st, *(--decskey));
  st = DECRYPT_ROUND(st, *(--decskey));
  st = DECRYPT_ROUND(st, *(--decskey));
  st = DECRYPT_ROUND(st, *(--decskey));
  st = DECRYPT_ROUND(st, *(--decskey));
  st = DECRYPT_ROUND(st, *(--decskey));

  DECRYPT_ROUND_LAST(st, *(--decskey), ptext);

  return SUCCESS;
}

void aes_ni::clear() noexcept {
  nr_ = 0;
  has_subkeys_ = false;
  memset(encskeys_, 0xCC, sizeof(encskeys_));
  memset(decskeys_, 0xCC, sizeof(decskeys_));
}

inline void aes_ni::expand_128bit_key(const uint8_t * const key, u128_t *encskeys, u128_t *decskeys) const noexcept {
#if (_M_X64 == 100 || _M_IX86 == 600)
  u128_t t1 = LOAD_KEY_128BIT(key);
  u128_t t2 = {0};
  u128_t t3 = {0};
#elif (_M_ARM == 7)
  uint32_t buf[44]  = {0};
  uint32_t tmp = 0;
#endif


#if (_M_X64 == 100 || _M_IX86 == 600)
  encskeys[0] = t1;

  EXPAND_128BIT_KEY(encskeys,  1, t1, t2, t3, RCON01);
  EXPAND_128BIT_KEY(encskeys,  2, t1, t2, t3, RCON02);
  EXPAND_128BIT_KEY(encskeys,  3, t1, t2, t3, RCON03);
  EXPAND_128BIT_KEY(encskeys,  4, t1, t2, t3, RCON04);
  EXPAND_128BIT_KEY(encskeys,  5, t1, t2, t3, RCON05);
  EXPAND_128BIT_KEY(encskeys,  6, t1, t2, t3, RCON06);
  EXPAND_128BIT_KEY(encskeys,  7, t1, t2, t3, RCON07);
  EXPAND_128BIT_KEY(encskeys,  8, t1, t2, t3, RCON08);
  EXPAND_128BIT_KEY(encskeys,  9, t1, t2, t3, RCON09);
  EXPAND_128BIT_KEY(encskeys, 10, t1, t2, t3, RCON10);
#elif (_M_ARM == 7)
  memcpy(buf, key, 16);
  EXPAND_KEY(buf, tmp, AES128_KEY_CONV_SIZE, AES128_ROUNDS, rcon);

  encskeys[0]  = LOAD_KEY_128BIT(&buf[0]);
  encskeys[1]  = LOAD_KEY_128BIT(&buf[4]);
  encskeys[2]  = LOAD_KEY_128BIT(&buf[8]);
  encskeys[3]  = LOAD_KEY_128BIT(&buf[12]);
  encskeys[4]  = LOAD_KEY_128BIT(&buf[16]);
  encskeys[5]  = LOAD_KEY_128BIT(&buf[20]);
  encskeys[6]  = LOAD_KEY_128BIT(&buf[24]);
  encskeys[7]  = LOAD_KEY_128BIT(&buf[28]);
  encskeys[8]  = LOAD_KEY_128BIT(&buf[32]);
  encskeys[9]  = LOAD_KEY_128BIT(&buf[36]);
  encskeys[10] = LOAD_KEY_128BIT(&buf[40]);

  memset(buf, 0x00000000, sizeof(buf));
#endif

  /* EqInvCipher */
  decskeys[0]  = encskeys[0];
  decskeys[1]  = INVERSE_MIXCOLUMNS(encskeys[1]);
  decskeys[2]  = INVERSE_MIXCOLUMNS(encskeys[2]);
  decskeys[3]  = INVERSE_MIXCOLUMNS(encskeys[3]);
  decskeys[4]  = INVERSE_MIXCOLUMNS(encskeys[4]);
  decskeys[5]  = INVERSE_MIXCOLUMNS(encskeys[5]);
  decskeys[6]  = INVERSE_MIXCOLUMNS(encskeys[6]);
  decskeys[7]  = INVERSE_MIXCOLUMNS(encskeys[7]);
  decskeys[8]  = INVERSE_MIXCOLUMNS(encskeys[8]);
  decskeys[9]  = INVERSE_MIXCOLUMNS(encskeys[9]);
  decskeys[10] = encskeys[10];
}

inline void aes_ni::expand_192bit_key(const uint8_t * const key, u128_t *encskeys, u128_t *decskeys) const noexcept {
#if (_M_X64 == 100 || _M_IX86 == 600)
  u128_t k1 = LOAD_KEY_128BIT(key);
  u128_t k2 = LOAD_KEY_64BIT((key + 16));
  u128_t t1 = {0};
  u128_t t2 = {0};
  u128_t f  = {0};
#elif (_M_ARM == 7)
  uint32_t buf[52]  = {0};
  uint32_t tmp = 0;
#endif

#if (_M_X64 == 100 || _M_IX86 == 600)
  encskeys[0] = k1;

  EXPAND_192BIT_KEY1(encskeys,  1, k1, k2, f, t1, t2, RCON01);
  EXPAND_192BIT_KEY2(encskeys,  3, k1, k2, f, t1, t2, RCON02);

  EXPAND_192BIT_KEY1(encskeys,  4, k1, k2, f, t1, t2, RCON03);
  EXPAND_192BIT_KEY2(encskeys,  6, k1, k2, f, t1, t2, RCON04);

  EXPAND_192BIT_KEY1(encskeys,  7, k1, k2, f, t1, t2, RCON05);
  EXPAND_192BIT_KEY2(encskeys,  9, k1, k2, f, t1, t2, RCON06);

  EXPAND_192BIT_KEY1(encskeys, 10, k1, k2, f, t1, t2, RCON07);
  EXPAND_192BIT_KEY2(encskeys, 12, k1, k2, f, t1, t2, RCON08);
#elif (_M_ARM == 7)
  memcpy(buf, key, 24);
  EXPAND_KEY(buf, tmp, AES192_KEY_CONV_SIZE, AES192_ROUNDS, rcon);

  encskeys[0]  = LOAD_KEY_128BIT(&buf[0]);
  encskeys[1]  = LOAD_KEY_128BIT(&buf[4]);
  encskeys[2]  = LOAD_KEY_128BIT(&buf[8]);
  encskeys[3]  = LOAD_KEY_128BIT(&buf[12]);
  encskeys[4]  = LOAD_KEY_128BIT(&buf[16]);
  encskeys[5]  = LOAD_KEY_128BIT(&buf[20]);
  encskeys[6]  = LOAD_KEY_128BIT(&buf[24]);
  encskeys[7]  = LOAD_KEY_128BIT(&buf[28]);
  encskeys[8]  = LOAD_KEY_128BIT(&buf[32]);
  encskeys[9]  = LOAD_KEY_128BIT(&buf[36]);
  encskeys[10] = LOAD_KEY_128BIT(&buf[40]);
  encskeys[11] = LOAD_KEY_128BIT(&buf[44]);
  encskeys[12] = LOAD_KEY_128BIT(&buf[48]);

  memset(buf, 0x00000000, sizeof(buf));
#endif

  /* EqInvCipher */
  decskeys[0]  = encskeys[0];
  decskeys[1]  = INVERSE_MIXCOLUMNS(encskeys[1]);
  decskeys[2]  = INVERSE_MIXCOLUMNS(encskeys[2]);
  decskeys[3]  = INVERSE_MIXCOLUMNS(encskeys[3]);
  decskeys[4]  = INVERSE_MIXCOLUMNS(encskeys[4]);
  decskeys[5]  = INVERSE_MIXCOLUMNS(encskeys[5]);
  decskeys[6]  = INVERSE_MIXCOLUMNS(encskeys[6]);
  decskeys[7]  = INVERSE_MIXCOLUMNS(encskeys[7]);
  decskeys[8]  = INVERSE_MIXCOLUMNS(encskeys[8]);
  decskeys[9]  = INVERSE_MIXCOLUMNS(encskeys[9]);
  decskeys[10] = INVERSE_MIXCOLUMNS(encskeys[10]);
  decskeys[11] = INVERSE_MIXCOLUMNS(encskeys[11]);
  decskeys[12] = encskeys[12];
}

inline void aes_ni::expand_256bit_key(const uint8_t * const key, u128_t *encskeys, u128_t *decskeys) const noexcept {
#if (_M_X64 == 100 || _M_IX86 == 600)
  u128_t k1 = LOAD_KEY_128BIT(key);
  u128_t k2 = LOAD_KEY_128BIT((key + 16));
  u128_t t1 = {0};
  u128_t t2 = {0};
  u128_t f  = {0};
#elif (_M_ARM == 7)
  uint32_t buf[60]  = {0};
  uint32_t tmp = 0;
#endif

#if (_M_X64 == 100 || _M_IX86 == 600)
  encskeys[0] = k1;
  encskeys[1] = k2;

  EXPAND_256BIT_KEY1(encskeys,  2, k1, k2, f, t1, t2, RCON01);
  EXPAND_256BIT_KEY2(encskeys,  3, k1, k2, f, t1, t2);

  EXPAND_256BIT_KEY1(encskeys,  4, k1, k2, f, t1, t2, RCON02);
  EXPAND_256BIT_KEY2(encskeys,  5, k1, k2, f, t1, t2);

  EXPAND_256BIT_KEY1(encskeys,  6, k1, k2, f, t1, t2, RCON03);
  EXPAND_256BIT_KEY2(encskeys,  7, k1, k2, f, t1, t2);

  EXPAND_256BIT_KEY1(encskeys,  8, k1, k2, f, t1, t2, RCON04);
  EXPAND_256BIT_KEY2(encskeys,  9, k1, k2, f, t1, t2);

  EXPAND_256BIT_KEY1(encskeys, 10, k1, k2, f, t1, t2, RCON05);
  EXPAND_256BIT_KEY2(encskeys, 11, k1, k2, f, t1, t2);

  EXPAND_256BIT_KEY1(encskeys, 12, k1, k2, f, t1, t2, RCON06);
  EXPAND_256BIT_KEY2(encskeys, 13, k1, k2, f, t1, t2);

  EXPAND_256BIT_KEY1(encskeys, 14, k1, k2, f, t1, t2, RCON07);
#elif (_M_ARM == 7)
  memcpy(buf, key, 32);
  EXPAND_KEY(buf, tmp, AES256_KEY_CONV_SIZE, AES256_ROUNDS, rcon);

  encskeys[0]  = LOAD_KEY_128BIT(&buf[0]);
  encskeys[1]  = LOAD_KEY_128BIT(&buf[4]);
  encskeys[2]  = LOAD_KEY_128BIT(&buf[8]);
  encskeys[3]  = LOAD_KEY_128BIT(&buf[12]);
  encskeys[4]  = LOAD_KEY_128BIT(&buf[16]);
  encskeys[5]  = LOAD_KEY_128BIT(&buf[20]);
  encskeys[6]  = LOAD_KEY_128BIT(&buf[24]);
  encskeys[7]  = LOAD_KEY_128BIT(&buf[28]);
  encskeys[8]  = LOAD_KEY_128BIT(&buf[32]);
  encskeys[9]  = LOAD_KEY_128BIT(&buf[36]);
  encskeys[10] = LOAD_KEY_128BIT(&buf[40]);
  encskeys[11] = LOAD_KEY_128BIT(&buf[44]);
  encskeys[12] = LOAD_KEY_128BIT(&buf[48]);
  encskeys[13] = LOAD_KEY_128BIT(&buf[52]);
  encskeys[14] = LOAD_KEY_128BIT(&buf[56]);

  memset(buf, 0x00000000, sizeof(buf));
#endif

  /* EqInvCipher */
  decskeys[0]  = encskeys[0];
  decskeys[1]  = INVERSE_MIXCOLUMNS(encskeys[1]);
  decskeys[2]  = INVERSE_MIXCOLUMNS(encskeys[2]);
  decskeys[3]  = INVERSE_MIXCOLUMNS(encskeys[3]);
  decskeys[4]  = INVERSE_MIXCOLUMNS(encskeys[4]);
  decskeys[5]  = INVERSE_MIXCOLUMNS(encskeys[5]);
  decskeys[6]  = INVERSE_MIXCOLUMNS(encskeys[6]);
  decskeys[7]  = INVERSE_MIXCOLUMNS(encskeys[7]);
  decskeys[8]  = INVERSE_MIXCOLUMNS(encskeys[8]);
  decskeys[9]  = INVERSE_MIXCOLUMNS(encskeys[9]);
  decskeys[10] = INVERSE_MIXCOLUMNS(encskeys[10]);
  decskeys[11] = INVERSE_MIXCOLUMNS(encskeys[11]);
  decskeys[12] = INVERSE_MIXCOLUMNS(encskeys[12]);
  decskeys[13] = INVERSE_MIXCOLUMNS(encskeys[13]);
  decskeys[14] = encskeys[14];
}

}

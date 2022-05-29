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

#define AES128_ROUNDS           10
#define AES192_ROUNDS           12
#define AES256_ROUNDS           14

#define AES128_KEY_BYTE_SIZE    16
#define AES192_KEY_BYTE_SIZE    24
#define AES256_KEY_BYTE_SIZE    32

#define RCON01  0x0000'0001
#define RCON02  0x0000'0002
#define RCON03  0x0000'0004
#define RCON04  0x0000'0008
#define RCON05  0x0000'0010
#define RCON06  0x0000'0020
#define RCON07  0x0000'0040
#define RCON08  0x0000'0080
#define RCON09  0x0000'001b
#define RCON10  0x0000'0036

/* k1 = (w3, w2, w1, w0)                     */
/* f(w4) = SubWord(RotWord(w4))              */
/* w4  = w0 ^ f(w3)                          */
/* w5  = w0 ^ w1 ^ f(w3)                     */
/* w6  = w0 ^ w1 ^ w2 ^ f(w3)                */
/* w7  = w0 ^ w1 ^ w2 ^ w3 ^ f(w3)           */
#define EXPAND_128BIT_KEY(k, round, k1, t1, t2, rcon)   \
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
#define EXPAND_192BIT_KEY1(k, round, k1, k2, f, t1, t2, rcon)       \
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
#define EXPAND_192BIT_KEY2(k, round, k1, k2, f, t1, t2, rcon)       \
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
#define EXPAND_256BIT_KEY1(k, round, k1, k2, f, t1, t2, rcon)       \
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
#define EXPAND_256BIT_KEY2(k, round, k1, k2, f, t1, t2)             \
  f = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(k1, 0x00), 0xAA); \
  t1 = _mm_slli_si128(k2, 4);                                       \
  t2 = _mm_xor_si128(t1, k2);                                       \
  t1 = _mm_slli_si128(t1, 4);                                       \
  t2 = _mm_xor_si128(t1, t2);                                       \
  t1 = _mm_slli_si128(t1, 4);                                       \
  t2 = _mm_xor_si128(t1, t2);                                       \
  k2 = _mm_xor_si128(t2, f);                                        \
  k[round] = k2;


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
  __m128i st = _mm_loadu_si128((__m128i*)ptext);
  __m128i *encskey = encskeys_;

  if (false == has_subkeys_) { return UNSET_KEY_ERROR; }

  st = _mm_xor_si128(st, *encskey);

  st = _mm_aesenc_si128(st, *(++encskey));
  st = _mm_aesenc_si128(st, *(++encskey));
  st = _mm_aesenc_si128(st, *(++encskey));
  st = _mm_aesenc_si128(st, *(++encskey));
  st = _mm_aesenc_si128(st, *(++encskey));
  st = _mm_aesenc_si128(st, *(++encskey));
  st = _mm_aesenc_si128(st, *(++encskey));
  st = _mm_aesenc_si128(st, *(++encskey));
  st = _mm_aesenc_si128(st, *(++encskey));

  if (AES256_ROUNDS == nr_) {
    st = _mm_aesenc_si128(st, *(++encskey));
    st = _mm_aesenc_si128(st, *(++encskey));
    st = _mm_aesenc_si128(st, *(++encskey));
    st = _mm_aesenc_si128(st, *(++encskey));
  } else if (AES192_ROUNDS == nr_) {
    st = _mm_aesenc_si128(st, *(++encskey));
    st = _mm_aesenc_si128(st, *(++encskey));
  }
  _mm_storeu_si128((__m128i*)ctext, _mm_aesenclast_si128(st, *(++encskey)));

  return SUCCESS;
}

int32_t aes_ni::decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept {
  __m128i st = _mm_loadu_si128((__m128i*)ctext);
  __m128i *decskey = &decskeys_[nr_];

  if (false == has_subkeys_) { return UNSET_KEY_ERROR; }

  st = _mm_xor_si128(st, *decskey);

  if (AES256_ROUNDS == nr_) {
    st = _mm_aesdec_si128(st, *(--decskey));
    st = _mm_aesdec_si128(st, *(--decskey));
    st = _mm_aesdec_si128(st, *(--decskey));
    st = _mm_aesdec_si128(st, *(--decskey));
  } else if (AES192_ROUNDS == nr_) {
    st = _mm_aesdec_si128(st, *(--decskey));
    st = _mm_aesdec_si128(st, *(--decskey));
  }

  st = _mm_aesdec_si128(st, *(--decskey));
  st = _mm_aesdec_si128(st, *(--decskey));
  st = _mm_aesdec_si128(st, *(--decskey));
  st = _mm_aesdec_si128(st, *(--decskey));
  st = _mm_aesdec_si128(st, *(--decskey));
  st = _mm_aesdec_si128(st, *(--decskey));
  st = _mm_aesdec_si128(st, *(--decskey));
  st = _mm_aesdec_si128(st, *(--decskey));
  st = _mm_aesdec_si128(st, *(--decskey));

  _mm_storeu_si128((__m128i*)ptext, _mm_aesdeclast_si128(st, *(--decskey)));

  return SUCCESS;
}

void aes_ni::clear() noexcept {
  nr_ = 0;
  has_subkeys_ = false;
  memset(encskeys_, 0xCC, sizeof(encskeys_));
  memset(decskeys_, 0xCC, sizeof(decskeys_));
}

inline void aes_ni::expand_128bit_key(const uint8_t * const key, __m128i *encskeys, __m128i *decskeys) const noexcept {
  __m128i t1 = _mm_loadu_si128((const __m128i *)key);
  __m128i t2 = {0};
  __m128i t3 = {0};

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

  /* EqInvCipher */
  decskeys[0]  = encskeys[0];   
  decskeys[1]  = _mm_aesimc_si128(encskeys[1]);
  decskeys[2]  = _mm_aesimc_si128(encskeys[2]);
  decskeys[3]  = _mm_aesimc_si128(encskeys[3]);
  decskeys[4]  = _mm_aesimc_si128(encskeys[4]);
  decskeys[5]  = _mm_aesimc_si128(encskeys[5]);
  decskeys[6]  = _mm_aesimc_si128(encskeys[6]);
  decskeys[7]  = _mm_aesimc_si128(encskeys[7]);
  decskeys[8]  = _mm_aesimc_si128(encskeys[8]);
  decskeys[9]  = _mm_aesimc_si128(encskeys[9]);
  decskeys[10] = encskeys[10];
}

inline void aes_ni::expand_192bit_key(const uint8_t * const key, __m128i *encskeys, __m128i *decskeys) const noexcept {
  __m128i k1 = _mm_loadu_si128((const __m128i *)key);
  __m128i k2 = _mm_loadl_epi64((const __m128i *)(key + 16));
  __m128i t1 = {0};
  __m128i t2 = {0};
  __m128i f  = {0}; 

  encskeys[0] = k1;

  EXPAND_192BIT_KEY1(encskeys,  1, k1, k2, f, t1, t2, RCON01);
  EXPAND_192BIT_KEY2(encskeys,  3, k1, k2, f, t1, t2, RCON02);
                                   
  EXPAND_192BIT_KEY1(encskeys,  4, k1, k2, f, t1, t2, RCON03);
  EXPAND_192BIT_KEY2(encskeys,  6, k1, k2, f, t1, t2, RCON04);
                                   
  EXPAND_192BIT_KEY1(encskeys,  7, k1, k2, f, t1, t2, RCON05);
  EXPAND_192BIT_KEY2(encskeys,  9, k1, k2, f, t1, t2, RCON06);

  EXPAND_192BIT_KEY1(encskeys, 10, k1, k2, f, t1, t2, RCON07);
  EXPAND_192BIT_KEY2(encskeys, 12, k1, k2, f, t1, t2, RCON08);

  /* EqInvCipher */
  decskeys[0]  = encskeys[0];
  decskeys[1]  = _mm_aesimc_si128(encskeys[1]);
  decskeys[2]  = _mm_aesimc_si128(encskeys[2]);
  decskeys[3]  = _mm_aesimc_si128(encskeys[3]);
  decskeys[4]  = _mm_aesimc_si128(encskeys[4]);
  decskeys[5]  = _mm_aesimc_si128(encskeys[5]);
  decskeys[6]  = _mm_aesimc_si128(encskeys[6]);
  decskeys[7]  = _mm_aesimc_si128(encskeys[7]);
  decskeys[8]  = _mm_aesimc_si128(encskeys[8]);
  decskeys[9]  = _mm_aesimc_si128(encskeys[9]);
  decskeys[10] = _mm_aesimc_si128(encskeys[10]);
  decskeys[11] = _mm_aesimc_si128(encskeys[11]);
  decskeys[12] = encskeys[12];
}

inline void aes_ni::expand_256bit_key(const uint8_t * const key, __m128i *encskeys, __m128i *decskeys) const noexcept {
  __m128i k1 = _mm_loadu_si128((const __m128i *)key);
  __m128i k2 = _mm_loadu_si128((const __m128i *)(key + 16));
  __m128i t1 = {0};
  __m128i t2 = {0};
  __m128i f  = {0}; 

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

  /* EqInvCipher */
  decskeys[0]  = encskeys[0];
  decskeys[1]  = _mm_aesimc_si128(encskeys[1]);
  decskeys[2]  = _mm_aesimc_si128(encskeys[2]);
  decskeys[3]  = _mm_aesimc_si128(encskeys[3]);
  decskeys[4]  = _mm_aesimc_si128(encskeys[4]);
  decskeys[5]  = _mm_aesimc_si128(encskeys[5]);
  decskeys[6]  = _mm_aesimc_si128(encskeys[6]);
  decskeys[7]  = _mm_aesimc_si128(encskeys[7]);
  decskeys[8]  = _mm_aesimc_si128(encskeys[8]);
  decskeys[9]  = _mm_aesimc_si128(encskeys[9]);
  decskeys[10] = _mm_aesimc_si128(encskeys[10]);
  decskeys[11] = _mm_aesimc_si128(encskeys[11]);
  decskeys[12] = _mm_aesimc_si128(encskeys[12]);
  decskeys[13] = _mm_aesimc_si128(encskeys[13]);
  decskeys[14] = encskeys[14];
}

}
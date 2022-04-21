/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "des.h"
#include "bit_utill.h"
#include "byte_utill.h"

namespace cryptography {

#define EXTRACT_6BIT_1                                    0x0000'0000'0000'003F
#define EXTRACT_6BIT_2                                    0x0000'0000'0000'0FC0
#define EXTRACT_6BIT_3                                    0x0000'0000'0003'F000
#define EXTRACT_6BIT_4                                    0x0000'0000'00FC'0000
#define EXTRACT_6BIT_5                                    0x0000'0000'3F00'0000
#define EXTRACT_6BIT_6                                    0x0000'000F'C000'0000
#define EXTRACT_6BIT_7                                    0x0000'03F0'0000'0000
#define EXTRACT_6BIT_8                                    0x0000'FC00'0000'0000

#define EXTRACT_BYTE_1                                    0x0000'0000'0000'00FF
#define EXTRACT_BYTE_2                                    0x0000'0000'0000'FF00
#define EXTRACT_BYTE_3                                    0x0000'0000'00FF'0000
#define EXTRACT_BYTE_4                                    0x0000'0000'FF00'0000
#define EXTRACT_BYTE_5                                    0x0000'00FF'0000'0000
#define EXTRACT_BYTE_6                                    0x0000'FF00'0000'0000
#define EXTRACT_BYTE_7                                    0x00FF'0000'0000'0000
#define EXTRACT_BYTE_8                                    0xFF00'0000'0000'0000

#define KEY_SHIFT_EXTRACT_MSB_1BIT                        0x0800'0000
#define KEY_SHIFT_EXTRACT_MSB_2BIT                        0x0C00'0000
#define KEY_SHIFT_REMOVE_MSB_1BIT                         0x07FF'FFFF
#define KEY_SHIFT_REMOVE_MSB_2BIT                         0x03FF'FFFF

#define KEY_SHIFT_EXTRACT_LSB_1BIT                        0x0000'0001
#define KEY_SHIFT_EXTRACT_LSB_2BIT                        0x0000'0003
#define KEY_SHIFT_REMOVE_LSB_1BIT                         0x0FFF'FFFE
#define KEY_SHIFT_REMOVE_LSB_2BIT                         0x0FFF'FFFC

#define SUBKEY_EXTRACT_LEFT_7BYTE                         0x00FF'FFFF'F000'0000
#define SUBKEY_EXTRACT_RIGHT_7BYTE                        0x0000'0000'0FFF'FFFF

#define EXTRACT_LEFT_1BIT                                 0x20
#define EXTRACT_RIGHT_1BIT                                0x01
#define EXTRACT_MIDDLE_4BIT                               0x1E

#define EXTRACT_AND_SET_BIT_LEFT64(target, pos, setpos)   POPCOUNT64(target & (0x8000'0000'0000'0000 >> (pos - 1))) << (63 - setpos)
#define EXTRACT_BIT_LEFT64(target, position)              POPCOUNT64(target & (0x8000'0000'0000'0000 >> (position - 1)))

#define EXTRACT_AND_SET_BIT_LEFT32(target, pos, setpos)   POPCOUNT32(target & (0x8000'0000 >> (pos - 1))) << (31 - setpos)
#define EXTRACT_BIT_LEFT32(target, position)              POPCOUNT32(target & (0x8000'0000 >> (position - 1)))

#define SUCCESS                                           0
#define FAILURE                                           1

static const uint8_t ip[64] = {
  0x3A, 0x32, 0x2A, 0x22, 0x1A, 0x12, 0x0A, 0x02,
  0x3C, 0x34, 0x2C, 0x24, 0x1C, 0x14, 0x0C, 0x04,
  0x3E, 0x36, 0x2E, 0x26, 0x1E, 0x16, 0x0E, 0x06,
  0x40, 0x38, 0x30, 0x28, 0x20, 0x18, 0x10, 0x08,
  0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09, 0x01,
  0x3B, 0x33, 0x2B, 0x23, 0x1B, 0x13, 0x0B, 0x03,
  0x3D, 0x35, 0x2D, 0x25, 0x1D, 0x15, 0x0D, 0x05,
  0x3F, 0x37, 0x2F, 0x27, 0x1F, 0x17, 0x0F, 0x07,
};

static const uint8_t invip[64] = {
  0x28, 0x08, 0x30, 0x10, 0x38, 0x18, 0x40, 0x20,
  0x27, 0x07, 0x2F, 0x0F, 0x37, 0x17, 0x3F, 0x1F,
  0x26, 0x06, 0x2E, 0x0E, 0x36, 0x16, 0x3E, 0x1E,
  0x25, 0x05, 0x2D, 0x0D, 0x35, 0x15, 0x3D, 0x1D,
  0x24, 0x04, 0x2C, 0x0C, 0x34, 0x14, 0x3C, 0x1C,
  0x23, 0x03, 0x2B, 0x0B, 0x33, 0x13, 0x3B, 0x1B,
  0x22, 0x02, 0x2A, 0x0A, 0x32, 0x12, 0x3A, 0x1A,
  0x21, 0x01, 0x29, 0x09, 0x31, 0x11, 0x39, 0x19,
};

static const uint8_t e[48] = {
  0x20, 0x01, 0x02, 0x03, 0x04, 0x05,
  0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
  0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
  0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
  0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x01,
};

static const uint8_t p[32] = {
  0x10, 0x07, 0x14, 0x15,
  0x1D, 0x0C, 0x1C, 0x11,
  0x01, 0x0F, 0x17, 0x1A,
  0x05, 0x12, 0x1F, 0x0A,
  0x02, 0x08, 0x18, 0x0E,
  0x20, 0x1B, 0x03, 0x09,
  0x13, 0x0D, 0x1E, 0x06,
  0x16, 0x0B, 0x04, 0x19,
};

static const uint8_t pc1[56] = {
  0x39, 0x31, 0x29, 0x21, 0x19, 0x11, 0x09,
  0x01, 0x3A, 0x32, 0x2A, 0x22, 0x1A, 0x12,
  0x0A, 0x02, 0x3B, 0x33, 0x2B, 0x23, 0x1B,
  0x13, 0x0B, 0x03, 0x3C, 0x34, 0x2C, 0x24,
  0x3F, 0x37, 0x2F, 0x27, 0x1F, 0x17, 0x0F,
  0x07, 0x3E, 0x36, 0x2E, 0x26, 0x1E, 0x16,
  0x0E, 0x06, 0x3D, 0x35, 0x2D, 0x25, 0x1D,
  0x15, 0x0D, 0x05, 0x1C, 0x14, 0x0C, 0x04,
};

static const uint8_t pc2[48] = {
  0x0E, 0x11, 0x0B, 0x18, 0x01, 0x05,
  0x03, 0x1C, 0x0F, 0x06, 0x15, 0x0A,
  0x17, 0x13, 0x0C, 0x04, 0x1A, 0x08,
  0x10, 0x07, 0x1B, 0x14, 0x0D, 0x02,
  0x29, 0x34, 0x1F, 0x25, 0x2F, 0x37,
  0x1E, 0x28, 0x33, 0x2D, 0x21, 0x30,
  0x2C, 0x31, 0x27, 0x38, 0x22, 0x35,
  0x2E, 0x2A, 0x32, 0x24, 0x1D, 0x20,
};

static const uint8_t sbox[8][4][16] = {
  { /* SBOX1 */
    {0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08, 0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07},
    {0x00, 0x0F, 0x07, 0x04, 0x0E, 0x02, 0x0D, 0x01, 0x0A, 0x06, 0x0C, 0x0B, 0x09, 0x05, 0x03, 0x08},
    {0x04, 0x01, 0x0E, 0x08, 0x0D, 0x06, 0x02, 0x0B, 0x0F, 0x0C, 0x09, 0x07, 0x03, 0x0A, 0x05, 0x00},
    {0x0F, 0x0C, 0x08, 0x02, 0x04, 0x09, 0x01, 0x07, 0x05, 0x0B, 0x03, 0x0E, 0x0A, 0x00, 0x06, 0x0D},
  }, 
  { /* SBOX2 */
    {0x0F, 0x01, 0x08, 0x0E, 0x06, 0x0B, 0x03, 0x04, 0x09, 0x07, 0x02, 0x0D, 0x0C, 0x00, 0x05, 0x0A},
    {0x03, 0x0D, 0x04, 0x07, 0x0F, 0x02, 0x08, 0x0E, 0x0C, 0x00, 0x01, 0x0A, 0x06, 0x09, 0x0B, 0x05},
    {0x00, 0x0E, 0x07, 0x0B, 0x0A, 0x04, 0x0D, 0x01, 0x05, 0x08, 0x0C, 0x06, 0x09, 0x03, 0x02, 0x0F},
    {0x0D, 0x08, 0x0A, 0x01, 0x03, 0x0F, 0x04, 0x02, 0x0B, 0x06, 0x07, 0x0C, 0x00, 0x05, 0x0E, 0x09},
  },
  { /* SBOX3 */
    {0x0A, 0x00, 0x09, 0x0E, 0x06, 0x03, 0x0F, 0x05, 0x01, 0x0D, 0x0C, 0x07, 0x0B, 0x04, 0x02, 0x08},
    {0x0D, 0x07, 0x00, 0x09, 0x03, 0x04, 0x06, 0x0A, 0x02, 0x08, 0x05, 0x0E, 0x0C, 0x0B, 0x0F, 0x01},
    {0x0D, 0x06, 0x04, 0x09, 0x08, 0x0F, 0x03, 0x00, 0x0B, 0x01, 0x02, 0x0C, 0x05, 0x0A, 0x0E, 0x07},
    {0x01, 0x0A, 0x0D, 0x00, 0x06, 0x09, 0x08, 0x07, 0x04, 0x0F, 0x0E, 0x03, 0x0B, 0x05, 0x02, 0x0C},
  },
  { /* SBOX4 */
    {0x07, 0x0D, 0x0E, 0x03, 0x00, 0x06, 0x09, 0x0A, 0x01, 0x02, 0x08, 0x05, 0x0B, 0x0C, 0x04, 0x0F},
    {0x0D, 0x08, 0x0B, 0x05, 0x06, 0x0F, 0x00, 0x03, 0x04, 0x07, 0x02, 0x0C, 0x01, 0x0A, 0x0E, 0x09},
    {0x0A, 0x06, 0x09, 0x00, 0x0C, 0x0B, 0x07, 0x0D, 0x0F, 0x01, 0x03, 0x0E, 0x05, 0x02, 0x08, 0x04},
    {0x03, 0x0F, 0x00, 0x06, 0x0A, 0x01, 0x0D, 0x08, 0x09, 0x04, 0x05, 0x0B, 0x0C, 0x07, 0x02, 0x0E},
  },
  { /* SBOX5 */
    {0x02, 0x0C, 0x04, 0x01, 0x07, 0x0A, 0x0B, 0x06, 0x08, 0x05, 0x03, 0x0F, 0x0D, 0x00, 0x0E, 0x09},
    {0x0E, 0x0B, 0x02, 0x0C, 0x04, 0x07, 0x0D, 0x01, 0x05, 0x00, 0x0F, 0x0A, 0x03, 0x09, 0x08, 0x06},
    {0x04, 0x02, 0x01, 0x0B, 0x0A, 0x0D, 0x07, 0x08, 0x0F, 0x09, 0x0C, 0x05, 0x06, 0x03, 0x00, 0x0E},
    {0x0B, 0x08, 0x0C, 0x07, 0x01, 0x0E, 0x02, 0x0D, 0x06, 0x0F, 0x00, 0x09, 0x0A, 0x04, 0x05, 0x03},
  },
  { /* SBOX6 */
    {0x0C, 0x01, 0x0A, 0x0F, 0x09, 0x02, 0x06, 0x08, 0x00, 0x0D, 0x03, 0x04, 0x0E, 0x07, 0x05, 0x0B},
    {0x0A, 0x0F, 0x04, 0x02, 0x07, 0x0C, 0x09, 0x05, 0x06, 0x01, 0x0D, 0x0E, 0x00, 0x0B, 0x03, 0x08},
    {0x09, 0x0E, 0x0F, 0x05, 0x02, 0x08, 0x0C, 0x03, 0x07, 0x00, 0x04, 0x0A, 0x01, 0x0D, 0x0B, 0x06},
    {0x04, 0x03, 0x02, 0x0C, 0x09, 0x05, 0x0F, 0x0A, 0x0B, 0x0E, 0x01, 0x07, 0x06, 0x00, 0x08, 0x0D},
  },
  { /* SBOX7 */
    {0x04, 0x0B, 0x02, 0x0E, 0x0F, 0x00, 0x08, 0x0D, 0x03, 0x0C, 0x09, 0x07, 0x05, 0x0A, 0x06, 0x01},
    {0x0D, 0x00, 0x0B, 0x07, 0x04, 0x09, 0x01, 0x0A, 0x0E, 0x03, 0x05, 0x0C, 0x02, 0x0F, 0x08, 0x06},
    {0x01, 0x04, 0x0B, 0x0D, 0x0C, 0x03, 0x07, 0x0E, 0x0A, 0x0F, 0x06, 0x08, 0x00, 0x05, 0x09, 0x02},
    {0x06, 0x0B, 0x0D, 0x08, 0x01, 0x04, 0x0A, 0x07, 0x09, 0x05, 0x00, 0x0F, 0x0E, 0x02, 0x03, 0x0C},
  },
  { /* SBOX8 */
    {0x0D, 0x02, 0x08, 0x04, 0x06, 0x0F, 0x0B, 0x01, 0x0A, 0x09, 0x03, 0x0E, 0x05, 0x00, 0x0C, 0x07},
    {0x01, 0x0F, 0x0D, 0x08, 0x0A, 0x03, 0x07, 0x04, 0x0C, 0x05, 0x06, 0x0B, 0x00, 0x0E, 0x09, 0x02},
    {0x07, 0x0B, 0x04, 0x01, 0x09, 0x0C, 0x0E, 0x02, 0x00, 0x06, 0x0A, 0x0D, 0x0F, 0x03, 0x05, 0x08},
    {0x02, 0x01, 0x0E, 0x07, 0x04, 0x0A, 0x08, 0x0D, 0x0F, 0x0C, 0x09, 0x00, 0x03, 0x05, 0x06, 0x0B},
  }
};

static const uint8_t shift[16] = {
  0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01,
};

static const uint8_t left_rschd[16] = {
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
};
static const uint8_t right_rschd[16] = {
  0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
};

des::~des() {
  memset(encrypto_subkeys_, 0xcc, sizeof(encrypto_subkeys_));
  memset(decrypto_subkeys_, 0xcc, sizeof(decrypto_subkeys_));
}

int32_t des::initialize(const uint8_t *key, const uint32_t ksize) {
  uint64_t tmpkey = {0};

  if (8 != ksize) { return FAILURE; }

  tmpkey |= (uint64_t)key[0] << 56;
  tmpkey |= (uint64_t)key[1] << 48;
  tmpkey |= (uint64_t)key[2] << 40;
  tmpkey |= (uint64_t)key[3] << 32;
  tmpkey |= (uint64_t)key[4] << 24;
  tmpkey |= (uint64_t)key[5] << 16;
  tmpkey |= (uint64_t)key[6] <<  8;
  tmpkey |= (uint64_t)key[7] <<  0;

  create_encrypto_subkeys(tmpkey, encrypto_subkeys_);
  create_decrypto_subkeys(tmpkey, decrypto_subkeys_);

  has_subkeys_ = true;
  
  return SUCCESS;
}

int32_t des::encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize) {
  uint32_t tmppln32bit[2] = {0};
  uint32_t out[2] = {0};
  uint8_t tmp8bit[8] = {0};

  if (8 != psize || 8 != csize) { return FAILURE; }
  if (true != has_subkeys_) { return FAILURE; };

  memcpy(tmp8bit, ptext, 8);
  BIGENDIAN_32BIT_U8_TO_U64_COPY(tmp8bit, tmppln32bit);

  initialize_permute(tmppln32bit);

  for (int8_t stg = 0; stg < 16; ++stg) {
    uint32_t roundtext = 0;

    round(encrypto_subkeys_[stg], tmppln32bit[right_rschd[stg]], roundtext);
    tmppln32bit[left_rschd[stg]] ^= roundtext;
  }

  out[0] = tmppln32bit[1];
  out[1] = tmppln32bit[0];

  finalize_permute(out);

  BIGENDIAN_32BIT_U64_TO_U8_COPY(out, ctext);

  return SUCCESS;
}

int32_t des::decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize) {
  uint32_t tmpcphr32bit[2] = {0};
  uint32_t out[2] = {0};
  uint8_t tmp8bit[8] = {0};

  if (8 != psize || 8 != csize) { return FAILURE; }
  if (true != has_subkeys_) { return FAILURE; };

  memcpy(tmp8bit, ctext, 8);
  BIGENDIAN_32BIT_U8_TO_U64_COPY(tmp8bit, tmpcphr32bit);

  initialize_permute(tmpcphr32bit);

  for (int8_t stg = 0; stg < 16; ++stg) {
    uint32_t roundtext = 0;

    round(decrypto_subkeys_[stg], tmpcphr32bit[right_rschd[stg]], roundtext);
    tmpcphr32bit[left_rschd[stg]] ^= roundtext;
  }

  out[0] = tmpcphr32bit[1];
  out[1] = tmpcphr32bit[0];

  finalize_permute(out);

  BIGENDIAN_32BIT_U64_TO_U8_COPY(out, ptext);

  return SUCCESS;
}

void des::clear() {
  has_subkeys_ = false;
  memset(encrypto_subkeys_, 0xcc, sizeof(encrypto_subkeys_));
  memset(decrypto_subkeys_, 0xcc, sizeof(decrypto_subkeys_));
}

inline void des::create_encrypto_subkeys(const uint64_t key, uint64_t *subkeys) const noexcept {
  uint32_t lkey = 0;
  uint32_t rkey = 0;

  permuted_choice1(key, lkey, rkey);

  for (int8_t stg = 0; stg < 16; ++stg) {
    if (0x01 == shift[stg]) {
      lkey = ((lkey & KEY_SHIFT_REMOVE_MSB_1BIT) << 1) | ((lkey & KEY_SHIFT_EXTRACT_MSB_1BIT) >> 27); 
      rkey = ((rkey & KEY_SHIFT_REMOVE_MSB_1BIT) << 1) | ((rkey & KEY_SHIFT_EXTRACT_MSB_1BIT) >> 27); 

    } else if (0x02 == shift[stg]) {
      lkey = ((lkey & KEY_SHIFT_REMOVE_MSB_2BIT) << 2) | ((lkey & KEY_SHIFT_EXTRACT_MSB_2BIT) >> 26); 
      rkey = ((rkey & KEY_SHIFT_REMOVE_MSB_2BIT) << 2) | ((rkey & KEY_SHIFT_EXTRACT_MSB_2BIT) >> 26); 

    }
    permuted_choice2(lkey, rkey, subkeys[stg]);
  }
}

inline void des::create_decrypto_subkeys(const uint64_t key, uint64_t *subkeys) const noexcept {
  uint32_t lkey = 0;
  uint32_t rkey = 0;

  permuted_choice1(key, lkey, rkey);

  for (int8_t stg = 0; stg < 16; ++stg) {
    if (0 != stg) {
      if (0x01 == shift[stg]) {
        lkey = ((lkey & KEY_SHIFT_REMOVE_LSB_1BIT) >> 1) | ((lkey & KEY_SHIFT_EXTRACT_LSB_1BIT) << 27); 
        rkey = ((rkey & KEY_SHIFT_REMOVE_LSB_1BIT) >> 1) | ((rkey & KEY_SHIFT_EXTRACT_LSB_1BIT) << 27); 

      } else if (0x02 == shift[stg]) {
        lkey = ((lkey & KEY_SHIFT_REMOVE_LSB_2BIT) >> 2) | ((lkey & KEY_SHIFT_EXTRACT_LSB_2BIT) << 26); 
        rkey = ((rkey & KEY_SHIFT_REMOVE_LSB_2BIT) >> 2) | ((rkey & KEY_SHIFT_EXTRACT_LSB_2BIT) << 26); 

      }
    }
    permuted_choice2(lkey, rkey, subkeys[stg]);
  }
}


inline void des::permuted_choice1(const uint64_t key, uint32_t &left, uint32_t &right) const noexcept {
  uint64_t tmp_key = 0;

  for (int8_t bits = 0; bits < sizeof(pc1); bits += 8) {
    tmp_key |= EXTRACT_AND_SET_BIT_LEFT64(key, pc1[bits]    ,  bits);
    tmp_key |= EXTRACT_AND_SET_BIT_LEFT64(key, pc1[bits + 1], (bits + 1));
    tmp_key |= EXTRACT_AND_SET_BIT_LEFT64(key, pc1[bits + 2], (bits + 2));
    tmp_key |= EXTRACT_AND_SET_BIT_LEFT64(key, pc1[bits + 3], (bits + 3));
    tmp_key |= EXTRACT_AND_SET_BIT_LEFT64(key, pc1[bits + 4], (bits + 4));
    tmp_key |= EXTRACT_AND_SET_BIT_LEFT64(key, pc1[bits + 5], (bits + 5));
    tmp_key |= EXTRACT_AND_SET_BIT_LEFT64(key, pc1[bits + 6], (bits + 6));
    tmp_key |= EXTRACT_AND_SET_BIT_LEFT64(key, pc1[bits + 7], (bits + 7));
  }

  tmp_key >>= 8;
  left = (uint32_t)((tmp_key & SUBKEY_EXTRACT_LEFT_7BYTE) >> 28);
  right = (uint32_t)(tmp_key & SUBKEY_EXTRACT_RIGHT_7BYTE);
}

inline void des::permuted_choice2(const uint32_t left, const uint32_t right, uint64_t &subkey) const noexcept {
  uint64_t skey = 0; 

  skey |= (uint64_t)left << 28;
  skey |= (uint64_t)right;
  skey <<= 8;

  for (int8_t bits = 0; bits < sizeof(pc2); bits += 8) {
    subkey |= EXTRACT_AND_SET_BIT_LEFT64(skey, pc2[bits]    ,  bits);
    subkey |= EXTRACT_AND_SET_BIT_LEFT64(skey, pc2[bits + 1], (bits + 1));
    subkey |= EXTRACT_AND_SET_BIT_LEFT64(skey, pc2[bits + 2], (bits + 2));
    subkey |= EXTRACT_AND_SET_BIT_LEFT64(skey, pc2[bits + 3], (bits + 3));
    subkey |= EXTRACT_AND_SET_BIT_LEFT64(skey, pc2[bits + 4], (bits + 4));
    subkey |= EXTRACT_AND_SET_BIT_LEFT64(skey, pc2[bits + 5], (bits + 5));
    subkey |= EXTRACT_AND_SET_BIT_LEFT64(skey, pc2[bits + 6], (bits + 6));
    subkey |= EXTRACT_AND_SET_BIT_LEFT64(skey, pc2[bits + 7], (bits + 7));
  }
  subkey >>= 16;
}

inline void des::initialize_permute(uint32_t *text) const noexcept {
  uint64_t iptext = 0;
  uint64_t tmp = (uint64_t)text[0] << 32 | (uint64_t)text[1];

  for (int8_t bits = 0; bits < sizeof(ip); bits += 8) {
    iptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, ip[bits]    ,  bits);
    iptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, ip[bits + 1], (bits + 1));
    iptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, ip[bits + 2], (bits + 2));
    iptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, ip[bits + 3], (bits + 3));
    iptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, ip[bits + 4], (bits + 4));
    iptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, ip[bits + 5], (bits + 5));
    iptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, ip[bits + 6], (bits + 6));
    iptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, ip[bits + 7], (bits + 7));
  }
  text[0] = iptext >> 32;
  text[1] = iptext & 0x0000'0000'FFFF'FFFF;
}

inline void des::finalize_permute(uint32_t *text) const noexcept {
  uint64_t fptext = 0;
  uint64_t tmp = (uint64_t)text[0] << 32 | (uint64_t)text[1];

  for (int8_t bits = 0; bits < sizeof(invip); bits += 8) {
    fptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, invip[bits]    ,  bits);
    fptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, invip[bits + 1], (bits + 1));
    fptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, invip[bits + 2], (bits + 2));
    fptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, invip[bits + 3], (bits + 3));
    fptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, invip[bits + 4], (bits + 4));
    fptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, invip[bits + 5], (bits + 5));
    fptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, invip[bits + 6], (bits + 6));
    fptext |= EXTRACT_AND_SET_BIT_LEFT64(tmp, invip[bits + 7], (bits + 7));
  }
  text[0] = fptext >> 32;
  text[1] = fptext & 0x0000'0000'FFFF'FFFF;
}

inline void des::round(const uint64_t subkey, const uint32_t rtext, uint32_t &roundtext) const noexcept {
  uint64_t targettext = 0;
  uint32_t cmb_stext = 0;
  uint8_t stext[8] = {0};

  expand(rtext, targettext);

  targettext ^= subkey;

  stext[7] = (uint8_t)( targettext & EXTRACT_6BIT_1);
  stext[6] = (uint8_t)((targettext & EXTRACT_6BIT_2) >>  6);
  stext[5] = (uint8_t)((targettext & EXTRACT_6BIT_3) >> 12);
  stext[4] = (uint8_t)((targettext & EXTRACT_6BIT_4) >> 18);
  stext[3] = (uint8_t)((targettext & EXTRACT_6BIT_5) >> 24);
  stext[2] = (uint8_t)((targettext & EXTRACT_6BIT_6) >> 30);
  stext[1] = (uint8_t)((targettext & EXTRACT_6BIT_7) >> 36);
  stext[0] = (uint8_t)((targettext & EXTRACT_6BIT_8) >> 42);

  for (int8_t sidx = 0; sidx < 8; ++sidx) {
    uint8_t left = 0;
    uint8_t right = 0;

    left = ((stext[sidx] & EXTRACT_LEFT_1BIT) >> 4) | (stext[sidx] & EXTRACT_RIGHT_1BIT);
    right = (stext[sidx] & EXTRACT_MIDDLE_4BIT) >> 1;

    stext[sidx] = sbox[sidx][left][right];
  }

  cmb_stext |= ( (uint32_t)stext[7]);
  cmb_stext |= (((uint32_t)stext[6]) <<  4);
  cmb_stext |= (((uint32_t)stext[5]) <<  8);
  cmb_stext |= (((uint32_t)stext[4]) << 12);
  cmb_stext |= (((uint32_t)stext[3]) << 16);
  cmb_stext |= (((uint32_t)stext[2]) << 20);
  cmb_stext |= (((uint32_t)stext[1]) << 24);
  cmb_stext |= (((uint32_t)stext[0]) << 28);

  permute(cmb_stext, roundtext);
}

inline void des::expand(const uint32_t rtext, uint64_t &etext) const noexcept {
  uint64_t tmp_rtext = (uint64_t)rtext << 32;

  for (int8_t bits = 0; bits < sizeof(e); bits += 8) {
    etext |= EXTRACT_AND_SET_BIT_LEFT64(tmp_rtext, e[bits]    ,  bits);
    etext |= EXTRACT_AND_SET_BIT_LEFT64(tmp_rtext, e[bits + 1], (bits + 1));
    etext |= EXTRACT_AND_SET_BIT_LEFT64(tmp_rtext, e[bits + 2], (bits + 2));
    etext |= EXTRACT_AND_SET_BIT_LEFT64(tmp_rtext, e[bits + 3], (bits + 3));
    etext |= EXTRACT_AND_SET_BIT_LEFT64(tmp_rtext, e[bits + 4], (bits + 4));
    etext |= EXTRACT_AND_SET_BIT_LEFT64(tmp_rtext, e[bits + 5], (bits + 5));
    etext |= EXTRACT_AND_SET_BIT_LEFT64(tmp_rtext, e[bits + 6], (bits + 6));
    etext |= EXTRACT_AND_SET_BIT_LEFT64(tmp_rtext, e[bits + 7], (bits + 7));
  }
  etext >>= 16;
}

inline void des::permute(const uint32_t rtext, uint32_t &ptext) const noexcept {

  for (int8_t bits = 0; bits < sizeof(p); bits += 8) {
    ptext |= EXTRACT_AND_SET_BIT_LEFT32(rtext, p[bits]    ,  bits);
    ptext |= EXTRACT_AND_SET_BIT_LEFT32(rtext, p[bits + 1], (bits + 1));
    ptext |= EXTRACT_AND_SET_BIT_LEFT32(rtext, p[bits + 2], (bits + 2));
    ptext |= EXTRACT_AND_SET_BIT_LEFT32(rtext, p[bits + 3], (bits + 3));
    ptext |= EXTRACT_AND_SET_BIT_LEFT32(rtext, p[bits + 4], (bits + 4));
    ptext |= EXTRACT_AND_SET_BIT_LEFT32(rtext, p[bits + 5], (bits + 5));
    ptext |= EXTRACT_AND_SET_BIT_LEFT32(rtext, p[bits + 6], (bits + 6));
    ptext |= EXTRACT_AND_SET_BIT_LEFT32(rtext, p[bits + 7], (bits + 7));
  }
}

}

/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <cstring>
#include <stdint.h>

#include "defs.h"

#ifndef BYTE_UTILL_H
#define BYTE_UTILL_H

#ifdef __LITTLE_ENDIAN__

#elif __BIG_ENDIAN__

#endif

/* Convert types while preserving big endianness as follows.                                */
/* src type      dst type  src data                 [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]  */
/* uint16_t  to  uint8_t : 0x1122              ->   0x11 0x22                               */
/* uint32_t  to  uint8_t : 0x11223344          ->   0x11 0x22 0x33 0x44                     */
/* uint64_t  to  uint8_t : 0x1122334455667788  ->   0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 */
/* ... After that, the same as above.                                                           */
#define BIGENDIAN_U16_TO_U8(u16val, u8array)   u8array[0] = (uint8_t)((u64val & 0xFF00) >> 8); \
                                               u8array[1] = (uint8_t)( u64val & 0x00FF);

#define BIGENDIAN_U32_TO_U8(u32val, u8array)   u8array[0] = (uint8_t)((u64val & 0xFF00'0000) >> 24); \
                                               u8array[1] = (uint8_t)((u64val & 0x00FF'0000) >> 16); \
                                               u8array[2] = (uint8_t)((u64val & 0x0000'FF00) >>  8); \
                                               u8array[3] = (uint8_t)( u64val & 0x0000'00FF);


#define BIGENDIAN_U64_TO_U8(u64val, u8array)   u8array[0] = (uint8_t)((u64val & 0xFF00'0000'0000'0000) >> 56); \
                                               u8array[1] = (uint8_t)((u64val & 0x00FF'0000'0000'0000) >> 48); \
                                               u8array[2] = (uint8_t)((u64val & 0x0000'FF00'0000'0000) >> 40); \
                                               u8array[3] = (uint8_t)((u64val & 0x0000'00FF'0000'0000) >> 32); \
                                               u8array[4] = (uint8_t)((u64val & 0x0000'0000'FF00'0000) >> 24); \
                                               u8array[5] = (uint8_t)((u64val & 0x0000'0000'00FF'0000) >> 16); \
                                               u8array[6] = (uint8_t)((u64val & 0x0000'0000'0000'FF00) >>  8); \
                                               u8array[7] = (uint8_t)( u64val & 0x0000'0000'0000'00FF);

/* Convert types while preserving big endianness as follows.                                */
/* src type      dst type   [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]       src data           */
/* uint8_t   to  uint16_t : 0x11 0x22                                ->  0x1122             */
/* uint8_t   to  uint32_t : 0x11 0x22 0x33 0x44                      ->  0x11223344         */
/* uint8_t   to  uint64_t : 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88  ->  0x1122334455667788 */
/* ... After that, the same as above.                                                           */
#define BIGENDIAN_U8_TO_U16(u8array, u16val)   u16val = ((uint16_t)u8array[0] <<  8)  | \
                                                        ((uint16_t)u8array[1])

#define BIGENDIAN_U8_TO_U32(u8array, u32val)   u32val = ((uint32_t)u8array[0] << 24)  | \
                                                        ((uint32_t)u8array[1] << 16)  | \
                                                        ((uint32_t)u8array[2] <<  8)  | \
                                                        ((uint32_t)u8array[3])

#define BIGENDIAN_U8_TO_U64(u8array, u64val)   u64val = ((uint64_t)u8array[0] << 56)  | \
                                                        ((uint64_t)u8array[1] << 48)  | \
                                                        ((uint64_t)u8array[2] << 40)  | \
                                                        ((uint64_t)u8array[3] << 32)  | \
                                                        ((uint64_t)u8array[4] << 24)  | \
                                                        ((uint64_t)u8array[5] << 16)  | \
                                                        ((uint64_t)u8array[6] <<  8)  | \
                                                        ((uint64_t)u8array[7])

typedef union union_unsigned_int_32bit_array {
  uint32_t u32;
  uint8_t  u8[4];
} union_array_u32_t;

typedef union union_unsigned_int_64bit_array {
  uint64_t u64;
  uint32_t u32[2];
  uint8_t  u8[8];
} union_array_u64_t;

typedef union union_unsigned_int_128bit_array {
  uint64_t u64[2];
  uint32_t u32[4];
  uint8_t  u8[16];
} union_array_u128_t;

typedef union union_unsigned_int_256bit_array {
  uint64_t u64[4];
  uint32_t u32[8];
  uint8_t  u8[32];
} union_array_u256_t;

#endif

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

#ifndef BYTE_UTILL_H
#define BYTE_UTILL_H

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
#if (__BYTE_ORDER == __LITTLE_ENDIAN) || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define __LITTLE_ENDIAN__
#elif (__BYTE_ORDER == __BIG_ENDIAN) || (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define __BIG_ENDIAN__
#endif
#endif

#ifdef __LITTLE_ENDIAN__

/* Convert types while preserving big endianness as follows.                                */
/* src type      dst type  src data                 [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]  */
/* uint64_t  to  uint8_t : 0x1122334455667788  ->   0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 */
/* uint32_t  to  uint8_t : 0x11223344          ->   0x11 0x22 0x33 0x44                     */
/* uint32_t  to  uint8_t : 0x1122              ->   0x11 0x22                               */
#define BIGENDIAN_U64_TO_U8(u64val, u8array)   u8array[0] = (uint8_t)((u64val & 0xFF00'0000'0000'0000) >> 56); \
                                               u8array[1] = (uint8_t)((u64val & 0x00FF'0000'0000'0000) >> 48); \
                                               u8array[2] = (uint8_t)((u64val & 0x0000'FF00'0000'0000) >> 40); \
                                               u8array[3] = (uint8_t)((u64val & 0x0000'00FF'0000'0000) >> 32); \
                                               u8array[4] = (uint8_t)((u64val & 0x0000'0000'FF00'0000) >> 24); \
                                               u8array[5] = (uint8_t)((u64val & 0x0000'0000'00FF'0000) >> 16); \
                                               u8array[6] = (uint8_t)((u64val & 0x0000'0000'0000'FF00) >>  8); \
                                               u8array[7] = (uint8_t)( u64val & 0x0000'0000'0000'00FF);

#define BIGENDIAN_U32_TO_U8(u32val, u8array)   u8array[0] = (uint8_t)((u64val & 0xFF00'0000) >> 24); \
                                               u8array[1] = (uint8_t)((u64val & 0x00FF'0000) >> 16); \
                                               u8array[2] = (uint8_t)((u64val & 0x0000'FF00) >>  8); \
                                               u8array[3] = (uint8_t)( u64val & 0x0000'00FF);

#define BIGENDIAN_U16_TO_U8(u16val, u8array)   u8array[0] = (uint8_t)((u64val & 0xFF00) >> 8); \
                                               u8array[1] = (uint8_t)( u64val & 0x00FF);

/* Convert types while preserving big endianness as follows.                                */
/* src type      dst type   [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]       src data           */
/* uint8_t   to  uint64_t : 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88  ->  0x1122334455667788 */
/* uint8_t   to  uint32_t : 0x11 0x22 0x33 0x44                      ->  0x11223344         */
/* uint8_t   to  uint16_t : 0x11 0x22                                ->  0x1122             */
#define BIGENDIAN_U8_TO_U64(u8array, u64val)   u64val = ((uint64_t)u8array[0] << 56)  | \
                                                        ((uint64_t)u8array[1] << 48)  | \
                                                        ((uint64_t)u8array[2] << 40)  | \
                                                        ((uint64_t)u8array[3] << 32)  | \
                                                        ((uint64_t)u8array[4] << 24)  | \
                                                        ((uint64_t)u8array[5] << 16)  | \
                                                        ((uint64_t)u8array[6] <<  8)  | \
                                                        ((uint64_t)u8array[7])

#define BIGENDIAN_U8_TO_U32(u8array, u32val)   u32val = ((uint32_t)u8array[0] << 24)  | \
                                                        ((uint32_t)u8array[1] << 16)  | \
                                                        ((uint32_t)u8array[2] <<  8)  | \
                                                        ((uint32_t)u8array[3])


#define BIGENDIAN_U8_TO_U16(u8array, u16val)   u16val = ((uint16_t)u8array[0] <<  8)  | \
                                                        ((uint16_t)u8array[1])

#else
/* Convert types while preserving big endianness as follows.                                */
/* src type      dst type  src data                 [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]  */
/* uint64_t  to  uint8_t : 0x1122334455667788  ->   0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 */
/* uint32_t  to  uint8_t : 0x11223344          ->   0x11 0x22 0x33 0x44                     */
/* uint32_t  to  uint8_t : 0x1122              ->   0x11 0x22                               */
#define BIGENDIAN_U64_TO_U8(u64val, u8ptr)      u8ptr = (uint8_t *)&u64val;
#define BIGENDIAN_U32_TO_U8(u32val, u8ptr)      u8ptr = (uint8_t *)&u32val;
#define BIGENDIAN_U16_TO_U8(u16val, u8ptr)      u8ptr = (uint8_t *)&u16val;

/* Convert types while preserving big endianness as follows.                                */
/* src type      dst type   [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]       src data           */
/* uint8_t   to  uint64_t : 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88  ->  0x1122334455667788 */
/* uint8_t   to  uint32_t : 0x11 0x22 0x33 0x44                      ->  0x11223344         */
/* uint8_t   to  uint16_t : 0x11 0x22                                ->  0x1122             */
#define BIGENDIAN_U8_TO_U64(u8array, u64ptr)    u64ptr = (uint64_t *)&u8array;
#define BIGENDIAN_U8_TO_U32(u8array, u32ptr)    u32ptr = (uint32_t *)&u8array;
#define BIGENDIAN_U8_TO_U16(u8array, u16ptr)    u16ptr = (uint16_t *)&u8array;
#endif

#endif

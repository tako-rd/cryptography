/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef __DEFS_H__
#define __DEFS_H__

//#define ENABLE_CRYPTOGRAPHY_LITTLE_ENDIAN
//#define ENABLE_CRYPTOGRAPHY_BIG_ENDIAN

#include <cstring>
#include <type_traits>

#ifdef CRYPTOGRAPHY_DEBUG
//#define ENABLE_FUNCTIONS_FOR_GTEST

#include <iostream>
#include <bitset>
#endif

/* Don't want to use memory allocation in this library,                 */
/* so don't use the following STL unless the caller passes an argument. */
#include <string>
#include <vector>

#define CRYPTOGRAPHY_RIGHT_32BIT_MASK        0xFFFF'FFFF'0000'0000
#define CRYPTOGRAPHY_LEFT_32BIT_MASK         0x0000'0000'FFFF'FFFF

#ifdef _MSC_VER
#include <intrin.h>

#define ALIGNAS(x)                            __declspec(align(x))
#define GET_CPUID(info, eax)                  __cpuid(info, eax)
#define POPCOUNT32(x)                         __popcnt(x)

#ifdef _WIN64
#define POPCOUNT64(x)                         __popcnt64(x)
#elif _WIN32
#define POPCOUNT64(x)                         (__popcnt((uint32_t)((x & CRYPTOGRAPHY_RIGHT_32BIT_MASK) >> 32)) + \
                                               __popcnt((uint32_t)(x & CRYPTOGRAPHY_LEFT_32BIT_MASK)))
#endif

#elif __GNUC__
#include <cpuid.h>
#include <x86intrin.h>

#define ALIGNAS(x)                            __attribute__((aligned(n)))
#define GET_CPUID(info, eax)                  __cpuid(eax, info[0], info[1], info[2], info[3])
#define POPCOUNT32(x)                         __builtin_popcount(x)

#ifdef __x86_64__ 
#define POPCOUNT64(x)                         __builtin_popcountll(x)
#else
#define POPCOUNT64(x)                         (__builtin_popcount((uint32_t)((x & CRYPTOGRAPHY_RIGHT_32BIT_MASK) >> 32)) + \
                                               __builtin_popcount((uint32_t)(x & CRYPTOGRAPHY_LEFT_32BIT_MASK)))
#endif

#endif

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__) 

#if (__BYTE_ORDER == __LITTLE_ENDIAN) || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define __LITTLE_ENDIAN__

#elif (__BYTE_ORDER == __BIG_ENDIAN) || (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define __BIG_ENDIAN__

#endif

#endif

#ifdef CRYPTOGRAPHY_DEBUG
#define DEBUG_DISPLAY_BIT_8(tag, target)      (std::cout << "[" << __func__ << "]" << tag << " : " << std::bitset<8>(target) << std::endl)
#define DEBUG_DISPLAY_BIT_16(tag, target)     (std::cout << "[" << __func__ << "]" << tag << " : " << std::bitset<16>(target) << std::endl)
#define DEBUG_DISPLAY_BIT_32(tag, target)     (std::cout << "[" << __func__ << "]" << tag << " : " << std::bitset<32>(target) << std::endl)
#define DEBUG_DISPLAY_BIT_64(tag, target)     (std::cout << "[" << __func__ << "]" << tag << " : " << std::bitset<64>(target) << std::endl)
#define DEBUG_DISPLAY_BIT_COUNT(tag, target)  (std::cout << "[" << __func__ << "]" << tag << " bit count : " << POPCOUNT64(target) << std::endl)

#define DEBUG_START                           printf("[%s] Start.\n", __func__)
#define DEBUG_END                             printf("[%s] end.\n", __func__)
#define DEBUG_CHECK_POINT(x)                  printf("[%s] check point %d.\n", __func__, x)

#else
#define DEBUG_START
#define DEBUG_END

#endif

namespace cryptography {

#define EXTRACT_CIPHER_AND_HASH_TYPE  0xFF00
#define EXTRACT_BLOCK_CIPHER_MODE     0x00FF

typedef enum cipher_and_hash_type {
  DEFAULT      = 0x0000,
  DES          = 0x0100,
  AES128       = 0x0200,
  AES192       = 0x0300,
  AES256       = 0x0400,
  RSA          = 0x0500,
  MD4          = 0x0600,
  MD5          = 0x0700,
  SHA          = 0x0800,
  EXTRACT_TYPE = 0xFF00
} type_t;

typedef enum block_cipher_mode {
  ECB          = 0x0001, 
  CBC          = 0x0002, 
  CFB          = 0x0003, 
  OFB          = 0x0004, 
  CTR          = 0x0005, 
  EXTRACT_MODE = 0x00FF
} mode_t;

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

}

#endif

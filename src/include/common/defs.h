/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef DEFS_H
#define DEFS_H

//#define CRYPTOGRAPHY_ENABLE_LITTLE_ENDIAN
//#define CRYPTOGRAPHY_ENABLE_BIG_ENDIAN
//#define CRYPTOGRAPHY_PERMIT_USE_HEAP_MEMORY

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

#include <stdlib.h>

#define CRYPTOGRAPHY_RIGHT_32BIT_MASK        0xFFFF'FFFF'0000'0000
#define CRYPTOGRAPHY_LEFT_32BIT_MASK         

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
# if (__BYTE_ORDER == __LITTLE_ENDIAN) || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#   define __LITTLE_ENDIAN__
# elif (__BYTE_ORDER == __BIG_ENDIAN) || (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#   define __BIG_ENDIAN__
# endif
#endif

#ifdef _MSC_VER
# include <intrin.h>

# define ALIGNAS(x)                           __declspec(align(x))
# define GET_CPUID(info, eax)                 __cpuid(info, eax)
#elif __GNUC__
# include <cpuid.h>
# include <x86intrin.h>

# define ALIGNAS(x)                           __attribute__((aligned(n)))
# define GET_CPUID(info, eax)                 __cpuid(eax, info[0], info[1], info[2], info[3])
#endif

#ifdef CRYPTOGRAPHY_DEBUG
# define DEBUG_DISPLAY_BIT_8(tag, target)      (std::cout << "[" << __func__ << "]" << tag << " : " << std::bitset<8>(target) << std::endl)
# define DEBUG_DISPLAY_BIT_16(tag, target)     (std::cout << "[" << __func__ << "]" << tag << " : " << std::bitset<16>(target) << std::endl)
# define DEBUG_DISPLAY_BIT_32(tag, target)     (std::cout << "[" << __func__ << "]" << tag << " : " << std::bitset<32>(target) << std::endl)
# define DEBUG_DISPLAY_BIT_64(tag, target)     (std::cout << "[" << __func__ << "]" << tag << " : " << std::bitset<64>(target) << std::endl)
# define DEBUG_DISPLAY_BIT_COUNT(tag, target)  (std::cout << "[" << __func__ << "]" << tag << " bit count : " << POPCOUNT64(target) << std::endl)

# define DEBUG_START                           printf("[%s] Start.\n", __func__)
# define DEBUG_END                             printf("[%s] end.\n", __func__)
# define DEBUG_CHECK_POINT(x)                  printf("[%s] check point %d.\n", __func__, x)
#else
# define DEBUG_DISPLAY_BIT_8(tag, target)    
# define DEBUG_DISPLAY_BIT_16(tag, target)   
# define DEBUG_DISPLAY_BIT_32(tag, target)   
# define DEBUG_DISPLAY_BIT_64(tag, target)   
# define DEBUG_DISPLAY_BIT_COUNT(tag, target)

# define DEBUG_START
# define DEBUG_END
#endif

namespace cryptography {

typedef enum cipher_and_hash_type {
  DEFAULT      = 0x0000,
  SIMPLE_DES   = 0x0100,
  AES128       = 0x0200,
  AES192       = 0x0300,
  AES256       = 0x0400,
  CAMELLIA128  = 0x0500,
  CAMELLIA192  = 0x0600,
  CAMELLIA256  = 0x0700,
  SEED         = 0x0800,
  RSA          = 0x0900,
  MD4          = 0x1000,
  MD5          = 0x1100,
  SHA          = 0x1200,
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

}

#endif

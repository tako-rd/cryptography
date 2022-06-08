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

#include <stdlib.h>
#include <stdint.h>

#include <cstring>
#include <type_traits>

/* List of macros to be set in Makefile. */
//#define ENABLE_LITTLE_ENDIAN
//#define ENABLE_BIG_ENDIAN
//#define ENABLE_SSE
//#define ENABLE_SSE2
//#define ENABLE_SSE3
//#define ENABLE_SSE4_1
//#define ENABLE_SSE4_2
//#define ENABLE_AESNI

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
# if (ENABLE_LITTLE_ENDIAN)
#   define __LITTLE_ENDIAN__
# elif (ENABLE_BIG_ENDIAN)
#   define __BIG_ENDIAN__
# endif
#endif

namespace cryptography {

/*
 * The return code is defined as 32 bits.
 * The upper 16 bits are used to identify the module and the lower 16 bits are used to cause the error.
 */
typedef enum class module_code {
  SUCCESS    = 0x00000000,
  SECRET_KEY = 0x00010000,
  MODE       = 0x00020000,
  PUBLIC_KEY = 0x00030000,
  COMMON     = 0x00040000,
} module_code_t;

typedef enum class return_code {
  SUCCESS,
  INVALID_STRING_SIZE,
  UNSET_KEY,
  INVALID_KEY_SIZE,
  UNSET_IV,
  INVALID_IV_SIZE,
  INVALID_PADDING,
  RETURN_CODE_MAX = 0x0000FFFF,
} retcode_t;

/* The return code common to all modules. */
constexpr int32_t SUCCESS           = ((int32_t)module_code_t::SUCCESS | (int32_t)retcode_t::SUCCESS);

/* The return code of secret_key modules. */
constexpr int32_t UNSET_KEY_ERROR   = ((int32_t)module_code_t::SECRET_KEY | (int32_t)retcode_t::UNSET_KEY);
constexpr int32_t KEY_SIZE_ERROR    = ((int32_t)module_code_t::SECRET_KEY | (int32_t)retcode_t::INVALID_KEY_SIZE);

/* The return code of mode modules. */
constexpr int32_t UNSET_IV_ERROR    = ((int32_t)module_code_t::MODE | (int32_t)retcode_t::UNSET_IV);
constexpr int32_t STRING_SIZE_ERROR = ((int32_t)module_code_t::MODE | (int32_t)retcode_t::INVALID_STRING_SIZE);
constexpr int32_t IV_SIZE_ERROR     = ((int32_t)module_code_t::MODE | (int32_t)retcode_t::INVALID_IV_SIZE);
constexpr int32_t PADDING_ERROR     = ((int32_t)module_code_t::MODE | (int32_t)retcode_t::INVALID_PADDING);

}
#endif

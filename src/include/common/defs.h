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

#include <cstring>
#include <type_traits>

#include <stdlib.h>

/* List of macros to be set in Makefile. */
//#define ENABLE_SSE
//#define ENABLE_SSE2
//#define ENABLE_SSE3
//#define ENABLE_SSE4_1
//#define ENABLE_SSE4_2
//#define ENABLE_AESNI

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
# if (__BYTE_ORDER == __LITTLE_ENDIAN) || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#   define __LITTLE_ENDIAN__
# elif (__BYTE_ORDER == __BIG_ENDIAN) || (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#   define __BIG_ENDIAN__
# endif
#endif

namespace cryptography {

}

#endif

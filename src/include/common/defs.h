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

/* Don't want to use memory allocation in this library,                 */
/* so don't use the following STL unless the caller passes an argument. */
#include <string>
#include <vector>

#include <stdlib.h>

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

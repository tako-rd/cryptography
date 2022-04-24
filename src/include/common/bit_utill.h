/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <stdlib.h>

#include "common/defs.h"

#ifndef BIT_UTILL_H
#define BIT_UTILL_H

#ifdef _MSC_VER

# define ROTATE_LEFT32(val, shift)          _rotl((val), (shift))
# define ROTATE_RIGHT32(val, shift)         _rotr((val), (shift))

# define ROTATE_LEFT64(val, shift)          _rotl64((val), (shift))
# define ROTATE_RIGHT64(val, shift)         _rotr64((val), (shift))

# define POPCOUNT32(val)                    __popcnt((val))

# ifdef _WIN64
#   define POPCOUNT64(val)                  __popcnt64((val))
# elif _WIN32
#   define POPCOUNT64(val)                  (uint64_t)(__popcnt((uint32_t)((val) >> 32                  )) + \
                                                       __popcnt((uint32_t)((val) & 0x0000'0000'FFFF'FFFF)))
#endif

#elif __GNUC__

# define ROTATE_LEFT32(val, shift)          ((val >> (32 - shift)) | (val << shift)) 
# define ROTATE_RIGHT32(val, shift)         ((val >> shift) | (val << (32 - shift))) 
# define ROTATE_LEFT64(val, shift)          ((val >> (64 - shift)) | (val << shift)) 
# define ROTATE_RIGHT64(val, shift)         ((val >> shift) | (val << (64 - shift))) 

# define POPCOUNT32(val)                    __builtin_popcount(val)

# ifdef __x86_64__ 
#   define POPCOUNT64(val)                  __builtin_popcountll(val)
# else
#   define POPCOUNT64(val)                  (uint64_t)(__builtin_popcount((uint32_t)((val) >> 32                  )) + \
                                                       __builtin_popcount((uint32_t)((val) & 0x0000'0000'FFFF'FFFF)))
# endif

#endif

#endif
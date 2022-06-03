/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include <stdlib.h>
#include <stdint.h>

#include "common/defs.h"

#ifndef BIT_UTILL_H
#define BIT_UTILL_H

/* Prototype declaration of class. */
class bit;

#if defined(_MSC_VER)
# define ROTATE_LEFT32(val, shift)          _rotl((val), (shift))
# define ROTATE_RIGHT32(val, shift)         _rotr((val), (shift))

# define ROTATE_LEFT64(val, shift)          _rotl64((val), (shift))
# define ROTATE_RIGHT64(val, shift)         _rotr64((val), (shift))

# if (_M_X64 == 100 || _M_IX86 == 600)
#   define POPCOUNT32(val)                    __popcnt((val))

#   ifdef _WIN64
#     define POPCOUNT64(val)                  __popcnt64((val))
#   elif _WIN32
#     define POPCOUNT64(val)                  (uint64_t)(__popcnt((uint32_t)((val) >> 32                  )) + \
                                                         __popcnt((uint32_t)((val) & 0x0000'0000'FFFF'FFFF)))
#   endif
# elif (_M_ARM == 7)
#   define ROTATE_LEFT32(val, shift)          _rotl((val), (shift))
#   define ROTATE_RIGHT32(val, shift)         _rotr((val), (shift))

#   define ROTATE_LEFT64(val, shift)          _rotl64((val), (shift))
#   define ROTATE_RIGHT64(val, shift)         _rotr64((val), (shift))

#   define POPCOUNT32(val)                    bit::popcount32((val))
#   define POPCOUNT64(val)                    bit::popcount64((val))
#endif

#elif defined(__GNUC__)

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

namespace cryptography {

class bit {
 public:
  bit() noexcept {};

  bit(bit &other) = delete;

  bit(bit &&other) = delete;

  bit(const bit &other) = delete;

  bit(const bit &&other) = delete;

  ~bit() {};

  static uint32_t popcount32(uint64_t in) noexcept;

  static uint64_t popcount64(uint64_t in) noexcept;
};

}

#endif
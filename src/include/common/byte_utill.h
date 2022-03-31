/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <stdint.h>
#include <stdlib.h>

#include "defs.h"

#ifndef BYTE_UTILL_H
#define BYTE_UTILL_H

#ifdef __LITTLE_ENDIAN__
# ifdef _MSC_VER

#   define BIGENDIAN_U32_TO_U8(value, outptr)       value   = _byteswap_ulong(value); \
                                                    outptr  = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U32(value, outptr)       outptr  = (uint32_t *)&value;  \
                                                    *outptr = _byteswap_ulong(*outptr);

#   define BIGENDIAN_U64_TO_U8(value, outptr)       value   = _byteswap_uint64(value);  \
                                                    outptr  = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U64(value, outptr)       outptr  = (uint64_t *)&value;  \
                                                    *outptr = _byteswap_uint64(*outptr);

#   define BIGENDIAN_U128_TO_U8(value, outptr)      *(value)     = _byteswap_uint64(*value);  \
                                                    *(value + 1) = _byteswap_uint64(*(value + 1));  \
                                                    outptr       = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U128(value, outptr)      outptr        = (uint64_t *)value; \
                                                    *(outptr)     = _byteswap_uint64(*outptr);  \
                                                    *(outptr + 1) = _byteswap_uint64(*(outptr + 1));

#   define BIGENDIAN_U192_TO_U8(value, outptr)      *(value)     = _byteswap_uint64(*value);  \
                                                    *(value + 1) = _byteswap_uint64(*(value + 1));  \
                                                    *(value + 2) = _byteswap_uint64(*(value + 2));  \
                                                    outptr       = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U192(value, outptr)      outptr        = (uint64_t *)value; \
                                                    *(outptr)     = _byteswap_uint64(*outptr);  \
                                                    *(outptr + 1) = _byteswap_uint64(*(outptr + 1));  \
                                                    *(outptr + 2) = _byteswap_uint64(*(outptr + 2));

#   define BIGENDIAN_U256_TO_U8(value, outptr)      *(value)     = _byteswap_uint64(*value);  \
                                                    *(value + 1) = _byteswap_uint64(*(value + 1));  \
                                                    *(value + 2) = _byteswap_uint64(*(value + 2));  \
                                                    *(value + 3) = _byteswap_uint64(*(value + 3));  \
                                                    outptr       = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U256(value, outptr)      outptr        = (uint64_t *)value; \
                                                    *(outptr)     = _byteswap_uint64(*outptr);  \
                                                    *(outptr + 1) = _byteswap_uint64(*(outptr + 1));  \
                                                    *(outptr + 2) = _byteswap_uint64(*(outptr + 2));  \
                                                    *(outptr + 3) = _byteswap_uint64(*(outptr + 3));

#   ifdef _WIN64 
#   elif  _WIN32
#   endif

# elif  __GNUC__

#   define BIGENDIAN_U32_TO_U8(value, outptr)       value   = __builtin_bswap32(value); \
                                                    outptr  = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U32(value, outptr)       outptr  = (uint32_t *)&value;  \
                                                    *outptr = __builtin_bswap32(*outptr);

#   define BIGENDIAN_U64_TO_U8(value, outptr)       value   = __builtin_bswap64(value);  \
                                                    outptr  = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U64(value, outptr)       outptr  = (uint64_t *)&value;  \
                                                    *outptr = __builtin_bswap64(*outptr);

#   define BIGENDIAN_U128_TO_U8(value, outptr)      *(value)     = __builtin_bswap64(*value);  \
                                                    *(value + 1) = __builtin_bswap64(*(value + 1));  \
                                                    outptr       = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U128(value, outptr)      outptr        = (uint64_t *)value; \
                                                    *(outptr)     = __builtin_bswap64(*outptr);  \
                                                    *(outptr + 1) = __builtin_bswap64(*(outptr + 1));

#   define BIGENDIAN_U192_TO_U8(value, outptr)      *(value)     = __builtin_bswap64(*value);  \
                                                    *(value + 1) = __builtin_bswap64(*(value + 1));  \
                                                    *(value + 2) = __builtin_bswap64(*(value + 2));  \
                                                    outptr       = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U192(value, outptr)      outptr        = (uint64_t *)value; \
                                                    *(outptr)     = __builtin_bswap64(*outptr);  \
                                                    *(outptr + 1) = __builtin_bswap64(*(outptr + 1));  \
                                                    *(outptr + 2) = __builtin_bswap64(*(outptr + 2));

#   define BIGENDIAN_U256_TO_U8(value, outptr)      *(value)     = __builtin_bswap64(*value);  \
                                                    *(value + 1) = __builtin_bswap64(*(value + 1));  \
                                                    *(value + 2) = __builtin_bswap64(*(value + 2));  \
                                                    *(value + 3) = __builtin_bswap64(*(value + 3));  \
                                                    outptr       = (uint8_t *)&value;

#   define BIGENDIAN_U8_TO_U256(value, outptr)      outptr        = (uint64_t *)value; \
                                                    *(outptr)     = __builtin_bswap64(*outptr);  \
                                                    *(outptr + 1) = __builtin_bswap64(*(outptr + 1));  \
                                                    *(outptr + 2) = __builtin_bswap64(*(outptr + 2));  \
                                                    *(outptr + 3) = __builtin_bswap64(*(outptr + 3));

#   ifdef __x86_64__ 
#   else 
#   endif
# endif

#elif __BIG_ENDIAN__
# ifdef _MSC_VER

#   define BIGENDIAN_U32_TO_U8(value, outptr)       outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U32(value, outptr)       outptr = (uint32_t *)&value;
#   define BIGENDIAN_U64_TO_U8(value, outptr)       outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U64(value, outptr)       outptr = (uint64_t *)&value;
#   define BIGENDIAN_U128_TO_U8(value, outptr)      outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U128(value, outptr)      outptr = (uint64_t *)value;
#   define BIGENDIAN_U192_TO_U8(value, outptr)      outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U192(value, outptr)      outptr = (uint64_t *)value;
#   define BIGENDIAN_U256_TO_U8(value, outptr)      outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U256(value, outptr)      outptr = (uint64_t *)value;

#   ifdef _WIN64 
#   elif  _WIN32
#   endif
                                          
# elif  __GNUC__

#   define BIGENDIAN_U32_TO_U8(value, outptr)       outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U32(value, outptr)       outptr = (uint32_t *)&value;
#   define BIGENDIAN_U64_TO_U8(value, outptr)       outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U64(value, outptr)       outptr = (uint64_t *)&value;
#   define BIGENDIAN_U128_TO_U8(value, outptr)      outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U128(value, outptr)      outptr = (uint64_t *)value;
#   define BIGENDIAN_U192_TO_U8(value, outptr)      outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U192(value, outptr)      outptr = (uint64_t *)value;
#   define BIGENDIAN_U256_TO_U8(value, outptr)      outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U256(value, outptr)      outptr = (uint64_t *)value;

#   ifdef __x86_64__ 
#   else 
#   endif

# endif

#endif

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

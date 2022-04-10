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
/***********************************************************************/
/* Change the data type while maintaining little endianness in 32-bit. */
/***********************************************************************/
#   define LITTLEENDIAN_32BIT_U32_TO_U8(value, outptr)        outptr = (uint8_t *)&value;
#   define LITTLEENDIAN_32BIT_U8_TO_U32(value, outptr)        outptr = (uint32_t *)&value;
#   define LITTLEENDIAN_32BIT_U64_TO_U8(value, outptr)        outptr = (uint8_t *)&value;
#   define LITTLEENDIAN_32BIT_U8_TO_U64(value, outptr)        outptr = (uint32_t *)&value;
#   define LITTLEENDIAN_32BIT_U128_TO_U8(value, outptr)       outptr = (uint8_t *)&value;
#   define LITTLEENDIAN_32BIT_U8_TO_U128(value, outptr)       outptr = (uint32_t *)value;
#   define LITTLEENDIAN_32BIT_U192_TO_U8(value, outptr)       outptr = (uint8_t *)&value;
#   define LITTLEENDIAN_32BIT_U8_TO_U192(value, outptr)       outptr = (uint32_t *)value;
#   define LITTLEENDIAN_32BIT_U256_TO_U8(value, outptr)       outptr = (uint8_t *)&value;
#   define LITTLEENDIAN_32BIT_U8_TO_U256(value, outptr)       outptr = (uint32_t *)value;

/***********************************************************************/
/* Change the data type while maintaining little endianness in 64-bit. */
/***********************************************************************/

#   define BIGENDIAN_64BIT_U32_TO_U8(value, outptr)           outptr = (uint8_t *)&value;
#   define BIGENDIAN_64BIT_U8_TO_U32(value, outptr)           outptr = (uint32_t *)&value;
#   define BIGENDIAN_64BIT_U64_TO_U8(value, outptr)           outptr = (uint8_t *)&value;
#   define BIGENDIAN_64BIT_U8_TO_U64(value, outptr)           outptr = (uint64_t *)&value;
#   define BIGENDIAN_64BIT_U128_TO_U8(value, outptr)          outptr = (uint8_t *)&value;
#   define BIGENDIAN_64BIT_U8_TO_U128(value, outptr)          outptr = (uint64_t *)value;
#   define BIGENDIAN_64BIT_U192_TO_U8(value, outptr)          outptr = (uint8_t *)&value;
#   define BIGENDIAN_64BIT_U8_TO_U192(value, outptr)          outptr = (uint64_t *)value;
#   define BIGENDIAN_64BIT_U256_TO_U8(value, outptr)          outptr = (uint8_t *)&value;
#   define BIGENDIAN_64BIT_U8_TO_U256(value, outptr)          outptr = (uint64_t *)value;

/**********************************************************************/
/* Change and copy the data type while maintaining little endianness. */
/**********************************************************************/
#   define LITTLEENDIAN_U32_TO_U8_COPY(value, outval)         memcpy(outval, &value, 4);
#   define LITTLEENDIAN_U8_TO_U32_COPY(value, outval)         memcpy(&outval, value, 4);
#   define LITTLEENDIAN_U64_TO_U8_COPY(value, outval)         memcpy(outval, &value, 8);
#   define LITTLEENDIAN_U8_TO_U64_COPY(value, outval)         memcpy(&outval, value, 8);
#   define LITTLEENDIAN_U128_TO_U8_COPY(value, outval)        memcpy(outval, value, 16);
#   define LITTLEENDIAN_U8_TO_U128_COPY(value, outval)        memcpy(outval, value, 16);
#   define LITTLEENDIAN_U192_TO_U8_COPY(value, outval)        memcpy(outval, value, 24);
#   define LITTLEENDIAN_U8_TO_U192_COPY(value, outval)        memcpy(outval, value, 24);
#   define LITTLEENDIAN_U256_TO_U8_COPY(value, outval)        memcpy(outval, value, 32);
#   define LITTLEENDIAN_U8_TO_U256_COPY(value, outval)        memcpy(outval, value, 32); 

/********************************************************************/
/* Change the data type while maintaining big endianness in 32-bit. */
/********************************************************************/
#   define BIGENDIAN_U32_TO_U8(value, outptr)                 value   = _byteswap_ulong(value); \
                                                              outptr  = (uint8_t *)&value;
                                                              
#   define BIGENDIAN_U8_TO_U32(value, outptr)                 outptr  = (uint32_t *)&value;  \
                                                              *outptr = _byteswap_ulong(*outptr);

#   define BIGENDIAN_32BIT_U64_TO_U8(value, outptr)           *value       = _byteswap_ulong(*value);  \
                                                              *(value + 1) = _byteswap_ulong(*(value + 1));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_32BIT_U8_TO_U64(value, outptr)           outptr        = (uint32_t *)&value;  \
                                                              *outptr       = _byteswap_ulong(*outptr);  \
                                                              *(outptr + 1) = _byteswap_ulong(*(outptr + 1));

#   define BIGENDIAN_32BIT_U128_TO_U8(value, outptr)          *(value)     = _byteswap_ulong(*value);  \
                                                              *(value + 1) = _byteswap_ulong(*(value + 1));  \
                                                              *(value + 2) = _byteswap_ulong(*(value + 2));  \
                                                              *(value + 3) = _byteswap_ulong(*(value + 3));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_32BIT_U8_TO_U128(value, outptr)          outptr        = (uint32_t *)value; \
                                                              *(outptr)     = _byteswap_ulong(*outptr);  \
                                                              *(outptr + 1) = _byteswap_ulong(*(outptr + 1));  \
                                                              *(outptr + 2) = _byteswap_ulong(*(outptr + 2));  \
                                                              *(outptr + 3) = _byteswap_ulong(*(outptr + 3));

#   define BIGENDIAN_32BIT_U192_TO_U8(value, outptr)          *(value)     = _byteswap_ulong(*value);  \
                                                              *(value + 1) = _byteswap_ulong(*(value + 1));  \
                                                              *(value + 2) = _byteswap_ulong(*(value + 2));  \
                                                              *(value + 3) = _byteswap_ulong(*(value + 3));  \
                                                              *(value + 4) = _byteswap_ulong(*(value + 4));  \
                                                              *(value + 5) = _byteswap_ulong(*(value + 5));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_32BIT_U8_TO_U192(value, outptr)          outptr        = (uint32_t *)value; \
                                                              *(outptr)     = _byteswap_ulong(*outptr);  \
                                                              *(outptr + 1) = _byteswap_ulong(*(outptr + 1));  \
                                                              *(outptr + 2) = _byteswap_ulong(*(outptr + 2));  \
                                                              *(outptr + 3) = _byteswap_ulong(*(outptr + 3));  \
                                                              *(outptr + 4) = _byteswap_ulong(*(outptr + 4));  \
                                                              *(outptr + 5) = _byteswap_ulong(*(outptr + 5));

#   define BIGENDIAN_32BIT_U256_TO_U8(value, outptr)          *(value)     = _byteswap_ulong(*value);  \
                                                              *(value + 1) = _byteswap_ulong(*(value + 1));  \
                                                              *(value + 2) = _byteswap_ulong(*(value + 2));  \
                                                              *(value + 3) = _byteswap_ulong(*(value + 3));  \
                                                              *(value + 4) = _byteswap_ulong(*(value + 4));  \
                                                              *(value + 5) = _byteswap_ulong(*(value + 5));  \
                                                              *(value + 6) = _byteswap_ulong(*(value + 6));  \
                                                              *(value + 7) = _byteswap_ulong(*(value + 7));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_32BIT_U8_TO_U256(value, outptr)          outptr        = (uint32_t *)value; \
                                                              *(outptr)     = _byteswap_ulong(*outptr);  \
                                                              *(outptr + 1) = _byteswap_ulong(*(outptr + 1));  \
                                                              *(outptr + 2) = _byteswap_ulong(*(outptr + 2));  \
                                                              *(outptr + 3) = _byteswap_ulong(*(outptr + 3));  \
                                                              *(outptr + 4) = _byteswap_ulong(*(outptr + 4));  \
                                                              *(outptr + 5) = _byteswap_ulong(*(outptr + 5));  \
                                                              *(outptr + 6) = _byteswap_ulong(*(outptr + 6));  \
                                                              *(outptr + 7) = _byteswap_ulong(*(outptr + 7));

/*****************************************************************************/
/* Change and copy the data type while maintaining big endianness in 32-bit. */
/*****************************************************************************/
#   define BIGENDIAN_U32_TO_U8_COPY(value, outval)            value   = _byteswap_ulong(value); \
                                                              memcpy(outval, &value, 4);

#   define BIGENDIAN_U8_TO_U32_COPY(value, outval)            memcpy(&outval, value, 4);  \
                                                              outval  = _byteswap_ulong(outval);

#   define BIGENDIAN_32BIT_U64_TO_U8_COPY(value, outval)      *value       = _byteswap_ulong(*value);  \
                                                              *(value + 1) = _byteswap_ulong(*(value + 1));  \
                                                              memcpy(outval, &value, 8);

#   define BIGENDIAN_32BIT_U8_TO_U64_COPY(value, outval)      memcpy(&outval, value, 8);  \
                                                              *outval       = _byteswap_ulong(*outval);  \
                                                              *(outval + 1) = _byteswap_ulong(*(outval + 1));

#   define BIGENDIAN_32BIT_U128_TO_U8_COPY(value, outval)     *(value)     = _byteswap_ulong(*value);  \
                                                              *(value + 1) = _byteswap_ulong(*(value + 1));  \
                                                              *(value + 2) = _byteswap_ulong(*(value + 2));  \
                                                              *(value + 3) = _byteswap_ulong(*(value + 3));  \
                                                              memcpy(outval, value, 16);

#   define BIGENDIAN_32BIT_U8_TO_U128_COPY(value, outval)     memcpy(outval, value, 16); \
                                                              *(outval)     = _byteswap_ulong(*outval);  \
                                                              *(outval + 1) = _byteswap_ulong(*(outval + 1));  \
                                                              *(outval + 2) = _byteswap_ulong(*(outval + 2));  \
                                                              *(outval + 3) = _byteswap_ulong(*(outval + 3));

#   define BIGENDIAN_32BIT_U192_TO_U8_COPY(value, outval)     *(value)     = _byteswap_ulong(*value);  \
                                                              *(value + 1) = _byteswap_ulong(*(value + 1));  \
                                                              *(value + 2) = _byteswap_ulong(*(value + 2));  \
                                                              *(value + 3) = _byteswap_ulong(*(value + 3));  \
                                                              *(value + 4) = _byteswap_ulong(*(value + 4));  \
                                                              *(value + 5) = _byteswap_ulong(*(value + 5));  \
                                                              memcpy(outval, value, 24);

#   define BIGENDIAN_32BIT_U8_TO_U192_COPY(value, outval)     memcpy(outval, value, 24); \
                                                              *(outval)     = _byteswap_ulong(*outval);  \
                                                              *(outval + 1) = _byteswap_ulong(*(outval + 1));  \
                                                              *(outval + 2) = _byteswap_ulong(*(outval + 2));  \
                                                              *(outval + 3) = _byteswap_ulong(*(outval + 3));  \
                                                              *(outval + 4) = _byteswap_ulong(*(outval + 4));  \
                                                              *(outval + 5) = _byteswap_ulong(*(outval + 5));

#   define BIGENDIAN_32BIT_U256_TO_U8_COPY(value, outval)     *(value)     = _byteswap_ulong(*value);  \
                                                              *(value + 1) = _byteswap_ulong(*(value + 1));  \
                                                              *(value + 2) = _byteswap_ulong(*(value + 2));  \
                                                              *(value + 3) = _byteswap_ulong(*(value + 3));  \
                                                              *(value + 4) = _byteswap_ulong(*(value + 4));  \
                                                              *(value + 5) = _byteswap_ulong(*(value + 5));  \
                                                              *(value + 6) = _byteswap_ulong(*(value + 6));  \
                                                              *(value + 7) = _byteswap_ulong(*(value + 7));  \
                                                              memcpy(outval, value, 32);

#   define BIGENDIAN_32BIT_U8_TO_U256_COPY(value, outval)     memcpy(outval, value, 32); \
                                                              *(outval)     = _byteswap_ulong(*outval);  \
                                                              *(outval + 1) = _byteswap_ulong(*(outval + 1));  \
                                                              *(outval + 2) = _byteswap_ulong(*(outval + 2));  \
                                                              *(outval + 3) = _byteswap_ulong(*(outval + 3));  \
                                                              *(outval + 4) = _byteswap_ulong(*(outval + 4));  \
                                                              *(outval + 5) = _byteswap_ulong(*(outval + 5));  \
                                                              *(outval + 6) = _byteswap_ulong(*(outval + 6));  \
                                                              *(outval + 7) = _byteswap_ulong(*(outval + 7));

/********************************************************************/
/* Change the data type while maintaining big endianness in 64-bit. */
/********************************************************************/
#   define BIGENDIAN_64BIT_U64_TO_U8(value, outptr)           value   = _byteswap_uint64(value);  \
                                                              outptr  = (uint8_t *)&value;

#   define BIGENDIAN_64BIT_U8_TO_U64(value, outptr)           outptr  = (uint64_t *)&value;  \
                                                              *outptr = _byteswap_uint64(*outptr);

#   define BIGENDIAN_64BIT_U128_TO_U8(value, outptr)          *(value)     = _byteswap_uint64(*value);  \
                                                              *(value + 1) = _byteswap_uint64(*(value + 1));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_64BIT_U8_TO_U128(value, outptr)          outptr        = (uint64_t *)value; \
                                                              *(outptr)     = _byteswap_uint64(*outptr);  \
                                                              *(outptr + 1) = _byteswap_uint64(*(outptr + 1));

#   define BIGENDIAN_64BIT_U192_TO_U8(value, outptr)          *(value)     = _byteswap_uint64(*value);  \
                                                              *(value + 1) = _byteswap_uint64(*(value + 1));  \
                                                              *(value + 2) = _byteswap_uint64(*(value + 2));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_64BIT_U8_TO_U192(value, outptr)          outptr        = (uint64_t *)value; \
                                                              *(outptr)     = _byteswap_uint64(*outptr);  \
                                                              *(outptr + 1) = _byteswap_uint64(*(outptr + 1));  \
                                                              *(outptr + 2) = _byteswap_uint64(*(outptr + 2));

#   define BIGENDIAN_64BIT_U256_TO_U8(value, outptr)          *(value)     = _byteswap_uint64(*value);  \
                                                              *(value + 1) = _byteswap_uint64(*(value + 1));  \
                                                              *(value + 2) = _byteswap_uint64(*(value + 2));  \
                                                              *(value + 3) = _byteswap_uint64(*(value + 3));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_64BIT_U8_TO_U256(value, outptr)          outptr        = (uint64_t *)value; \
                                                              *(outptr)     = _byteswap_uint64(*outptr);  \
                                                              *(outptr + 1) = _byteswap_uint64(*(outptr + 1));  \
                                                              *(outptr + 2) = _byteswap_uint64(*(outptr + 2));  \
                                                              *(outptr + 3) = _byteswap_uint64(*(outptr + 3));

/*****************************************************************************/
/* Change and copy the data type while maintaining big endianness in 64-bit. */
/*****************************************************************************/
#   define BIGENDIAN_64BIT_U64_TO_U8_COPY(value, outval)      value   = _byteswap_uint64(value);  \
                                                              memcpy(outval, &value, 8);

#   define BIGENDIAN_64BIT_U8_TO_U64_COPY(value, outval)      memcpy(&outval, value, 8);  \
                                                              outval = _byteswap_uint64(outval);

#   define BIGENDIAN_64BIT_U128_TO_U8_COPY(value, outval)     *(value)     = _byteswap_uint64(*value);  \
                                                              *(value + 1) = _byteswap_uint64(*(value + 1));  \
                                                              memcpy(outval, value, 16);

#   define BIGENDIAN_64BIT_U8_TO_U128_COPY(value, outval)     memcpy(outval, value, 16); \
                                                              *(outval)     = _byteswap_uint64(*outval);  \
                                                              *(outval + 1) = _byteswap_uint64(*(outval + 1));

#   define BIGENDIAN_64BIT_U192_TO_U8_COPY(value, outval)     *(value)     = _byteswap_uint64(*value);  \
                                                              *(value + 1) = _byteswap_uint64(*(value + 1));  \
                                                              *(value + 2) = _byteswap_uint64(*(value + 2));  \
                                                              memcpy(outval, value, 24);

#   define BIGENDIAN_64BIT_U8_TO_U192_COPY(value, outval)     memcpy(outval, value, 24); \
                                                              *(outval)     = _byteswap_uint64(*outval);  \
                                                              *(outval + 1) = _byteswap_uint64(*(outval + 1));  \
                                                              *(outval + 2) = _byteswap_uint64(*(outval + 2));

#   define BIGENDIAN_64BIT_U256_TO_U8_COPY(value, outval)     *(value)     = _byteswap_uint64(*value);  \
                                                              *(value + 1) = _byteswap_uint64(*(value + 1));  \
                                                              *(value + 2) = _byteswap_uint64(*(value + 2));  \
                                                              *(value + 3) = _byteswap_uint64(*(value + 3));  \
                                                              memcpy(outval, value, 32);

#   define BIGENDIAN_64BIT_U8_TO_U256_COPY(value, outval)     memcpy(outval, value, 32); \
                                                              *(outval)     = _byteswap_uint64(*outval);  \
                                                              *(outval + 1) = _byteswap_uint64(*(outval + 1));  \
                                                              *(outval + 2) = _byteswap_uint64(*(outval + 2));  \
                                                              *(outval + 3) = _byteswap_uint64(*(outval + 3));

#   if defined(_WIN64)
#   else
#   endif

# elif  __GNUC__

/********************************************************************/
/* Change the data type while maintaining big endianness in 64-bit. */
/********************************************************************/
#   define BIGENDIAN_U32_TO_U8(value, outptr)                 value   = __builtin_bswap32(value); \
                                                              outptr  = (uint8_t *)&value;

#   define BIGENDIAN_64BIT_U8_TO_U32(value, outptr)           outptr  = (uint32_t *)&value;  \
                                                              *outptr = __builtin_bswap32(*outptr);

#   define BIGENDIAN_64BIT_U64_TO_U8(value, outptr)           value   = __builtin_bswap64(value);  \
                                                              outptr  = (uint8_t *)&value;

#   define BIGENDIAN_64BIT_U8_TO_U64(value, outptr)           outptr  = (uint64_t *)&value;  \
                                                              *outptr = __builtin_bswap64(*outptr);

#   define BIGENDIAN_64BIT_U128_TO_U8(value, outptr)          *(value)     = __builtin_bswap64(*value);  \
                                                              *(value + 1) = __builtin_bswap64(*(value + 1));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_64BIT_U8_TO_U128(value, outptr)          outptr        = (uint64_t *)value; \
                                                              *(outptr)     = __builtin_bswap64(*outptr);  \
                                                              *(outptr + 1) = __builtin_bswap64(*(outptr + 1));

#   define BIGENDIAN_64BIT_U192_TO_U8(value, outptr)          *(value)     = __builtin_bswap64(*value);  \
                                                              *(value + 1) = __builtin_bswap64(*(value + 1));  \
                                                              *(value + 2) = __builtin_bswap64(*(value + 2));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_64BIT_U8_TO_U192(value, outptr)          outptr        = (uint64_t *)value; \
                                                              *(outptr)     = __builtin_bswap64(*outptr);  \
                                                              *(outptr + 1) = __builtin_bswap64(*(outptr + 1));  \
                                                              *(outptr + 2) = __builtin_bswap64(*(outptr + 2));

#   define BIGENDIAN_64BIT_U256_TO_U8(value, outptr)          *(value)     = __builtin_bswap64(*value);  \
                                                              *(value + 1) = __builtin_bswap64(*(value + 1));  \
                                                              *(value + 2) = __builtin_bswap64(*(value + 2));  \
                                                              *(value + 3) = __builtin_bswap64(*(value + 3));  \
                                                              outptr       = (uint8_t *)&value;

#   define BIGENDIAN_64BIT_U8_TO_U256(value, outptr)          outptr        = (uint64_t *)value; \
                                                              *(outptr)     = __builtin_bswap64(*outptr);  \
                                                              *(outptr + 1) = __builtin_bswap64(*(outptr + 1));  \
                                                              *(outptr + 2) = __builtin_bswap64(*(outptr + 2));  \
                                                              *(outptr + 3) = __builtin_bswap64(*(outptr + 3));

/*****************************************************************************/
/* Change and copy the data type while maintaining big endianness in 64-bit. */
/*****************************************************************************/
#   define BIGENDIAN_U32_TO_U8_COPY(value, outval)            value   = __builtin_bswap32(value);  \
                                                              memcpy(outval, &value, 4);

#   define BIGENDIAN_U8_TO_U32_COPY(value, outval)            memcpy(&outval, value, 4);  \
                                                              outval = __builtin_bswap32(outval);

#   define BIGENDIAN_64BIT_U64_TO_U8_COPY(value, outval)      value   = __builtin_bswap64(value);  \
                                                              memcpy(outval, &value, 8);

#   define BIGENDIAN_64BIT_U8_TO_U64_COPY(value, outval)      memcpy(&outval, value, 8);  \
                                                              outval = __builtin_bswap64(outval);

#   define BIGENDIAN_64BIT_U128_TO_U8_COPY(value, outval)     *(value)     = __builtin_bswap64(*value);  \
                                                              *(value + 1) = __builtin_bswap64(*(value + 1));  \
                                                              memcpy(outval, value, 16);

#   define BIGENDIAN_64BIT_U8_TO_U128_COPY(value, outval)     memcpy(outval, value, 16); \
                                                              *(outval)     = __builtin_bswap64(*outval);  \
                                                              *(outval + 1) = __builtin_bswap64(*(outval + 1));

#   define BIGENDIAN_64BIT_U192_TO_U8_COPY(value, outval)     *(value)     = __builtin_bswap64(*value);  \
                                                              *(value + 1) = __builtin_bswap64(*(value + 1));  \
                                                              *(value + 2) = __builtin_bswap64(*(value + 2));  \
                                                              memcpy(outval, value, 24);

#   define BIGENDIAN_64BIT_U8_TO_U192_COPY(value, outval)     memcpy(outval, value, 24); \
                                                              *(outval)     = __builtin_bswap64(*outval);  \
                                                              *(outval + 1) = __builtin_bswap64(*(outval + 1));  \
                                                              *(outval + 2) = __builtin_bswap64(*(outval + 2));

#   define BIGENDIAN_64BIT_U256_TO_U8_COPY(value, outval)     *(value)     = __builtin_bswap64(*value);  \
                                                              *(value + 1) = __builtin_bswap64(*(value + 1));  \
                                                              *(value + 2) = __builtin_bswap64(*(value + 2));  \
                                                              *(value + 3) = __builtin_bswap64(*(value + 3));  \
                                                              memcpy(outval, value, 32);

#   define BIGENDIAN_64BIT_U8_TO_U256_COPY(value, outval)     memcpy(outval, value, 32); \
                                                              *(outval)     = __builtin_bswap64(*outval);  \
                                                              *(outval + 1) = __builtin_bswap64(*(outval + 1));  \
                                                              *(outval + 2) = __builtin_bswap64(*(outval + 2));  \
                                                              *(outval + 3) = __builtin_bswap64(*(outval + 3));

#   if defined(__x86_64__)
#   else 
#   endif
# endif

#elif __BIG_ENDIAN__
# ifdef _MSC_VER

/********************************************************************/
/* Change the data type while maintaining big endianness in 32-bit. */
/********************************************************************/
#   define BIGENDIAN_U32_TO_U8(value, outptr)                 outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U32(value, outptr)                 outptr = (uint32_t *)&value;
#   define BIGENDIAN_32BIT_U64_TO_U8(value, outptr)           outptr = (uint8_t *)&value;
#   define BIGENDIAN_32BIT_U8_TO_U64(value, outptr)           outptr = (uint32_t *)&value;
#   define BIGENDIAN_32BIT_U128_TO_U8(value, outptr)          outptr = (uint8_t *)&value;
#   define BIGENDIAN_32BIT_U8_TO_U128(value, outptr)          outptr = (uint32_t *)value;
#   define BIGENDIAN_32BIT_U192_TO_U8(value, outptr)          outptr = (uint8_t *)&value;
#   define BIGENDIAN_32BIT_U8_TO_U192(value, outptr)          outptr = (uint32_t *)value;
#   define BIGENDIAN_32BIT_U256_TO_U8(value, outptr)          outptr = (uint8_t *)&value;
#   define BIGENDIAN_32BIT_U8_TO_U256(value, outptr)          outptr = (uint32_t *)value;

/*****************************************************************************/
/* Change and copy the data type while maintaining big endianness in 32-bit. */
/*****************************************************************************/
#   define BIGENDIAN_U32_TO_U8_COPY(value, outval)            memcpy(outval, &value, 4);
#   define BIGENDIAN_U8_TO_U32_COPY(value, outval)            memcpy(&outval, value, 4);
#   define BIGENDIAN_32BIT_U64_TO_U8_COPY(value, outval)      memcpy(outval, &value, 8);
#   define BIGENDIAN_32BIT_U8_TO_U64_COPY(value, outval)      memcpy(&outval, value, 8);
#   define BIGENDIAN_32BIT_U128_TO_U8_COPY(value, outval)     memcpy(outval, value, 16);
#   define BIGENDIAN_32BIT_U8_TO_U128_COPY(value, outval)     memcpy(outval, value, 16);
#   define BIGENDIAN_32BIT_U192_TO_U8_COPY(value, outval)     memcpy(outval, value, 24);
#   define BIGENDIAN_32BIT_U8_TO_U192_COPY(value, outval)     memcpy(outval, value, 24);
#   define BIGENDIAN_32BIT_U256_TO_U8_COPY(value, outval)     memcpy(outval, value, 32);
#   define BIGENDIAN_32BIT_U8_TO_U256_COPY(value, outval)     memcpy(outval, value, 32); 

/********************************************************************/
/* Change the data type while maintaining big endianness in 64-bit. */
/********************************************************************/
#   define BIGENDIAN_U32_TO_U8(value, outptr)                 outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U32(value, outptr)                 outptr = (uint32_t *)&value;
#   define BIGENDIAN_U64_TO_U8(value, outptr)                 outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U64(value, outptr)                 outptr = (uint64_t *)&value;
#   define BIGENDIAN_U128_TO_U8(value, outptr)                outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U128(value, outptr)                outptr = (uint64_t *)value;
#   define BIGENDIAN_U192_TO_U8(value, outptr)                outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U192(value, outptr)                outptr = (uint64_t *)value;
#   define BIGENDIAN_U256_TO_U8(value, outptr)                outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U256(value, outptr)                outptr = (uint64_t *)value;

/*****************************************************************************/
/* Change and copy the data type while maintaining big endianness in 64-bit. */
/*****************************************************************************/
#   define BIGENDIAN_64BIT_U64_TO_U8_COPY(value, outval)      memcpy(outval, &value, 8);
#   define BIGENDIAN_64BIT_U8_TO_U64_COPY(value, outval)      memcpy(&outval, value, 8);
#   define BIGENDIAN_64BIT_U128_TO_U8_COPY(value, outval)     memcpy(outval, value, 16);
#   define BIGENDIAN_64BIT_U8_TO_U128_COPY(value, outval)     memcpy(outval, value, 16);
#   define BIGENDIAN_64BIT_U192_TO_U8_COPY(value, outval)     memcpy(outval, value, 24);
#   define BIGENDIAN_64BIT_U8_TO_U192_COPY(value, outval)     memcpy(outval, value, 24);
#   define BIGENDIAN_64BIT_U256_TO_U8_COPY(value, outval)     memcpy(outval, value, 32);
#   define BIGENDIAN_64BIT_U8_TO_U256_COPY(value, outval)     memcpy(outval, value, 32);

#   if defined(_WIN64)
#   else
#   endif
                                          
# elif  __GNUC__
/********************************************************************/
/* Change the data type while maintaining big endianness in 32-bit. */
/********************************************************************/
#   define BIGENDIAN_U32_TO_U8(value, outptr)                 outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U32(value, outptr)                 outptr = (uint32_t *)&value;
#   define BIGENDIAN_32BIT_U64_TO_U8(value, outptr)           outptr = (uint8_t *)&value;
#   define BIGENDIAN_32BIT_U8_TO_U64(value, outptr)           outptr = (uint32_t *)&value;
#   define BIGENDIAN_32BIT_U128_TO_U8(value, outptr)          outptr = (uint8_t *)&value;
#   define BIGENDIAN_32BIT_U8_TO_U128(value, outptr)          outptr = (uint32_t *)value;
#   define BIGENDIAN_32BIT_U192_TO_U8(value, outptr)          outptr = (uint8_t *)&value;
#   define BIGENDIAN_32BIT_U8_TO_U192(value, outptr)          outptr = (uint32_t *)value;
#   define BIGENDIAN_32BIT_U256_TO_U8(value, outptr)          outptr = (uint8_t *)&value;
#   define BIGENDIAN_32BIT_U8_TO_U256(value, outptr)          outptr = (uint32_t *)value;

/*****************************************************************************/
/* Change and copy the data type while maintaining big endianness in 32-bit. */
/*****************************************************************************/
#   define BIGENDIAN_U32_TO_U8_COPY(value, outval)            memcpy(outval, &value, 4);
#   define BIGENDIAN_U8_TO_U32_COPY(value, outval)            memcpy(&outval, value, 4);
#   define BIGENDIAN_32BIT_U64_TO_U8_COPY(value, outval)      memcpy(outval, &value, 8);
#   define BIGENDIAN_32BIT_U8_TO_U64_COPY(value, outval)      memcpy(&outval, value, 8);
#   define BIGENDIAN_32BIT_U128_TO_U8_COPY(value, outval)     memcpy(outval, value, 16);
#   define BIGENDIAN_32BIT_U8_TO_U128_COPY(value, outval)     memcpy(outval, value, 16);
#   define BIGENDIAN_32BIT_U192_TO_U8_COPY(value, outval)     memcpy(outval, value, 24);
#   define BIGENDIAN_32BIT_U8_TO_U192_COPY(value, outval)     memcpy(outval, value, 24);
#   define BIGENDIAN_32BIT_U256_TO_U8_COPY(value, outval)     memcpy(outval, value, 32);
#   define BIGENDIAN_32BIT_U8_TO_U256_COPY(value, outval)     memcpy(outval, value, 32); 

/********************************************************************/
/* Change the data type while maintaining big endianness in 64-bit. */
/********************************************************************/
#   define BIGENDIAN_U32_TO_U8(value, outptr)                 outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U32(value, outptr)                 outptr = (uint32_t *)&value;
#   define BIGENDIAN_U64_TO_U8(value, outptr)                 outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U64(value, outptr)                 outptr = (uint64_t *)&value;
#   define BIGENDIAN_U128_TO_U8(value, outptr)                outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U128(value, outptr)                outptr = (uint64_t *)value;
#   define BIGENDIAN_U192_TO_U8(value, outptr)                outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U192(value, outptr)                outptr = (uint64_t *)value;
#   define BIGENDIAN_U256_TO_U8(value, outptr)                outptr = (uint8_t *)&value;
#   define BIGENDIAN_U8_TO_U256(value, outptr)                outptr = (uint64_t *)value;

/*****************************************************************************/
/* Change and copy the data type while maintaining big endianness in 64-bit. */
/*****************************************************************************/
#   define BIGENDIAN_64BIT_U64_TO_U8_COPY(value, outval)      memcpy(outval, &value, 8);
#   define BIGENDIAN_64BIT_U8_TO_U64_COPY(value, outval)      memcpy(&outval, value, 8);
#   define BIGENDIAN_64BIT_U128_TO_U8_COPY(value, outval)     memcpy(outval, value, 16);
#   define BIGENDIAN_64BIT_U8_TO_U128_COPY(value, outval)     memcpy(outval, value, 16);
#   define BIGENDIAN_64BIT_U192_TO_U8_COPY(value, outval)     memcpy(outval, value, 24);
#   define BIGENDIAN_64BIT_U8_TO_U192_COPY(value, outval)     memcpy(outval, value, 24);
#   define BIGENDIAN_64BIT_U256_TO_U8_COPY(value, outval)     memcpy(outval, value, 32);
#   define BIGENDIAN_64BIT_U8_TO_U256_COPY(value, outval)     memcpy(outval, value, 32);

#   if defined(__x86_64__)
#   else 
#   endif

# endif

#endif

#endif

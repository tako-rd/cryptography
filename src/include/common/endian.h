/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef ENDIAN_H
#define ENDIAN_H

#include <stdint.h>
#include <string.h>

#include <type_traits>

#include "defs.h"
#include "simd.h"

namespace cryptography {

/***************************************************************/
/* Do not use in situations where execution speed is required. */
/***************************************************************/

/* Prototype declaration of class. */
template <template <typename T, uint32_t F> class Endian, typename UnitType, uint32_t ByteSize> class endian;
template <typename UnitType, uint32_t Size> class little_endian;
template <typename UnitType, uint32_t Size> class big_endian;

/* Alias declaration */
template <typename UnitType, uint32_t Size> using BIG    = big_endian<UnitType, Size>;
template <typename UnitType, uint32_t Size> using LITTLE = little_endian<UnitType, Size>;

/* Endian converter interface.                      */
/* Use as follows.                                  */
/*  endian<BIG, uint32_t, 16>::convert(in, out);    */
/*  endian<LITTLE, uint32_t, 16>::convert(in, out); */
/*  .. etc                                          */ 
template <template <typename T, uint32_t F> class Endian, typename UnitType, uint32_t ByteSize>
class endian {
 public:
  endian() noexcept {};

  endian(endian &other) = delete;

  endian(endian &&other) = delete;

  ~endian() {};

  static UnitType* convert(const uint8_t * const in, UnitType *out) noexcept {
    return Endian<UnitType, ByteSize>::convert(in, out);
  };

  static uint8_t* convert(const UnitType * const in, uint8_t *out) noexcept {
    return Endian<UnitType, ByteSize>::convert(in, out);
  };

  static_assert(true == std::is_same<UnitType, uint16_t>::value ||
                true == std::is_same<UnitType, uint32_t>::value ||
                true == std::is_same<UnitType, uint64_t>::value, 
                "Select unitType, which is the conversion source and destination type, from uint16_t, uint32_t, and uint64_t.");
  static_assert(true == std::is_same<Endian<UnitType, ByteSize>, big_endian<UnitType, ByteSize>>::value ||
                true == std::is_same<Endian<UnitType, ByteSize>, little_endian<UnitType, ByteSize>>::value,
                "Select Endian, which is in byte order, from BIG or LITTLE.");
  static_assert(0 == (ByteSize % sizeof(UnitType)), 
                "Specify the number of bytes that can be divided by the byte size of the type name specified in UnitType in ByteSize.");
};

class wrapswap {
 public:
  wrapswap() noexcept {};

  wrapswap(wrapswap &other)= delete;

  wrapswap(wrapswap &&other) = delete;

  ~wrapswap() {};

  static inline uint16_t byteswap(const uint16_t t) noexcept {
#if defined(_MSC_VER)
    return _byteswap_ushort(t);
#elif defined(__GNUC__)
    return __builtin_bswap16 (t);
#endif
  }

  static inline uint32_t byteswap(const uint32_t t) noexcept {
#if defined(_MSC_VER)
    return _byteswap_ulong(t);
#elif defined(__GNUC__)
    return __builtin_bswap32(t);
#endif
  }

  static inline uint64_t byteswap(const uint64_t t) noexcept {
#if defined(_MSC_VER)
    return _byteswap_uint64(t);
#elif defined(__GNUC__)
    return __builtin_bswap64(t);
#endif
  }
};

template <typename UnitType, uint32_t ByteSize>
class little_endian {
 public:
  little_endian() noexcept {};

  little_endian(little_endian &other) = delete;

  little_endian(little_endian &&other) = delete;

  ~little_endian() {};

  static inline UnitType* convert(const uint8_t * const in, UnitType *out) noexcept {
#if defined(__BIG_ENDIAN__)
    constexpr uint32_t units = ByteSize / sizeof(UnitType);
    static_assert(0 != units, "*** ERROR : ByteSize is smaller than UnitType size and cannot be converted.");

    memcpy(out, in, ByteSize);
    for (uint32_t i = 0; i < units; ++i) {
      out[i] = wrapswap::byteswap(out[i]);
    }
#elif defined(__LITTLE_ENDIAN__)
    memcpy(out, in, ByteSize);
#endif
    return out;
  };

  static inline uint8_t* convert(const UnitType * const in, uint8_t *out) noexcept {
#if defined(__BIG_ENDIAN__)
    constexpr uint32_t units = ByteSize / sizeof(UnitType);
    UnitType buf[units] = {0};

    static_assert(0 != units, "*** ERROR : ByteSize is smaller than UnitType size and cannot be converted.");

    memcpy(buf, in, ByteSize);
    for (uint32_t i = 0; i < units; ++i) {
      buf[i] = wrapswap::byteswap(buf[i]);
    }
    memcpy(out, buf, ByteSize);
#elif defined(__LITTLE_ENDIAN__)
    memcpy(out, in, ByteSize);
#endif
    return out;
  };
};

template <typename UnitType, uint32_t ByteSize>
class big_endian {
 public:
  big_endian() noexcept {};

  big_endian(big_endian &other) = delete;

  big_endian(big_endian &&other) = delete;

  ~big_endian() {};

  static inline UnitType* convert(const uint8_t * const in, UnitType *out) noexcept {
#if defined(__LITTLE_ENDIAN__)
    constexpr uint32_t units = ByteSize / sizeof(UnitType);
    static_assert(0 != units, "*** ERROR : ByteSize is smaller than UnitType size and cannot be converted.");

    memcpy(out, in, ByteSize);
    for (uint32_t i = 0; i < units; ++i) {
      out[i] = wrapswap::byteswap(out[i]);
    }
#elif defined(__BIG_ENDIAN__)
    memcpy(out, in, ByteSize);
#endif
    return out;
  };

  static inline uint8_t* convert(const UnitType * const in, uint8_t *out) noexcept {
#if defined(__LITTLE_ENDIAN__)
    constexpr uint32_t units = ByteSize / sizeof(UnitType);
    UnitType buf[units] = {0};

    static_assert(0 != units, "*** ERROR : ByteSize is smaller than UnitType size and cannot be converted.");

    memcpy(buf, in, ByteSize);
    for (uint32_t i = 0; i < units; ++i) {
      buf[i] = wrapswap::byteswap(buf[i]);
    }
    memcpy(out, buf, ByteSize);
#elif defined(__BIG_ENDIAN__)
    memcpy(out, in, ByteSize);
#endif
    return out;
  };
};

}
#endif

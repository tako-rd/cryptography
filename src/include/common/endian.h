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

#include "simd.h"

// 使うものメモ
// _byteswap_ulong()
// _byteswap_uint64()

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
# if (__BYTE_ORDER == __LITTLE_ENDIAN) || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#   define __LITTLE_ENDIAN__
# elif (__BYTE_ORDER == __BIG_ENDIAN) || (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#   define __BIG_ENDIAN__
# endif
#endif

namespace cryptography {

// image : endian<Big, uint8_t, uint32_t, 16>
//  例 : uint8_t in[16]をビッグエンディアンでuint32_t out[4]に変換する。
//  endian<Big, uint32_t, 16>で変換元のサイズはオーバーロードで解決でもよし。
//  変換先の配列サイズは呼び元側が知っている前提でよし。

// prototype
template <template <typename T, uint32_t F> class Endian, typename UnitType, uint32_t ByteSize> class endian;
template <typename UnitType, uint32_t Size> class little_endian;
template <typename UnitType, uint32_t Size> class big_endian;

// alias
template <typename UnitType, uint32_t Size> using BIG = big_endian<UnitType, Size>;
template <typename UnitType, uint32_t Size> using LITTLE = little_endian<UnitType, Size>;

template <template <typename T, uint32_t F> class Endian, typename UnitType, uint32_t ByteSize>
class endian {
 public:
  endian() noexcept {};

  ~endian() {};

  static UnitType* convert(const uint8_t * const in, UnitType *out) noexcept {
    return Endian<UnitType, ByteSize>::convert(in, out);
  };

  static uint8_t* convert(const UnitType * const in, uint8_t *out) noexcept {
    return Endian<UnitType, ByteSize>::convert(in, out);
  };
};

class wrapswap {
 public:
  wrapswap() noexcept {};

  ~wrapswap() {};

  static uint16_t byteswap(const uint16_t t) noexcept {
    return _byteswap_ushort(t);
  }

  static uint32_t byteswap(const uint32_t t) noexcept {
    return _byteswap_ulong(t);
  }

  static uint64_t byteswap(const uint64_t t) noexcept {
    return _byteswap_uint64(t);
  }
};

template <typename UnitType, uint32_t ByteSize>
class little_endian {
 public:
  little_endian() noexcept {};

  ~little_endian() {};

  static UnitType* convert(const uint8_t * const in, UnitType *out) noexcept {
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

  static uint8_t* convert(const UnitType * const in, uint8_t *out) noexcept {
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

  ~big_endian() {};

  static UnitType* convert(const uint8_t * const in, UnitType *out) noexcept {
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

  static uint8_t* convert(const UnitType * const in, uint8_t *out) noexcept {
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

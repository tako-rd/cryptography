/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "padding.h"

namespace cryptography {

void padding::initialize(const pdtype_t type, uint32_t unit_size) {
  type_ = type;
  unit_size_ = unit_size;
}

void padding::set(const char *raw, const uint64_t rawlen, char *padded, const uint64_t paddedlen) {

}

void padding::remove(const char *padded, const uint64_t paddedlen, char *raw, const uint64_t rawlen) {

}

inline void padding::set_zero_padding(const char *raw, const uint64_t rawlen, char *padded, const uint64_t paddedlen) const noexcept {
  const uint64_t psize = unit_size_ - (rawlen % unit_size_);



}

inline void padding::remove_zero_padding(const char *padded, const uint64_t paddedlen, char *raw, const uint64_t rawlen) const noexcept {

}



}
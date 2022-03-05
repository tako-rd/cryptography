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

int32_t padding::set(const char * const raw, const uint64_t rawlen, char *buf, const uint64_t buflen) {
  const uint64_t paddedlen  = (unit_size_ * ((rawlen / unit_size_) + 1));
  const uint8_t plen = (rawlen - paddedlen > 0) ? (rawlen - paddedlen) : (paddedlen - rawlen);
  int32_t ret = 0;

  memset(buf, 0x00, buflen);

  if (paddedlen == buflen) {
    return 1;
  } else {
    switch (type_) {
      case PKCS1:
        break;
      case PKCS5:
        ret = set_pkcs5(raw, rawlen, plen, paddedlen, buf);
        break;
      case PKCS7:
        ret = set_pkcs7(raw, rawlen, plen, paddedlen, buf);
        break;
      case PKCS8:
        break;
      case PKCS9:
        break;
      case PKCS10:
        break;
      case PKCS11:
        break;
      case PKCS12:
        break;
      case ISO10126:
        break;
      case SSL3:
        break;
      case OAEP_PADDING:
        break;
      default:
        break;
    }
  }
  return ret;
}

int32_t padding::remove(const char * const padded, const uint64_t paddedlen, char *buf, const uint64_t buflen) {
  int32_t ret = 0;

  memset(buf, 0x00, buflen);

  if (0 == (buflen % unit_size_) && buflen < paddedlen) {
    return 1;
  } else {
    switch (type_) {
      case PKCS1:
        break;
      case PKCS5:
        ret = remove_pkcs5(padded, paddedlen, buf);
        break;
      case PKCS7:
        ret = remove_pkcs7(padded, paddedlen, buf);
        break;
      case PKCS8:
        break;
      case PKCS9:
        break;
      case PKCS10:
        break;
      case PKCS11:
        break;
      case PKCS12:
        break;
      case ISO10126:
        break;
      case SSL3:
        break;
      case OAEP_PADDING:
        break;
      default:
        break;
    }
  }
  return ret;
}

inline int32_t padding::set_pkcs5(const char * const raw, const uint64_t rawlen, const uint64_t plen, const uint64_t pend, char *buf) const noexcept {
  if (0x08 < plen) {
    return 1;
  }

  for (uint64_t i = 0; i < rawlen; ++i) {
    buf[i] = raw[i];
  }

  for (uint64_t j = rawlen; j < pend; ++j) {
    buf[j] = (char)((uint8_t)plen);
  }
  return 0;
}

inline int32_t padding::remove_pkcs5(const char * const padded, const uint64_t paddedlen, char *buf) const noexcept {
  const uint8_t plen = (uint8_t)padded[paddedlen - 1];
  const uint64_t rlen = paddedlen - plen; 

  if (0x08 < plen) {
    return 1;
  }

  for (uint8_t i = rlen; paddedlen > i; ++i) {
    if (plen != (uint8_t)padded[i]) {
      return 1;
    }
  }

  for (uint64_t j = 0; rlen > j; ++j) {
    buf[j] = padded[j];
  } 
  return 0;
}

inline int32_t padding::set_pkcs7(const char * const raw, const uint64_t rawlen, const uint64_t plen, const uint64_t pend, char *buf) const noexcept {
  if (0xFF < plen) {
    return 1;
  }

  for (uint64_t i = 0; i < rawlen; ++i) {
    buf[i] = raw[i];
  }

  for (uint64_t j = rawlen; j < pend; ++j) {
    buf[j] = (char)((uint8_t)plen);
  }
  return 0;
}

inline int32_t padding::remove_pkcs7(const char * const padded, const uint64_t paddedlen, char *buf) const noexcept {
  const uint8_t plen = (uint8_t)padded[paddedlen - 1];
  const uint64_t rlen = paddedlen - plen; 

  if (0xFF < plen) {
    return 1;
  }

  for (uint8_t i = rlen; paddedlen > i; ++i) {
    if (plen != (uint8_t)padded[i]) {
      return 1;
    }
  }

  for (uint64_t j = 0; rlen > j; ++j) {
    buf[j] = padded[j];
  } 
  return 0;
}


}
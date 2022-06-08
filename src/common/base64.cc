/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#if (_M_X64 == 100 || _M_IX86 == 600) || (_X86_ == 1 || __x86_64__ == 1)
#include "common/base64.h"

namespace cryptography {

#define EXTRACT_6BIT_MASK     0x000000000000003F
#define EXTRACT_8BIT_MASK     0x00000000000000FF
#define BASE64_PADDING_CHAR   '='

static const char base64_encode_table[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/',
};

static const uint8_t base64_decode_table[123] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00, 0x3F,
  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
  0x3C, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
  0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
  0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
  0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
  0x31, 0x32, 0x33,
};

base64::base64() {

}

base64::~base64() {

}
void base64::encode(const std::vector<uint8_t> byte_array, std::string &base64text) {
  encode_rfc4648(byte_array, base64text);
}

void base64::encode(const std::string inputtext, std::string &base64text) {
  std::vector<uint8_t> input_bytes;
  uint64_t size = inputtext.length();
  const char *text_p = inputtext.c_str();

  for (uint64_t cnt = 0; cnt < size; ++cnt) {
    input_bytes.emplace_back(text_p[cnt]);
  }

  encode_rfc4648(input_bytes, base64text);
}

void base64::decode(std::vector<uint8_t> &byte_array, const std::string base64text) {
  decode_rfc4648(byte_array, base64text);
}

void base64::decode(std::string &byte_array, const std::string base64text) {
  std::vector<uint8_t> output_bytes;

  decode_rfc4648(output_bytes, base64text);

  for (uint8_t &b : output_bytes) {
    byte_array += (char)b;
  }
}


void base64::encode_rfc4648(const std::vector<uint8_t> byte_array, std::string &base64text) {

  if (0 == byte_array.size() && UINT64_MAX < byte_array.size()) {
    // error code.
    return ;
  }

  base64text = "";
  uint64_t cipher_size = ('\0' != byte_array.back()) ? byte_array.size() : byte_array.size() - 1;

  for (uint64_t bytes = 0; bytes < cipher_size; bytes += 3) {
    uint32_t char_32bit = 0;
    uint8_t char_size = 0;
    uint8_t array_6bit[4] = {0};

    char_size = (uint8_t)((3 < cipher_size - bytes) ? 3 : (cipher_size - bytes));

    for (uint8_t cnt = 0; cnt < char_size; ++cnt) {
      char_32bit |= (uint32_t)(byte_array[bytes + cnt] << (16 - (8 * cnt)));
    }

    for (uint8_t cnt = 0; cnt < char_size + 1; ++cnt) {
      array_6bit[cnt] = (uint8_t)((char_32bit & (EXTRACT_6BIT_MASK << (18 - (6 * cnt)))) >> (18 - (6 * cnt)));
    }

    for (uint8_t cnt = 0; cnt < 4; ++cnt) {
      if (char_size + 1 > cnt) {
        base64text += base64_encode_table[array_6bit[cnt]];
      } else {
        base64text += BASE64_PADDING_CHAR;
      }
    }
  }
}

void base64::decode_rfc4648(std::vector<uint8_t> &byte_array, const std::string base64text) {
  uint64_t base64text_size = 0;

  if (0 == base64text.size() && UINT64_MAX < base64text.size()) {
    // error code.
    return ;
  }

  byte_array.clear();

  if (std::string::npos != base64text.find_first_of(BASE64_PADDING_CHAR)) {
    base64text_size = base64text.find_first_of(BASE64_PADDING_CHAR);
  } else {
    base64text_size = base64text.size();
  }

  for (uint64_t bytes = 0; bytes < base64text_size; bytes += 4) {
    uint32_t ptext = 0;

    for (uint8_t cnt = 0; cnt < 4; ++cnt) {
      if (sizeof(base64_decode_table) > base64text[bytes + cnt]) {
        ptext |= (uint32_t)(base64_decode_table[base64text[bytes + cnt]] << (18 - (6 * cnt)));
      } else {
        // error code.
        return ;
      }
    }

    for (uint8_t cnt = 0; cnt < 3; ++cnt) {
      uint8_t charactor = (uint8_t)((ptext & (EXTRACT_8BIT_MASK << (16 - (8 * cnt)))) >> (16 - (8 * cnt)));

      if ('\0' != charactor) {
        byte_array.emplace_back(charactor);
      }
    }
  }
}


}
#endif

/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "key_generator.h"

namespace cryptography {

static const uint8_t des_weak_keys[4][8] = {
  {0b0000'0001, 0b0000'0001, 0b0000'0001, 0b0000'0001, 0b0000'0001, 0b0000'0001, 0b0000'0001, 0b0000'0001},
  {0b0001'1111, 0b0001'1111, 0b0001'1111, 0b0001'1111, 0b1110'0000, 0b1110'0000, 0b1110'0000, 0b1110'0000},
  {0b1110'0000, 0b1110'0000, 0b1110'0000, 0b1110'0000, 0b0001'1111, 0b0001'1111, 0b0001'1111, 0b0001'1111},
  {0b1111'1110, 0b1111'1110, 0b1111'1110, 0b1111'1110, 0b1111'1110, 0b1111'1110, 0b1111'1110, 0b1111'1110},
};

static const uint8_t des_semiweak_keys[12][8] = {
  {0b000'00001, 0b1111'1110, 0b0000'0001, 0b1111'1110, 0b0000'0001, 0b1111'1110, 0b0000'0001, 0b1111'1110},
  {0b111'11110, 0b0000'0001, 0b1111'1110, 0b0000'0001, 0b1111'1110, 0b0000'0001, 0b1111'1110, 0b0000'0001},
  {0b000'11111, 0b1110'0000, 0b0001'1111, 0b1110'0000, 0b0001'1111, 0b1110'0000, 0b0001'1111, 0b1110'0000},
  {0b111'00000, 0b0001'1111, 0b1110'0000, 0b0001'1111, 0b1110'0000, 0b0001'1111, 0b1110'0000, 0b0001'1111},
  {0b000'00001, 0b1110'0000, 0b0000'0001, 0b1110'0000, 0b0000'0001, 0b1110'0000, 0b0000'0001, 0b1110'0000},
  {0b111'00000, 0b0000'0001, 0b1110'0000, 0b0000'0001, 0b1110'0000, 0b0000'0001, 0b1110'0000, 0b0000'0001},
  {0b000'11111, 0b1111'1110, 0b0001'1111, 0b1111'1110, 0b0001'1111, 0b1111'1110, 0b0001'1111, 0b1111'1110},
  {0b111'11110, 0b0001'1111, 0b1111'1110, 0b0001'1111, 0b1111'1110, 0b0001'1111, 0b1111'1110, 0b0001'1111},
  {0b000'00001, 0b0001'1111, 0b0000'0001, 0b0001'1111, 0b0000'0001, 0b0001'1111, 0b0000'0001, 0b0001'1111},
  {0b000'11111, 0b0000'0001, 0b0001'1111, 0b0000'0001, 0b0001'1111, 0b0000'0001, 0b0001'1111, 0b0000'0001},
  {0b111'00000, 0b1111'1110, 0b1110'0000, 0b1111'1110, 0b1110'0000, 0b1111'1110, 0b1110'0000, 0b1111'1110},
  {0b111'11110, 0b1110'0000, 0b1111'1110, 0b1110'0000, 0b1111'1110, 0b1110'0000, 0b1111'1110, 0b1110'0000},
};

key_generator::key_generator() {

}

key_generator::~key_generator() {

}

std::vector<uint8_t> key_generator::generate(const uint16_t schm) {
  std::vector<uint8_t> key = {0};

  switch (schm) {
    case SIMPLE_DES:
      key = gen_des_key();
      break;
    case AES128:
    case AES192:
    case AES256:
      break;
    case RSA:
      break;
    default:
      break;
  }

  return key;
}

std::vector<uint8_t> key_generator::gen_des_key() {
  std::vector<uint8_t> key;
  uint8_t key_oct = 0;
  bool is_unsecured = true;
  std::random_device rnd_dev;
  std::mt19937 mt(rnd_dev());
  std::uniform_int_distribution<> rnd_8bit(0, UINT8_MAX);

  do {
    for (int bytes = 0; bytes < 8; ++bytes) {
      int parity_seed = 0;

      key_oct = (uint8_t)rnd_8bit(mt);
      for (int shift = 1; shift < 8; ++shift) {
        if (0 != (key_oct & (1 << shift))) {
          ++parity_seed;
        }
      }

      if (0 == (parity_seed % 2)) {
        key_oct = key_oct >> 1;
        key_oct = (key_oct << 1) + 0b0000'0001;
        key.push_back(key_oct);

      } else {
        key_oct = key_oct >> 1;
        key_oct = (key_oct << 1) + 0b0000'0000;
        key.push_back(key_oct);
      }
    }

    is_unsecured = check_des_key(key);
    if (true == is_unsecured) {
      key.clear();
    }
  } while (is_unsecured);

  return key;
}

bool key_generator::check_des_key(const std::vector<uint8_t>& key) {
  bool is_match_all = false;

  for (int wk_idx = 0; wk_idx < 4; ++wk_idx) {
    for (int bytes = 0; bytes < 8; ++bytes) {
      if (des_weak_keys[wk_idx][bytes] == key[bytes]) {
        is_match_all = true;
      } else {
        is_match_all = false;
        break;
      }
    }

    if (true == is_match_all) {
      return is_match_all;
    }
  }

  for (int swk_idx = 0; swk_idx < 12; ++swk_idx) {
    for (int bytes = 0; bytes < 8; ++bytes) {
      if (des_semiweak_keys[swk_idx][bytes] == key[bytes]) {
        is_match_all = true;
      } else {
        is_match_all = false;
        break;
      }
    }

    if (true == is_match_all) {
      return is_match_all;
    }
  }

  return is_match_all;
}


}
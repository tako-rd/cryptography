/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include <stdint.h>
#include <vector>
#include <random>

#include <iostream>
#include <bitset>

#include "defs.h"

namespace cryptography {

class key_generator { 
 public:
  key_generator();

  ~key_generator();

  std::vector<uint8_t> generate(const uint16_t schm);

 private:
  std::vector<uint8_t> gen_des_key();

  bool check_des_key(const std::vector<uint8_t>& key);
   
};

}

#endif
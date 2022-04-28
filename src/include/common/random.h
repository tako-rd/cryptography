/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

#include "common/simd.h"

namespace cryptography {

class random {
 public:
  random() {};

  ~random() {};

  int32_t generate_u32() const noexcept;

  int32_t generate_u64() const noexcept;

 private:

};

}
#endif

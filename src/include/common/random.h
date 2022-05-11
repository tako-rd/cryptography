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
  random() noexcept {};

  ~random() {};

  uint32_t generate_u32() const noexcept;

  uint64_t generate_u64() const noexcept;
};

}
#endif

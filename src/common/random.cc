/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */


#include "common/random.h"

namespace cryptography {

/* Temporary implementation. Eventually,                        */ 
/* random numbers from multiple sources will be mixed and used. */
uint32_t random::generate_u32() const noexcept {
  uint32_t randval = 0;

  while (0 == _rdrand32_step(&randval));
  return randval;
}

}
/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "common/bit.h"
#include "common/simd.h"

namespace cryptography {

uint32_t bit::popcount32(uint64_t in) noexcept {
# if (_M_X64 == 100 || _M_IX86 == 600)
  static_assert(true, "An infeasible function has been called.");
  return 0;
# elif (_M_ARM == 7)
  uint8x8_t counter8x8 = {0}; 
  uint32_t counter = 0;

  counter8x8 = vcnt_u8(vcreate_u8((uint64_t)in));

  counter += vget_lane_u8(counter8x8, 0);
  counter += vget_lane_u8(counter8x8, 1);
  counter += vget_lane_u8(counter8x8, 2);
  counter += vget_lane_u8(counter8x8, 3);

  return counter;
#endif
}

uint64_t bit::popcount64(uint64_t in) noexcept {
# if (_M_X64 == 100 || _M_IX86 == 600)
  static_assert(true, "An infeasible function has been called.");
  return 0;
# elif (_M_ARM == 7)
  uint8x8_t counter8x8 = {0}; 
  uint32_t counter = 0;

  counter8x8 = vcnt_u8(vcreate_u8(in));

  counter += vget_lane_u8(counter8x8, 0);
  counter += vget_lane_u8(counter8x8, 1);
  counter += vget_lane_u8(counter8x8, 2);
  counter += vget_lane_u8(counter8x8, 3);
  counter += vget_lane_u8(counter8x8, 4);
  counter += vget_lane_u8(counter8x8, 5);
  counter += vget_lane_u8(counter8x8, 6);
  counter += vget_lane_u8(counter8x8, 7);

  return counter;
#endif
}

}
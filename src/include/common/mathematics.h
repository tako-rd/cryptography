/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef MATHEMATICS_H
#define MATHEMATICS_H

#include <string.h>
#include <stdint.h>

#include "common/random.h"
#include "common/bignumber.h"

namespace cryptography {

#define CONVERT_BIT_TO_BYTE(x) ((x) >> 3)
#define CONVERT_BIT_TO_UNIT(x) ((x) >> 5)

#define NPRIMELITY_TESTS  20

class mathematics {
public:
  mathematics() noexcept {};

  ~mathematics() {};

  void extended_gcd(bignumber a, bignumber b, bignumber &nx, bignumber &ny) noexcept {
    bignumber x = 0;
    bignumber y = 0;

    nx = 0;
    ny = 1;
    while (a % b != 0) {
      bignumber q = a / b;
      bignumber r = a % b;
      bignumber tx = x - q * nx;
      bignumber ty = y - q * ny;

      a = b;
      b = r;
      x = nx;
      y = ny;
      nx = tx;
      ny = ty;
    }
  }

  bool is_prime(bignumber &n) noexcept {
    if (n == 1 || (n & 0x00000001) == 0U) {
      return false;
    } else if (n == 2) {
      return true;
    }

    bignumber d = n - 1;
    bignumber a = 0U;
    bignumber t = 0U;
    bignumber y = 0U;

    while ((d & 0x0000'0001) == 0U) {
      d = d >> 1;
    }

    for (int32_t k = 0; k < NPRIMELITY_TESTS; ++k) {
      for (int32_t i = 0; i < CONVERT_BIT_TO_UNIT(n.bitsize()); ++i) {
        a[i] = ramdom_.generate_u32();
      }
      a = (a + 1) % n;
      t = d;
      y = mod_power(a, t, n);

      while ((t != (n - 1)) && (y != 0x00000001) && (y != (n - 1))) {
        y = (y * y) % n;
        t = t << 1;
      }

      if ((y != n - 1) && (t & 0x00000001) == 0U) { 
        return false; 
      }
    }
    return true;
  }

private:
  const bignumber mod_power(bignumber &base, bignumber exp, const bignumber &mod) noexcept {
    bignumber out = 1;

    while (exp > 0) {
      if ((exp & 0x00000001) == 0x00000001) {
        out = (out * base) % mod;
      }
      base = (base * base) % mod;
      exp = exp >> 1;
    }
    return out;
  }

  random ramdom_;
};

}
#endif

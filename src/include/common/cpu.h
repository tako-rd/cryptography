/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef _CPU_H_
#define _CPU_H_

#include "defs.h"

namespace cryptography {

typedef union cpu_infomations {
  struct reg32 {
    int32_t eax; /* EAX */
    int32_t ebx; /* EBX */
    int32_t ecx; /* ECX */
    int32_t edx; /* EDX */
  } reg32;

  struct bytes {
    /* EAX */
    int8_t eax0;
    int8_t eax1;
    int8_t eax2;
    int8_t eax3;
    /* EBX */
    int8_t ebx0;
    int8_t ebx1;
    int8_t ebx2;
    int8_t ebx3;
    /* ECX */
    int8_t ecx0;
    int8_t ecx1;
    int8_t ecx2;
    int8_t ecx3;
    /* EDX */
    int8_t edx0;
    int8_t edx1;
    int8_t edx2;
    int8_t edx3;
  } reg8;
} cpuinfo_t;

typedef enum cpu_vender_infomation {
  INTEL = 0,
  AMD,
  ARM,
  APPLE,
  UNKNOWN_CPU_VENDER,
} cpu_vender_t;

class cpu {
 public:
  cpu();

  ~cpu();

  void check();

  /* TODO: Classify by function. */
  bool aes();

  bool sha();

  bool fpu();

  bool avx();

  bool avx2();

  bool avx512cd();

  bool avx512er();

  bool avx512f();

  bool avx512pf();

  bool mmx();

  bool mmxext();

  bool sse();

  bool sse2();

  bool sse3();

  bool ssse3();

  bool sse4_1();

  bool sse4_2();

  bool sse4a();

  bool fma();

  bool popcnt();

  bool rdtscp();

 private:
  cpu_vender_t vender_;

  cpuinfo_t features_eax1_;

  cpuinfo_t extened_features_eax7_;

  cpuinfo_t extened_features_eax8_1_;
};

}

#endif

/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#include "cpu.h"

#define CPUID_EAX_INPUT_EXTENSIONS  0x8000'0001

#define CPUID_EBX_VENDER_INTEL      0x756e'6547
#define CPUID_ECX_VENDER_INTEL      0x6c65'746e
#define CPUID_EDX_VENDER_INTEL      0x4965'6e69

#define CPUID_EBX_VENDER_AMD        
#define CPUID_ECX_VENDER_AMD      
#define CPUID_EDX_VENDER_AMD      

#define EXTRACT_BIT_0               0b0000'0001
#define EXTRACT_BIT_1               0b0000'0010
#define EXTRACT_BIT_2               0b0000'0100
#define EXTRACT_BIT_3               0b0000'1000
#define EXTRACT_BIT_4               0b0001'0000
#define EXTRACT_BIT_5               0b0010'0000
#define EXTRACT_BIT_6               0b0100'0000
#define EXTRACT_BIT_7               0b1000'0000

namespace cryptography {



cpu::cpu() {
  vender_ = UNKNOWN_CPU_VENDER;
  memset(&features_eax1_, 0x00, sizeof(features_eax1_));
  memset(&extened_features_eax7_, 0x00, sizeof(extened_features_eax7_));
  memset(&extened_features_eax8_1_, 0x00, sizeof(extened_features_eax8_1_));

  check();
}

cpu::~cpu() {

}

bool cpu::aes() {
  return (features_eax1_.reg8.ecx3 & EXTRACT_BIT_0) == EXTRACT_BIT_0;
}

bool cpu::sha(){
  return (extened_features_eax7_.reg8.ebx3 & EXTRACT_BIT_5) == EXTRACT_BIT_5;
}

bool cpu::fpu() {
  return (features_eax1_.reg8.edx0 & EXTRACT_BIT_0) == EXTRACT_BIT_0;
}

bool cpu::avx() {
  return (features_eax1_.reg8.ecx3 & EXTRACT_BIT_4) == EXTRACT_BIT_4;
}

bool cpu::avx2() {
  return (extened_features_eax7_.reg8.ebx0 & EXTRACT_BIT_5) == EXTRACT_BIT_5;
}

bool cpu::avx512cd() {
  return (extened_features_eax7_.reg8.ebx3 & EXTRACT_BIT_4) == EXTRACT_BIT_4;
}

bool cpu::avx512er() {
  return (extened_features_eax7_.reg8.ebx3 & EXTRACT_BIT_3) == EXTRACT_BIT_3;
}

bool cpu::avx512f() {
  return (extened_features_eax7_.reg8.ebx2 & EXTRACT_BIT_0) == EXTRACT_BIT_0;
}

bool cpu::avx512pf() {
  return (extened_features_eax7_.reg8.ebx3 & EXTRACT_BIT_2) == EXTRACT_BIT_2;
}

bool cpu::mmx() {
  return (features_eax1_.reg8.edx2 & EXTRACT_BIT_7) == EXTRACT_BIT_7;
}

bool cpu::mmxext() {
  return (extened_features_eax8_1_.reg8.edx2 & EXTRACT_BIT_6) == EXTRACT_BIT_6;
}

bool cpu::sse() {
  return (features_eax1_.reg8.edx3 & EXTRACT_BIT_1) == EXTRACT_BIT_1;
}

bool cpu::sse2() {
  return (features_eax1_.reg8.edx3 & EXTRACT_BIT_2) == EXTRACT_BIT_2;
}

bool cpu::sse3() {
  return (features_eax1_.reg8.ecx0 & EXTRACT_BIT_0) == EXTRACT_BIT_0;
}

bool cpu::ssse3() {
  return (features_eax1_.reg8.ecx1 & EXTRACT_BIT_1) == EXTRACT_BIT_1;
}

bool cpu::sse4_1() {
  return (features_eax1_.reg8.ecx2 & EXTRACT_BIT_3) == EXTRACT_BIT_3;
}

bool cpu::sse4_2() {
  return (features_eax1_.reg8.ecx2 & EXTRACT_BIT_4) == EXTRACT_BIT_4;
}

bool cpu::sse4a() {
  return (extened_features_eax8_1_.reg8.ecx0 & EXTRACT_BIT_6) == EXTRACT_BIT_6;
}

bool cpu::fma() {
  return (features_eax1_.reg8.ecx1 & EXTRACT_BIT_4) == EXTRACT_BIT_4;
}

bool cpu::popcnt() {
  return (features_eax1_.reg8.ecx2 & EXTRACT_BIT_7) == EXTRACT_BIT_7;
}

bool cpu::rdtscp() {
  return (extened_features_eax8_1_.reg8.edx3 & EXTRACT_BIT_3) == EXTRACT_BIT_3;
}

void cpu::check() {
  int32_t vender[4] = {0};
  int32_t features_eax1[4] = {0};
  int32_t extened_features_eax7[4] = {0};
  int32_t extened_features_eax8_1[4] = {0};
  cpuinfo_t info = {0};

  /* Get CPU vender infomation. */
  GET_CPUID(vender, 0x0000'0000);

  info.reg32.eax = vender[0]; 
  info.reg32.ebx = vender[1]; 
  info.reg32.ecx = vender[2]; 
  info.reg32.edx = vender[3]; 
#if 0
  printf("%08x\n", info.reg32.ebx);
  printf("%08x\n", info.reg32.ecx);
  printf("%08x\n", info.reg32.edx);
#endif
  /* Identify the CPU vendor. */
  if (CPUID_EBX_VENDER_INTEL == info.reg32.ebx &&
      CPUID_ECX_VENDER_INTEL == info.reg32.ecx &&
      CPUID_EDX_VENDER_INTEL == info.reg32.edx) {
    vender_ = INTEL;

  } else {

  }

  /* Gets information about the CPU features. */
  GET_CPUID(features_eax1, 0x0000'0001);
  features_eax1_.reg32.eax = features_eax1[0];
  features_eax1_.reg32.ebx = features_eax1[1];
  features_eax1_.reg32.ecx = features_eax1[2];
  features_eax1_.reg32.edx = features_eax1[3];

#if 0
  DEBUG_DISPLAY_BIT_32("EAX1", features_eax1_.reg32.eax);
  DEBUG_DISPLAY_BIT_8("EAX1-3", features_eax1_.reg8.eax3);
  DEBUG_DISPLAY_BIT_8("EAX1-2", features_eax1_.reg8.eax2);
  DEBUG_DISPLAY_BIT_8("EAX1-1", features_eax1_.reg8.eax1);
  DEBUG_DISPLAY_BIT_8("EAX1-0", features_eax1_.reg8.eax0);

  DEBUG_DISPLAY_BIT_32("EBX1", features_eax1_.reg32.ebx);
  DEBUG_DISPLAY_BIT_8("EBX1-3", features_eax1_.reg8.ebx3);
  DEBUG_DISPLAY_BIT_8("EBX1-2", features_eax1_.reg8.ebx2);
  DEBUG_DISPLAY_BIT_8("EBX1-1", features_eax1_.reg8.ebx1);
  DEBUG_DISPLAY_BIT_8("EBX1-0", features_eax1_.reg8.ebx0);

  DEBUG_DISPLAY_BIT_32("ECX1", features_eax1_.reg32.ecx);
  DEBUG_DISPLAY_BIT_8("ECX1-3", features_eax1_.reg8.ecx3);
  DEBUG_DISPLAY_BIT_8("ECX1-2", features_eax1_.reg8.ecx2);
  DEBUG_DISPLAY_BIT_8("ECX1-1", features_eax1_.reg8.ecx1);
  DEBUG_DISPLAY_BIT_8("ECX1-0", features_eax1_.reg8.ecx0);

  DEBUG_DISPLAY_BIT_32("EDX1", features_eax1_.reg32.edx);
  DEBUG_DISPLAY_BIT_8("EDX1-3", features_eax1_.reg8.edx3);
  DEBUG_DISPLAY_BIT_8("EDX1-2", features_eax1_.reg8.edx2);
  DEBUG_DISPLAY_BIT_8("EDX1-1", features_eax1_.reg8.edx1);
  DEBUG_DISPLAY_BIT_8("EDX1-0", features_eax1_.reg8.edx0);
#endif

  GET_CPUID(extened_features_eax7, 0x0000'0007);
  extened_features_eax7_.reg32.eax = extened_features_eax7[0];
  extened_features_eax7_.reg32.ebx = extened_features_eax7[1];
  extened_features_eax7_.reg32.ecx = extened_features_eax7[2];
  extened_features_eax7_.reg32.edx = extened_features_eax7[3];

#if 0
  DEBUG_DISPLAY_BIT_32("EAX7", extened_features_eax7_.reg32.eax);
  DEBUG_DISPLAY_BIT_8("EAX7-3", extened_features_eax7_.reg8.eax3);
  DEBUG_DISPLAY_BIT_8("EAX7-2", extened_features_eax7_.reg8.eax2);
  DEBUG_DISPLAY_BIT_8("EAX7-1", extened_features_eax7_.reg8.eax1);
  DEBUG_DISPLAY_BIT_8("EAX7-0", extened_features_eax7_.reg8.eax0);

  DEBUG_DISPLAY_BIT_32("EBX7", extened_features_eax7_.reg32.ebx);
  DEBUG_DISPLAY_BIT_8("EBX7-3", extened_features_eax7_.reg8.ebx3);
  DEBUG_DISPLAY_BIT_8("EBX7-2", extened_features_eax7_.reg8.ebx2);
  DEBUG_DISPLAY_BIT_8("EBX7-1", extened_features_eax7_.reg8.ebx1);
  DEBUG_DISPLAY_BIT_8("EBX7-0", extened_features_eax7_.reg8.ebx0);

  DEBUG_DISPLAY_BIT_32("ECX7", extened_features_eax7_.reg32.ecx);
  DEBUG_DISPLAY_BIT_8("ECX7-3", extened_features_eax7_.reg8.ecx3);
  DEBUG_DISPLAY_BIT_8("ECX7-2", extened_features_eax7_.reg8.ecx2);
  DEBUG_DISPLAY_BIT_8("ECX7-1", extened_features_eax7_.reg8.ecx1);
  DEBUG_DISPLAY_BIT_8("ECX7-0", extened_features_eax7_.reg8.ecx0);

  DEBUG_DISPLAY_BIT_32("EDX7", extened_features_eax7_.reg32.edx);
  DEBUG_DISPLAY_BIT_8("EDX7-3", extened_features_eax7_.reg8.edx3);
  DEBUG_DISPLAY_BIT_8("EDX7-2", extened_features_eax7_.reg8.edx2);
  DEBUG_DISPLAY_BIT_8("EDX7-1", extened_features_eax7_.reg8.edx1);
  DEBUG_DISPLAY_BIT_8("EDX7-0", extened_features_eax7_.reg8.edx0);
#endif

  GET_CPUID(extened_features_eax8_1, 0x8000'0001);
  extened_features_eax8_1_.reg32.eax = extened_features_eax8_1[0];
  extened_features_eax8_1_.reg32.ebx = extened_features_eax8_1[1];
  extened_features_eax8_1_.reg32.ecx = extened_features_eax8_1[2];
  extened_features_eax8_1_.reg32.edx = extened_features_eax8_1[3];

#if 0
  DEBUG_DISPLAY_BIT_32("EAX8.1", extened_features_eax8_1_.reg32.eax);
  DEBUG_DISPLAY_BIT_8("EAX8.1-3", extened_features_eax8_1_.reg8.eax3);
  DEBUG_DISPLAY_BIT_8("EAX8.1-2", extened_features_eax8_1_.reg8.eax2);
  DEBUG_DISPLAY_BIT_8("EAX8.1-1", extened_features_eax8_1_.reg8.eax1);
  DEBUG_DISPLAY_BIT_8("EAX8.1-0", extened_features_eax8_1_.reg8.eax0);

  DEBUG_DISPLAY_BIT_32("EBX8.1", extened_features_eax8_1_.reg32.ebx);
  DEBUG_DISPLAY_BIT_8("EBX8.1-3", extened_features_eax8_1_.reg8.ebx3);
  DEBUG_DISPLAY_BIT_8("EBX8.1-2", extened_features_eax8_1_.reg8.ebx2);
  DEBUG_DISPLAY_BIT_8("EBX8.1-1", extened_features_eax8_1_.reg8.ebx1);
  DEBUG_DISPLAY_BIT_8("EBX8.1-0", extened_features_eax8_1_.reg8.ebx0);

  DEBUG_DISPLAY_BIT_32("ECX8.1", extened_features_eax8_1_.reg32.ecx);
  DEBUG_DISPLAY_BIT_8("ECX8.1-3", extened_features_eax8_1_.reg8.ecx3);
  DEBUG_DISPLAY_BIT_8("ECX8.1-2", extened_features_eax8_1_.reg8.ecx2);
  DEBUG_DISPLAY_BIT_8("ECX8.1-1", extened_features_eax8_1_.reg8.ecx1);
  DEBUG_DISPLAY_BIT_8("ECX8.1-0", extened_features_eax8_1_.reg8.ecx0);

  DEBUG_DISPLAY_BIT_32("EDX8.1", extened_features_eax8_1_.reg32.edx);
  DEBUG_DISPLAY_BIT_8("EDX8.1-3", extened_features_eax8_1_.reg8.edx3);
  DEBUG_DISPLAY_BIT_8("EDX8.1-2", extened_features_eax8_1_.reg8.edx2);
  DEBUG_DISPLAY_BIT_8("EDX8.1-1", extened_features_eax8_1_.reg8.edx1);
  DEBUG_DISPLAY_BIT_8("EDX8.1-0", extened_features_eax8_1_.reg8.edx0);
#endif
}

}

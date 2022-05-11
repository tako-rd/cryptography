/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef SIMD_H
#define SIMD_H

#if defined(_MSC_VER)
# include <intrin.h>

# define ALIGNAS(x)                           __declspec(align(x))
# define GET_CPUID(info, eax)                 __cpuid(info, eax)
#elif defined(__GNUC__)
# include <cpuid.h>
# include <x86intrin.h>

# define ALIGNAS(x)                           __attribute__((aligned(n)))
# define GET_CPUID(info, eax)                 __cpuid(eax, info[0], info[1], info[2], info[3])
#elif defined(__CC_ARM) && defined(_M_ARM64)
# include <arm_neon.h>

#elif defined(__INTEL_COMPILER)

#elif defined(__BORLANDC__)

#endif

#endif
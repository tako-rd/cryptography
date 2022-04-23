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

#ifdef _MSC_VER
# include <intrin.h>

# define ALIGNAS(x)                           __declspec(align(x))
# define GET_CPUID(info, eax)                 __cpuid(info, eax)
#elif __GNUC__
# include <cpuid.h>
# include <x86intrin.h>

# define ALIGNAS(x)                           __attribute__((aligned(n)))
# define GET_CPUID(info, eax)                 __cpuid(eax, info[0], info[1], info[2], info[3])
#endif

#endif
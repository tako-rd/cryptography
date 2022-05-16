/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <type_traits>

namespace cryptography {

/* If you want to change the dynamic memory allocation method, change this class. */
/* If dynamic memory cannot be used,                                              */
/* it is necessary to take measures such as passing a part of the global area.    */

template <typename Type, 
          bool FundamentralType = std::is_fundamental<Type>::value,
          bool IsPointer = std::is_pointer<Type>::value>
class allocator {
 public:
  allocator() noexcept {};

  ~allocator() {};

  Type* allocate(const uint32_t bytesize) noexcept {
    return (Type *)malloc(bytesize);
  };

  Type* reallocate(Type *ptr, const uint32_t previous_size, const uint32_t after_size) noexcept {
    Type *out = nullptr;
    out = (Type *)realloc(ptr, after_size);
    return out;
  };

  void deallocate(Type *ptr, const uint32_t bytesize) {
    memset(ptr, 0x00, bytesize);
    free(ptr);
  };
};

}
#endif

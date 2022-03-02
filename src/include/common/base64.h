/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef __BASE64_H_
#define __BASE64_H_

#include <string>
#include <vector>

#include "defs.h"

namespace cryptography {

class base64 {
 public:
  base64();

  ~base64();

  void encode(const std::vector<uint8_t> byte_array, std::string &base64text);

  void encode(const std::string inputtext, std::string &base64text);

  void decode(std::vector<uint8_t> &byte_array, const std::string base64text);

  void decode(std::string &byte_array, const std::string base64text);

 private:
   void encode_rfc4648(const std::vector<uint8_t> byte_array, std::string &base64text);

   void decode_rfc4648(std::vector<uint8_t> &byte_array, const std::string base64text);

};

}

#endif

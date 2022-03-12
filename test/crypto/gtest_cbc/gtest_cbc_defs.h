/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#ifndef GTEST_CBC_DEFS_H
#define GTEST_CBC_DEFS_H

#include <stdint.h>

const uint8_t CBC_TEST_DES_IV[8] = {
  '1', '2', '3', '4', '5', '6', '7', '8',
};

const uint8_t CBC_TEST_AES_IV[16] = {
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
};

const uint8_t CBC_TEST_STRING[80] = {
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
  '1', '2', '3', '4', '5', '6', '7', '8',
};

#endif
/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include "cfb.h"

namespace cryptography {

int32_t cfb::initialize(const uint16_t type, uint8_t *iv, const uint64_t ivlen) noexcept {

}

int32_t cfb::enc_preprocess(uint8_t *ptext, const uint64_t plen, uint8_t *cbuf, const uint64_t cblen) noexcept {

}

int32_t cfb::enc_postprocess(uint8_t *cbuf, const uint64_t cblen, uint8_t *ctext, const uint64_t clen) noexcept {

}

int32_t cfb::dec_preprocess(uint8_t *ctext, const uint64_t clen, uint8_t *pbuf, const uint64_t pblen) noexcept {

}

int32_t cfb::dec_postprocess(uint8_t *pbuf, const uint64_t pblen, uint8_t *ptext, const uint64_t plen) noexcept {

}

}
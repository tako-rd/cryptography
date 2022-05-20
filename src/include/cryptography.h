/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#include "common/defs.h"

#include "crypto/secret_key/secret_key.h"

#include "crypto/mode/mode.h"
#include "crypto/mode/cbc.h"
#include "crypto/mode/cfb.h"
#include "crypto/mode/ctr.h"
#include "crypto/mode/ecb.h"
#include "crypto/mode/ofb.h"

#include "crypto/public_key/rsa.h"
#include "common/bignumber.h"

namespace cryptography {

/*****************************************/
/* A list of classes available to users. */
/*****************************************/

/*!
 * Use as follows.
 *  secret_key<DES, CBC> des_cbc;
 *  secret_key<AES, ECB> aes_ecb;
 *  .. etc
 */
template <typename SecretKeyCryptosystem, template <typename T, uint32_t U> class Mode> class secret_key;

}

#endif

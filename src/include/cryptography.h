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
 * 
 * The algorithms and modes that can be set in the template arguments are summarized below.
 * The available secret key cryptographic algorithms are:
 *  - DES, AES, AESNI, Camellia, CAST128, CAST256, RC6, SEED, Twofish
 * The available encryption modes are:
 *  - ECB, CBC, CFB, OFB, CTR
 *
 * The methods available in the secret_key class are:
 *  - int32_t initialize(const uint8_t *key, const uint32_t ksize, const uint8_t *iv, const uint32_t ivsize)
 *      Specify the key used for encryption and decryption, and the initialization vector. 
 *        key    ... Specify the encryption key in any size of 128bit, 192bit, or 256bit.
 *        ksize  ... Specify the size of the encryption key in bytes. 
 *        iv     ... Specify the initialization vector with 128 bits.
 *        ivsize ... Specifies the size of the initialization vector in bytes.
 *
 *  - int32_t encrypt(const uint8_t * const ptext, const uint32_t psize, uint8_t *ctext, const uint32_t csize)
 *      Plaintext encryption is performed.
 *      The explanation of the argument is described below.
 *        ptext  ... Specifies the plaintext to be encrypted.
 *        psize  ... Specifies the size of the plaintext to be encrypted.
 *        ctext  ... Specifies a buffer to store the ciphertext. The buffer should be set as shown in the example below.
 *                   If the size of ptext is 12 bytes, the size of ctext should be 16 bytes.
 *                   If the size of ptext is 16 bytes, the size of ctext should be 32 bytes.
 *                   This is for pkcs7 padding.
 *        csize  ... Specifies the size of the ctext buffer as a multiple of 16 bytes.
 *                   Must be specified in ptext + fractional bytes.
 * 
 *  - int32_t decrypt(const uint8_t * const ctext, const uint32_t csize, uint8_t *ptext, const uint32_t psize)
 *      Decrypts the ciphertext.
 *      The explanation of the argument is described below.
 *        ctext  ... Specify a ciphertext that is a multiple of 16 bytes.
 *        csize  ... Specify the ciphertext size as a multiple of 16 byte size.
 *        ptext  ... Specify the buffer that receives plaintext in a multiple size of 16 bytes.
 *        psize  ... Specify the plaintext size as a multiple of 16 byte size.
 * 
 *  - void clear()
 *      Clear the subkey held in the secret_key class.
 * Note:
 *  If you want to use the ciphertext buffer with a fixed length, 
 *  you must copy the plaintext you enter into a buffer with a ciphertext buffer size of 16 bytes 
 *  and specify it in the ptext of the encrypt (...) method.
 *  For example, if you want to receive the ciphertext in a 500 byte ctext buffer, 
 *  you need to copy the plaintext to the (500-16) byte buffer and specify it in ptext.
 */
template <typename SecretKeyCryptosystem, template <typename T, uint32_t U> class Mode> class secret_key;

}

#endif

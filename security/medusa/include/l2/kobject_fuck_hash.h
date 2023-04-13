/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _FUCK_KOBJECT_HASH_H
#define _FUCK_KOBJECT_HASH_H

/* Hash name and digest size definitions based on the selected hashing function in Kconfig */
#if defined CONFIG_SECURITY_MEDUSA_FUCK_BLAKE2B_256 // BLAKE2B_256
    #if !IS_BUILTIN(CONFIG_CRYPTO_BLAKE2B)
		#error "You selected Blake2b for FUCK hash, but it is not configured to be builtin."
    #endif
    #include <crypto/blake2b.h>
    #define FUCK_HASH_NAME "blake2b-256" // crypto/blake2b_generic.c
    #define FUCK_HASH_DIGEST_SIZE BLAKE2B_256_HASH_SIZE
#elif defined CONFIG_SECURITY_MEDUSA_FUCK_BLAKE2B_512 // BLAKE2B_512
    #if !IS_BUILTIN(CONFIG_CRYPTO_BLAKE2B)
		#error "You selected Blake2b for FUCK hash, but it is not configured to be builtin."
    #endif
    #include <crypto/blake2b.h>
    #define FUCK_HASH_NAME "blake2b-512" // crypto/blake2b_generic.c
    #define FUCK_HASH_DIGEST_SIZE BLAKE2B_512_HASH_SIZE
#elif defined CONFIG_SECURITY_MEDUSA_FUCK_SHA2_256 // SHA2-256
    #if !IS_BUILTIN(CONFIG_CRYPTO_SHA256)
		#error "You selected sha256 for FUCK hash, but it is not configured to be builtin."
    #endif
    #include <crypto/sha2.h>
    #define FUCK_HASH_NAME "sha256" // crypto/sha256_generic.c
    #define FUCK_HASH_DIGEST_SIZE SHA256_DIGEST_SIZE
#elif defined CONFIG_SECURITY_MEDUSA_FUCK_SHA2_512 // SHA2-512
    #if !IS_BUILTIN(CONFIG_CRYPTO_SHA512)
		#error "You selected sha512 for FUCK hash, but it is not configured to be builtin."
    #endif
    #include <crypto/sha2.h>
    #define FUCK_HASH_NAME "sha512" // crypto/sha512_generic.c
    #define FUCK_HASH_DIGEST_SIZE SHA512_DIGEST_SIZE
#elif defined CONFIG_SECURITY_MEDUSA_FUCK_SHA3_256 // SHA3-256
    #if !IS_BUILTIN(CONFIG_CRYPTO_SHA3)
		#error "You selected sha3 for FUCK hash, but it is not configured to be builtin."
    #endif
    #include <crypto/sha3.h>
    #define FUCK_HASH_NAME "sha3-256" // crypto/sha3_generic.c
    #define FUCK_HASH_DIGEST_SIZE SHA3_256_DIGEST_SIZE
#elif defined CONFIG_SECURITY_MEDUSA_FUCK_SHA3_512 // SHA3-512
    #if !IS_BUILTIN(CONFIG_CRYPTO_SHA3)
		#error "You selected sha3 for FUCK hash, but it is not configured to be builtin."
    #endif
    #include <crypto/sha3.h>
    #define FUCK_HASH_NAME "sha3-512" // crypto/sha3_generic.c
    #define FUCK_HASH_DIGEST_SIZE SHA3_512_DIGEST_SIZE
#else
    #error "You not selected any hash function to be used in the FUCK module."
#endif

#endif

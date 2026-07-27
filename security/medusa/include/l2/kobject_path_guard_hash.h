/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_KOBJECT_PATH_GUARD_HASH_H
#define _MEDUSA_KOBJECT_PATH_GUARD_HASH_H

/* Hash parameters selected by security/medusa/Kconfig. */
#if defined(CONFIG_SECURITY_MEDUSA_PATH_GUARD_BLAKE2B_256)
#if !IS_BUILTIN(CONFIG_CRYPTO_BLAKE2B)
#error "Path guard requires built-in BLAKE2b"
#endif
#include <crypto/blake2b.h>
#define PATH_GUARD_HASH_NAME "blake2b-256"
#define PATH_GUARD_HASH_DIGEST_SIZE BLAKE2B_256_HASH_SIZE
#elif defined(CONFIG_SECURITY_MEDUSA_PATH_GUARD_BLAKE2B_512)
#if !IS_BUILTIN(CONFIG_CRYPTO_BLAKE2B)
#error "Path guard requires built-in BLAKE2b"
#endif
#include <crypto/blake2b.h>
#define PATH_GUARD_HASH_NAME "blake2b-512"
#define PATH_GUARD_HASH_DIGEST_SIZE BLAKE2B_512_HASH_SIZE
#elif defined(CONFIG_SECURITY_MEDUSA_PATH_GUARD_SHA2_256)
#if !IS_BUILTIN(CONFIG_CRYPTO_SHA256)
#error "Path guard requires built-in SHA-256"
#endif
#include <crypto/sha2.h>
#define PATH_GUARD_HASH_NAME "sha256"
#define PATH_GUARD_HASH_DIGEST_SIZE SHA256_DIGEST_SIZE
#elif defined(CONFIG_SECURITY_MEDUSA_PATH_GUARD_SHA2_512)
#if !IS_BUILTIN(CONFIG_CRYPTO_SHA512)
#error "Path guard requires built-in SHA-512"
#endif
#include <crypto/sha2.h>
#define PATH_GUARD_HASH_NAME "sha512"
#define PATH_GUARD_HASH_DIGEST_SIZE SHA512_DIGEST_SIZE
#elif defined(CONFIG_SECURITY_MEDUSA_PATH_GUARD_SHA3_256)
#if !IS_BUILTIN(CONFIG_CRYPTO_SHA3)
#error "Path guard requires built-in SHA-3"
#endif
#include <crypto/sha3.h>
#define PATH_GUARD_HASH_NAME "sha3-256"
#define PATH_GUARD_HASH_DIGEST_SIZE SHA3_256_DIGEST_SIZE
#elif defined(CONFIG_SECURITY_MEDUSA_PATH_GUARD_SHA3_512)
#if !IS_BUILTIN(CONFIG_CRYPTO_SHA3)
#error "Path guard requires built-in SHA-3"
#endif
#include <crypto/sha3.h>
#define PATH_GUARD_HASH_NAME "sha3-512"
#define PATH_GUARD_HASH_DIGEST_SIZE SHA3_512_DIGEST_SIZE
#else
#error "Select a Medusa path guard hashing function"
#endif

#endif /* _MEDUSA_KOBJECT_PATH_GUARD_HASH_H */

/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _FUCK_KOBJECT_HASH_H
#define _FUCK_KOBJECT_HASH_H

/* Hash name and digest size definitions based on the selected hashing function in config */
#ifdef CONFIG_SECURITY_MEDUSA_FUCK_BLAKE2B_256
#include <crypto/blake2b.h>
#define FUCK_HASH_NAME "blake2b-256" // crypto/blake2b_generic.c
#define FUCK_HASH_DIGEST_SIZE BLAKE2B_256_HASH_SIZE
#endif // BLAKE2B_256

#ifdef CONFIG_SECURITY_MEDUSA_FUCK_BLAKE2B_512
#include <crypto/blake2b.h>
#define FUCK_HASH_NAME "blake2b-512" // crypto/blake2b_generic.c
#define FUCK_HASH_DIGEST_SIZE BLAKE2B_512_HASH_SIZE
#endif // BLAKE2B_512

#ifdef SECURITY_MEDUSA_FUCK_BLAKE2S_256
#include <crypto/blake2s.h> // crypto/blake2s_generic.c
#define FUCK_HASH_NAME "blake2s-256"
#define FUCK_HASH_DIGEST_SIZE BLAKE2S_256_HASH_SIZE
#endif // BLAKE2S_256

#ifdef CONFIG_SECURITY_MEDUSA_FUCK_SHA2_256
#include <crypto/sha2.h>
#define FUCK_HASH_NAME "sha256" // crypto/sha256_generic.c
#define FUCK_HASH_DIGEST_SIZE SHA256_DIGEST_SIZE
#endif // SHA2-256

#ifdef CONFIG_SECURITY_MEDUSA_FUCK_SHA2_512
#include <crypto/sha2.h>
#define FUCK_HASH_NAME "sha512" // crypto/sha512_generic.c
#define FUCK_HASH_DIGEST_SIZE SHA512_DIGEST_SIZE
#endif // SHA2-512

#ifdef CONFIG_SECURITY_MEDUSA_FUCK_SHA3_256
#include <crypto/sha3.h>
#define FUCK_HASH_NAME "sha3-256" // crypto/sha3_generic.c
#define FUCK_HASH_DIGEST_SIZE SHA3_256_DIGEST_SIZE
#endif // SHA3-256

#ifdef CONFIG_SECURITY_MEDUSA_FUCK_SHA3_512
#include <crypto/sha3.h>
#define FUCK_HASH_NAME "sha3-512" // crypto/sha3_generic.c
#define FUCK_HASH_DIGEST_SIZE SHA3_512_DIGEST_SIZE
#endif // SHA3-512

#endif

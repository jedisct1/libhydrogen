#ifndef hydrogen_H
#define hydrogen_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wlong-long"
#endif
extern "C" {
#endif

#define HYDRO_VERSION_MAJOR 0
#define HYDRO_VERSION_MINOR 1

int hydro_init(void);

/* ---------------- */

#define randombytes_SEEDBYTES 32

uint32_t randombytes_random(void);

uint32_t randombytes_uniform(const uint32_t upper_bound);

void randombytes_buf(void *const buf, const size_t size);

void randombytes_buf_deterministic(void *const buf, const size_t len,
    const uint8_t seed[randombytes_SEEDBYTES]);

/* ---------------- */

#define hydro_hash_BYTES 32
#define hydro_hash_BYTES_MAX 65535
#define hydro_hash_BYTES_MIN 16
#define hydro_hash_CONTEXTBYTES 8
#define hydro_hash_KEYBYTES 32
#define hydro_hash_KEYBYTES_MAX 32
#define hydro_hash_KEYBYTES_MIN 16
#define hydro_hash_TWEAKBYTES 8

typedef struct hydro_hash_state {
    uint8_t  digest_len;
    uint8_t  key_len;
    uint8_t  fanout;
    uint8_t  depth;
    uint8_t  leaf_len[4];
    uint8_t  node_offset[4];
    uint8_t  xof_len[2];
    uint8_t  node_depth;
    uint8_t  inner_len;
    uint8_t  tweak[hydro_hash_TWEAKBYTES];
    uint8_t  ctx[hydro_hash_CONTEXTBYTES];
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[1];
    uint8_t  buf[64];
    uint8_t  buf_off;
} hydro_hash_state;

void hydro_hash_keygen(uint8_t *key, size_t key_len);

int hydro_hash_init(hydro_hash_state *state,
    const char ctx[hydro_hash_CONTEXTBYTES], const uint8_t *key, size_t key_len,
    size_t out_len);

int hydro_hash_update(hydro_hash_state *state, const void *in_, size_t in_len);

int hydro_hash_final(hydro_hash_state *state, uint8_t *out, size_t out_len);

int hydro_hash_hash(uint8_t *out, size_t out_len, const void *in_,
    size_t in_len, const char ctx[hydro_hash_CONTEXTBYTES], const uint8_t *key,
    size_t key_len);

/* ---------------- */

#define hydro_hash128_BYTES 16
#define hydro_hash128_CONTEXTBYTES 8
#define hydro_hash128_KEYBYTES 16

typedef struct hydro_hash128_state {
    uint64_t v0, v1, v2, v3;
    uint8_t  buf[8];
    uint8_t  buf_off;
    uint8_t  b;
} hydro_hash128_state;

void hydro_hash128_keygen(uint8_t key[hydro_hash128_KEYBYTES]);

int hydro_hash128_hash(uint8_t out[hydro_hash128_BYTES], const void *in_,
    size_t in_len, const char ctx[hydro_hash128_CONTEXTBYTES],
    const uint8_t key[hydro_hash128_KEYBYTES]);

int hydro_hash128_init(hydro_hash128_state *state,
    const char                              ctx[hydro_hash128_CONTEXTBYTES],
    const uint8_t                           key[hydro_hash128_KEYBYTES]);

int hydro_hash128_update(
    hydro_hash128_state *state, const void *in_, size_t in_len);

int hydro_hash128_final(
    hydro_hash128_state *state, uint8_t out[hydro_hash128_BYTES]);

/* ---------------- */

#define hydro_secretbox_CONTEXTBYTES 8
#define hydro_secretbox_HEADERBYTES (20 + 16)
#define hydro_secretbox_KEYBYTES 32

void hydro_secretbox_keygen(uint8_t key[hydro_secretbox_KEYBYTES]);

int hydro_secretbox_encrypt(uint8_t *c, const void *m_, size_t mlen,
    uint64_t msg_id, const char ctx[hydro_secretbox_CONTEXTBYTES],
    const uint8_t key[hydro_secretbox_KEYBYTES]);

int hydro_secretbox_decrypt(void *m_, const uint8_t *c, size_t clen,
    uint64_t msg_id, const char ctx[hydro_secretbox_CONTEXTBYTES],
    const uint8_t key[hydro_secretbox_KEYBYTES])
    __attribute__((warn_unused_result));

/* ---------------- */

#define hydro_kdf_CONTEXTBYTES 8
#define hydro_kdf_KEYBYTES 32
#define hydro_kdf_SUBKEYBYTES_MAX 65535
#define hydro_kdf_SUBKEYBYTES_MIN 16

void hydro_kdf_keygen(uint8_t key[hydro_kdf_KEYBYTES]);

int hydro_kdf_derive_from_key(uint8_t *subkey, size_t subkey_len,
    const char ctx[hydro_kdf_CONTEXTBYTES], uint64_t subkey_id,
    const uint8_t key[hydro_kdf_KEYBYTES]);

/* ---------------- */

#define hydro_sign_BYTES 64
#define hydro_sign_CONTEXTBYTES 8
#define hydro_sign_PUBLICKEYBYTES 32
#define hydro_sign_SECRETKEYBYTES 32
#define hydro_sign_SEEDBYTES 32

typedef struct hydro_sign_state {
    hydro_hash_state hash_st;
} hydro_sign_state;

typedef struct hydro_sign_keypair {
    uint8_t pk[hydro_sign_PUBLICKEYBYTES];
    uint8_t sk[hydro_sign_SECRETKEYBYTES];
} hydro_sign_keypair;

void hydro_sign_keygen(hydro_sign_keypair *kp);

void hydro_sign_keygen_deterministic(
    hydro_sign_keypair *kp, const uint8_t seed[hydro_sign_SEEDBYTES]);

int hydro_sign_init(
    hydro_sign_state *state, const char ctx[hydro_sign_CONTEXTBYTES]);

int hydro_sign_update(hydro_sign_state *state, const void *m_, size_t mlen);

int hydro_sign_final_create(hydro_sign_state *state,
    uint8_t                                   csig[hydro_sign_BYTES],
    const uint8_t                             sk[hydro_sign_SECRETKEYBYTES]);

int hydro_sign_final_verify(hydro_sign_state *state,
    const uint8_t                             csig[hydro_sign_BYTES],
    const uint8_t                             pk[hydro_sign_PUBLICKEYBYTES]);

int hydro_sign_create(uint8_t csig[hydro_sign_BYTES], const void *m_,
    size_t mlen, const char ctx[hydro_sign_CONTEXTBYTES],
    const uint8_t sk[hydro_sign_SECRETKEYBYTES]);

int hydro_sign_verify(const uint8_t csig[hydro_sign_BYTES], const void *m_,
    size_t mlen, const char ctx[hydro_sign_CONTEXTBYTES],
    const uint8_t pk[hydro_sign_PUBLICKEYBYTES]);

/* ---------------- */

void hydro_memzero(void *const pnt, size_t len);

void hydro_increment(uint8_t *n, size_t len);

bool hydro_equal(const void *b1_, const void *b2_, size_t len);

int hydro_compare(const uint8_t *b1_, const uint8_t *b2_, size_t len);

char *hydro_bin2hex(
    char *hex, size_t hex_maxlen, const uint8_t *bin, size_t bin_len);

int hydro_hex2bin(uint8_t *bin, size_t bin_maxlen, const char *hex,
    size_t hex_len, const char *ignore, size_t *bin_len, const char **hex_end);

/* ---------------- */

#define HYDRO_HWTYPE_ATMEGA328 1

#ifndef HYDRO_HWTYPE
#ifdef __AVR__
#define HYDRO_HWTYPE HYDRO_HWTYPE_ATMEGA328
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif

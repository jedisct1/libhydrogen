#ifndef hydrogen_H
#define hydrogen_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wlong-long"
#endif
extern "C" {
#endif

#define HYDRO_HWTYPE_ATMEGA328 1

#ifndef HYDRO_HWTYPE
#define HYDRO_HWTYPE HYDRO_HWTYPE_ATMEGA328
#endif

int hydro_init(void);

/* ---------------- */

#define randombytes_buf_deterministic_KEYBYTES 32

uint32_t randombytes_random(void);

uint32_t randombytes_uniform(const uint32_t upper_bound);

void randombytes_buf(void *const buf, const size_t size);

void randombytes_buf_deterministic(void *const buf, const size_t len,
    const uint8_t key[randombytes_buf_deterministic_KEYBYTES]);

/* ---------------- */

#define hydro_hash128_BYTES 16
#define hydro_hash128_KEYBYTES 16

typedef struct hydro_hash128_state {
    uint64_t v0, v1, v2, v3;
    uint8_t  mb[8];
    uint8_t  off;
    uint8_t  b;
} hydro_hash128_state;

void hydro_hash128_keygen(uint8_t key[hydro_hash128_KEYBYTES]);

int hydro_hash128_hash(uint8_t out[hydro_hash128_BYTES], const uint8_t *in,
    size_t inlen, const uint8_t key[hydro_hash128_KEYBYTES]);

int hydro_hash128_init(
    hydro_hash128_state *state, const uint8_t key[hydro_hash128_KEYBYTES]);

int hydro_hash128_update(
    hydro_hash128_state *state, const uint8_t *in, size_t inlen);

int hydro_hash128_final(
    hydro_hash128_state *state, uint8_t out[hydro_hash128_BYTES]);

/* ---------------- */

#define hydro_secretbox_KEYBYTES 32
#define hydro_secretbox_HEADERBYTES (20 + 16)

void hydro_secretbox_keygen(uint8_t key[hydro_secretbox_KEYBYTES]);

int hydro_secretbox_encrypt(uint8_t *c, const uint8_t *m, size_t mlen,
    const uint8_t key[hydro_secretbox_KEYBYTES]);

int hydro_secretbox_decrypt(uint8_t *m, const uint8_t *c, size_t clen,
    const uint8_t key[hydro_secretbox_KEYBYTES])
    __attribute__((warn_unused_result));

/* ---------------- */

void hydro_memzero(void *const pnt, size_t len);

void hydro_increment(uint8_t *n, size_t len);

_Bool hydro_equal(const void *b1_, const void *b2_, size_t len);

int hydro_compare(const uint8_t *b1_, const uint8_t *b2_, size_t len);

char *hydro_bin2hex(
    char *hex, size_t hex_maxlen, const uint8_t *bin, size_t bin_len);

int hydro_hex2bin(uint8_t *bin, size_t bin_maxlen, const char *hex,
    size_t hex_len, const char *ignore, size_t *bin_len, const char **hex_end);

#ifdef __cplusplus
}
#endif

#endif

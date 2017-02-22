#ifndef hydrogen_p_H
#define hydrogen_p_H

static int hydro_random_init(void);

/* ---------------- */

#define hydro_stream_chacha20_KEYBYTES 32
#define hydro_stream_chacha20_NONCEBYTES 12

#define hydro_stream_xchacha20_KEYBYTES 32
#define hydro_stream_xchacha20_NONCEBYTES 24

#define hydro_stream_chacha20_block_BYTES 64
#define hydro_stream_chacha20_block_KEYBYTES 32
#define hydro_stream_chacha20_block_NONCEBYTES 16

#define hydro_stream_hchacha20_BYTES 32
#define hydro_stream_hchacha20_KEYBYTES 32
#define hydro_stream_hchacha20_NONCEBYTES 16

static int
hydro_stream_chacha20(uint8_t *c, size_t len,
                      const uint8_t nonce[hydro_stream_chacha20_NONCEBYTES],
                      const uint8_t key[hydro_stream_chacha20_KEYBYTES]);

static int
hydro_stream_chacha20_xor(uint8_t *c, const uint8_t *m, size_t len,
                          const uint8_t nonce[hydro_stream_chacha20_NONCEBYTES],
                          const uint8_t key[hydro_stream_chacha20_KEYBYTES]);

static int hydro_stream_xchacha20_xor(
    uint8_t *c, const uint8_t *m, size_t len,
    const uint8_t nonce[hydro_stream_xchacha20_NONCEBYTES],
    const uint8_t key[hydro_stream_xchacha20_KEYBYTES]);

static void hydro_stream_chacha20_block(
    uint8_t       block[hydro_stream_chacha20_block_BYTES],
    const uint8_t nonce[hydro_stream_chacha20_block_NONCEBYTES],
    const uint8_t key[hydro_stream_chacha20_block_KEYBYTES]);

static void
hydro_stream_hchacha20(uint8_t       subkey[hydro_stream_hchacha20_BYTES],
                       const uint8_t nonce[hydro_stream_hchacha20_NONCEBYTES],
                       const uint8_t key[hydro_stream_hchacha20_KEYBYTES]);

/* ---------------- */

#define hydro_secretbox_NONCEBYTES 20
#define hydro_secretbox_MACBYTES 16

/* ---------------- */

#define hydro_x25519_BYTES 32
#define hydro_x25519_PUBLICKEYBYTES 32
#define hydro_x25519_SECRETKEYBYTES 32

static int hydro_x25519_scalarmult(uint8_t       out[hydro_x25519_BYTES],
                                   const uint8_t scalar[hydro_x25519_BYTES],
                                   const uint8_t x1[hydro_x25519_BYTES],
                                   bool          clamp)
    __attribute__((warn_unused_result));

static inline int
hydro_x25519_scalarmult_base(uint8_t       pk[hydro_x25519_PUBLICKEYBYTES],
                             const uint8_t sk[hydro_x25519_SECRETKEYBYTES])
    __attribute__((warn_unused_result));

static inline void hydro_x25519_scalarmult_base_uniform(
    uint8_t       pk[hydro_x25519_PUBLICKEYBYTES],
    const uint8_t sk[hydro_x25519_SECRETKEYBYTES]);

#endif

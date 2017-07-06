#define hydro_kx_AEAD_KEYBYTES hydro_hash_KEYBYTES
#define hydro_kx_AEAD_MACBYTES 16
#define hydro_kx_AEAD_HEADERBYTES hydro_kx_AEAD_MACBYTES

#define hydro_kx_CONTEXT "hydro_kx"
#define hydro_kx_CONTEXT_CK_K "kdf_ck_k"

static inline void
hydro_kx_mem_ct_zero_u32(uint32_t *dst_, size_t n)
{
    volatile uint32_t volatile * dst =
        (volatile uint32_t volatile *) (void *) dst_;
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = 0;
    }
}

static inline uint32_t
hydro_kx_mem_ct_cmp_u32(const uint32_t *b1_, const uint32_t *b2, size_t n)
__attribute__((warn_unused_result));

static inline uint32_t
hydro_kx_mem_ct_cmp_u32(const uint32_t *b1_, const uint32_t *b2, size_t n)
{
    const volatile uint32_t volatile * b1 =
        (const volatile uint32_t volatile *) (const void *) b1_;
    size_t   i;
    uint32_t cv = 0;

    for (i = 0; i < n; i++) {
        cv |= b1[i] ^ b2[i];
    }
    return cv;
}

void
hydro_kx_keygen(hydro_kx_keypair *static_kp)
{
    randombytes_buf(static_kp->sk, hydro_kx_SECRETKEYBYTES);
    if (hydro_x25519_scalarmult_base(static_kp->pk, static_kp->sk) != 0) {
        abort();
    }
}

static void
hydro_kx_aead_setup(uint8_t buf[gimli_BLOCKBYTES],
                    const hydro_kx_state *state,
                    const uint8_t psk[hydro_kx_PSKBYTES])
{
    static const uint8_t prefix[] = { 6, 'k', 'x', 'x', '2', '5', '6', 0 };

    mem_zero(buf + sizeof prefix, gimli_BLOCKBYTES - sizeof prefix);
    mem_cpy(buf, prefix, sizeof prefix);
    gimli_core_u8(buf);

    COMPILER_ASSERT(hydro_kx_AEAD_KEYBYTES == 2 * gimli_RATE);
    mem_xor(buf, state->k, gimli_RATE);
    gimli_core_u8(buf);
    mem_xor(buf, state->k + gimli_RATE, gimli_RATE);
    gimli_core_u8(buf);

    COMPILER_ASSERT(sizeof state->h == 2 * gimli_RATE);
    mem_xor(buf, state->h, gimli_RATE);
    gimli_core_u8(buf);
    mem_xor(buf, state->h + gimli_RATE, gimli_RATE);
    gimli_core_u8(buf);

    if (psk != NULL) {
        COMPILER_ASSERT(hydro_kx_PSKBYTES == 2 * gimli_RATE);
        mem_xor(buf, psk, gimli_RATE);
        gimli_core_u8(buf);
        mem_xor(buf, psk + gimli_RATE, gimli_RATE);
        gimli_core_u8(buf);
    }

    buf[0] ^= 0x1f;
    buf[gimli_RATE - 1] ^= 0x80;
    gimli_core_u8(buf);
}

static void
hydro_kx_aead_xor_enc(uint8_t buf[gimli_BLOCKBYTES],
                      uint8_t *out, const uint8_t *in, size_t inlen)
{
    size_t i;
    size_t leftover;

    for (i = 0; i < inlen / gimli_RATE; i++) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, gimli_RATE);
        mem_xor(buf, &in[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(buf);
    }
    leftover = inlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, leftover);
        mem_xor(buf, &in[i * gimli_RATE], leftover);
        gimli_core_u8(buf);
    }
}

static void
hydro_kx_aead_xor_dec(uint8_t buf[gimli_BLOCKBYTES],
                      uint8_t *out, const uint8_t *in, size_t inlen)
{
    size_t i;
    size_t leftover;

    for (i = 0; i < inlen / gimli_RATE; i++) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, gimli_RATE);
        mem_xor(buf, &out[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(buf);
    }
    leftover = inlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, leftover);
        mem_xor(buf, &out[i * gimli_RATE], leftover);
        gimli_core_u8(buf);
    }
}

static void
hydro_kx_encrypt(const hydro_kx_state *state, uint8_t *c, const uint8_t *m,
                 size_t mlen, const uint8_t psk[hydro_kx_PSKBYTES])
{
    uint8_t  buf[gimli_BLOCKBYTES];
    uint8_t *mac = &c[0];
    uint8_t *ct = &c[hydro_kx_AEAD_MACBYTES];

    hydro_kx_aead_setup(buf, state, psk);
    hydro_kx_aead_xor_enc(buf, ct, m, mlen);
    COMPILER_ASSERT(hydro_kx_AEAD_MACBYTES <= gimli_RATE);
    mem_cpy(mac, buf, hydro_kx_AEAD_MACBYTES);
}

static int hydro_kx_decrypt(hydro_kx_state *state, uint8_t *m, const uint8_t *c,
                            size_t clen, const uint8_t psk[hydro_kx_PSKBYTES])
    __attribute__((warn_unused_result));

static int
hydro_kx_decrypt(hydro_kx_state *state, uint8_t *m, const uint8_t *c,
                 size_t clen, const uint8_t psk[hydro_kx_PSKBYTES])
{
    uint32_t       pub_mac[hydro_kx_AEAD_MACBYTES / 4];
    uint32_t       int_state[gimli_BLOCKBYTES / 4];
    uint8_t       *buf = (uint8_t *) (void *) int_state;
    const uint8_t *mac = &c[0];
    const uint8_t *ct = &c[hydro_kx_AEAD_MACBYTES];
    size_t         mlen;
    uint32_t       cv;

    if (clen < hydro_kx_AEAD_HEADERBYTES) {
        return -1;
    }
    mlen = clen - hydro_kx_AEAD_HEADERBYTES;
    mem_cpy(pub_mac, mac, sizeof pub_mac);
    hydro_kx_aead_setup(buf, state, psk);
    hydro_kx_aead_xor_dec(buf, m, ct, mlen);
    COMPILER_ASSERT(hydro_kx_AEAD_MACBYTES <= gimli_RATE);
    cv = hydro_kx_mem_ct_cmp_u32(int_state, pub_mac, hydro_kx_AEAD_MACBYTES / 4);
    hydro_kx_mem_ct_zero_u32(int_state, gimli_BLOCKBYTES / 4);
    if (cv != 0) {
        mem_zero(m, mlen);
        return -1;
    }
    return 0;
}

static int
hydro_kx_scalarmult(hydro_kx_state *state, uint8_t dh_res[hydro_x25519_BYTES],
                    const uint8_t scalar[hydro_x25519_BYTES],
                    const uint8_t x1[hydro_x25519_BYTES])
{
    uint8_t ck_k[hydro_hash_BYTES + hydro_hash_KEYBYTES];

    if (hydro_x25519_scalarmult(dh_res, scalar, x1, 1) != 0) {
        return -1;
    }
    hydro_hash_hash(ck_k, sizeof ck_k, dh_res, hydro_x25519_BYTES,
                    hydro_kx_CONTEXT_CK_K, state->ck, sizeof state->ck);
    memcpy(state->ck, ck_k, sizeof state->ck);
    memcpy(state->k, ck_k + sizeof state->ck, sizeof state->k);

    return 0;
}

static void
hydro_kx_final(hydro_kx_state *state, uint8_t rx[hydro_kx_SESSIONKEYBYTES],
               uint8_t tx[hydro_kx_SESSIONKEYBYTES])
{
    COMPILER_ASSERT(hydro_kx_SESSIONKEYBYTES == hydro_kx_AEAD_KEYBYTES);
    COMPILER_ASSERT(hydro_kx_PUBLICKEYBYTES == hydro_x25519_BYTES);
    COMPILER_ASSERT(hydro_kx_SECRETKEYBYTES == hydro_x25519_BYTES);
    COMPILER_ASSERT(hydro_kx_PSKBYTES == hydro_hash_KEYBYTES);
    COMPILER_ASSERT(sizeof(state->h) == hydro_hash_BYTES);
    COMPILER_ASSERT(sizeof(state->ck) == hydro_hash_KEYBYTES);
    COMPILER_ASSERT(sizeof(state->k) == hydro_kx_AEAD_KEYBYTES);
    COMPILER_ASSERT(hydro_kx_RESPONSE1BYTES == hydro_kx_PUBLICKEYBYTES);
    COMPILER_ASSERT(hydro_kx_RESPONSE2BYTES ==
                    hydro_kx_PUBLICKEYBYTES + hydro_kx_AEAD_HEADERBYTES +
                        hydro_kx_PUBLICKEYBYTES);
    COMPILER_ASSERT(hydro_kx_RESPONSE3BYTES ==
                    hydro_kx_AEAD_HEADERBYTES + hydro_kx_PUBLICKEYBYTES);

    COMPILER_ASSERT(hydro_kdf_KEYBYTES == hydro_hash_BYTES);
    hydro_kdf_derive_from_key(rx, hydro_kx_SESSIONKEYBYTES, 0, hydro_kx_CONTEXT,
                              state->ck);
    hydro_kdf_derive_from_key(tx, hydro_kx_SESSIONKEYBYTES, 1, hydro_kx_CONTEXT,
                              state->ck);
    hydro_memzero(state, sizeof *state);
}

int
hydro_kx_xx_1(hydro_kx_state *state, uint8_t response1[hydro_kx_RESPONSE1BYTES],
              const uint8_t psk[hydro_kx_PSKBYTES])
{
    memset(state, 0, sizeof *state);

    hydro_kx_keygen(&state->eph_kp);
    hydro_hash_hash(state->h, sizeof state->h, state->eph_kp.pk,
                    sizeof state->eph_kp.pk, hydro_kx_CONTEXT, psk,
                    psk == NULL ? 0 : hydro_kx_PSKBYTES);
    memcpy(response1, state->eph_kp.pk, hydro_kx_PUBLICKEYBYTES);

    return 0;
}

int
hydro_kx_xx_2(hydro_kx_state *state, uint8_t response2[hydro_kx_RESPONSE2BYTES],
              const uint8_t           response1[hydro_kx_RESPONSE1BYTES],
              const uint8_t           psk[hydro_kx_PSKBYTES],
              const hydro_kx_keypair *static_kp)
{
    uint8_t        dh_res[hydro_x25519_BYTES];
    const uint8_t *peer_eph_pk = response1;

    memset(state, 0, sizeof *state);

    hydro_hash_hash(state->h, sizeof state->h, peer_eph_pk,
                    hydro_kx_PUBLICKEYBYTES, hydro_kx_CONTEXT, psk,
                    psk == NULL ? 0 : hydro_kx_PSKBYTES);
    hydro_kx_keygen(&state->eph_kp);
    memcpy(response2, state->eph_kp.pk, sizeof state->eph_kp.pk);
    hydro_hash_hash(state->h, sizeof state->h, state->eph_kp.pk,
                    sizeof state->eph_kp.pk, hydro_kx_CONTEXT, state->h,
                    sizeof state->h);

    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_eph_pk) !=
        0) {
        return -1;
    }
    hydro_kx_encrypt(state, response2 + sizeof state->eph_kp.pk, static_kp->pk,
                     sizeof static_kp->pk, psk);
    if (hydro_kx_scalarmult(state, dh_res, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    return 0;
}

int
hydro_kx_xx_3(hydro_kx_state *state, hydro_kx_session_keypair *kp,
              uint8_t                 response3[hydro_kx_RESPONSE3BYTES],
              uint8_t                 peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const uint8_t           response2[hydro_kx_RESPONSE2BYTES],
              const uint8_t           psk[hydro_kx_PSKBYTES],
              const hydro_kx_keypair *static_kp)
{
    uint8_t        dh_res[hydro_x25519_BYTES];
    uint8_t        peer_static_pk_[hydro_kx_PUBLICKEYBYTES];
    const uint8_t *peer_eph_pk = response2;
    const uint8_t *peer_encrypted_static_pk =
        response2 + hydro_kx_PUBLICKEYBYTES;

    hydro_hash_hash(state->h, sizeof state->h, peer_eph_pk,
                    hydro_kx_PUBLICKEYBYTES, hydro_kx_CONTEXT, state->h,
                    sizeof state->h);

    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_eph_pk) !=
        0) {
        return -1;
    }
    if (peer_static_pk == NULL) {
        peer_static_pk = peer_static_pk_;
    }
    if (hydro_kx_decrypt(state, peer_static_pk, peer_encrypted_static_pk,
                         hydro_kx_AEAD_HEADERBYTES + hydro_kx_PUBLICKEYBYTES,
                         psk) != 0) {
        return -1;
    }
    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_static_pk) !=
        0) {
        return -1;
    }
    hydro_kx_encrypt(state, response3, static_kp->pk, sizeof static_kp->pk,
                     psk);
    if (hydro_kx_scalarmult(state, dh_res, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_kx_final(state, kp->rx, kp->tx);

    return 0;
}

int
hydro_kx_xx_4(hydro_kx_state *state, hydro_kx_session_keypair *kp,
              uint8_t       peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const uint8_t response3[hydro_kx_RESPONSE3BYTES],
              const uint8_t psk[hydro_kx_PSKBYTES])
{
    uint8_t        dh_res[hydro_x25519_BYTES];
    uint8_t        peer_static_pk_[hydro_kx_PUBLICKEYBYTES];
    const uint8_t *peer_encrypted_static_pk = response3;

    if (peer_static_pk == NULL) {
        peer_static_pk = peer_static_pk_;
    }
    if (hydro_kx_decrypt(state, peer_static_pk, peer_encrypted_static_pk,
                         hydro_kx_AEAD_HEADERBYTES + hydro_kx_PUBLICKEYBYTES,
                         psk) != 0) {
        return -1;
    }
    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_static_pk) !=
        0) {
        return -1;
    }
    hydro_kx_final(state, kp->tx, kp->rx);

    return 0;
}

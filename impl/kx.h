#define hydro_kx_AEAD_KEYBYTES hydro_hash_KEYBYTES
#define hydro_kx_AEAD_MACBYTES 16
#define hydro_kx_AEAD_HEADERBYTES hydro_kx_AEAD_MACBYTES

#define hydro_kx_CONTEXT "hydro_kx"
#define hydro_kx_CONTEXT_CK_K "kdf_ck_k"

void
hydro_kx_keygen(hydro_kx_keypair *static_kp)
{
    hydro_random_buf(static_kp->sk, hydro_kx_SECRETKEYBYTES);
    if (hydro_x25519_scalarmult_base(static_kp->pk, static_kp->sk) != 0) {
        abort();
    }
}

void
hydro_kx_keygen_deterministic(hydro_kx_keypair *static_kp, const uint8_t seed[hydro_kx_SEEDBYTES])
{
    COMPILER_ASSERT(hydro_kx_SEEDBYTES >= hydro_random_SEEDBYTES);
    hydro_random_buf_deterministic(static_kp->sk, hydro_kx_SECRETKEYBYTES, seed);
    if (hydro_x25519_scalarmult_base(static_kp->pk, static_kp->sk) != 0) {
        abort();
    }
}

static void
hydro_kx_aead_setup(uint8_t buf[gimli_BLOCKBYTES], const hydro_kx_state *state,
                    const uint8_t psk[hydro_kx_PSKBYTES])
{
    static const uint8_t prefix[] = { 6, 'k', 'x', 'x', '2', '5', '6', 0 };

    mem_zero(buf + sizeof prefix, gimli_BLOCKBYTES - sizeof prefix);
    memcpy(buf, prefix, sizeof prefix);
    gimli_core_u8(buf, gimli_TAG_HEADER);

    COMPILER_ASSERT(hydro_kx_AEAD_KEYBYTES == 2 * gimli_RATE);
    mem_xor(buf, state->k, gimli_RATE);
    gimli_core_u8(buf, gimli_TAG_KEY);
    mem_xor(buf, state->k + gimli_RATE, gimli_RATE);
    gimli_core_u8(buf, gimli_TAG_KEY);

    COMPILER_ASSERT(sizeof state->h == 2 * gimli_RATE);
    mem_xor(buf, state->h, gimli_RATE);
    gimli_core_u8(buf, gimli_TAG_HEADER);
    mem_xor(buf, state->h + gimli_RATE, gimli_RATE);
    gimli_core_u8(buf, gimli_TAG_HEADER);

    if (psk != NULL) {
        COMPILER_ASSERT(hydro_kx_PSKBYTES == 2 * gimli_RATE);
        mem_xor(buf, psk, gimli_RATE);
        gimli_core_u8(buf, gimli_TAG_HEADER);
        mem_xor(buf, psk + gimli_RATE, gimli_RATE);
        gimli_core_u8(buf, gimli_TAG_HEADER);
    }
}

static void
hydro_kx_finalize(uint8_t *buf, const uint8_t key[hydro_kx_AEAD_KEYBYTES])
{
    COMPILER_ASSERT(hydro_kx_AEAD_KEYBYTES == gimli_CAPACITY);
    mem_xor(buf + gimli_RATE, key, hydro_kx_AEAD_KEYBYTES);
    gimli_core_u8(buf, gimli_TAG_FINAL);
    mem_xor(buf + gimli_RATE, key, hydro_kx_AEAD_KEYBYTES);
    gimli_core_u8(buf, gimli_TAG_FINAL);
}

static void
hydro_kx_aead_xor_enc(uint8_t buf[gimli_BLOCKBYTES], uint8_t *out, const uint8_t *in, size_t inlen)
{
    size_t i;
    size_t leftover;

    for (i = 0; i < inlen / gimli_RATE; i++) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, gimli_RATE);
        memcpy(buf, &out[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(buf, gimli_TAG_PAYLOAD);
    }
    leftover = inlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, leftover);
        mem_cpy(buf, &out[i * gimli_RATE], leftover);
    }
    gimli_pad_u8(buf, leftover, gimli_DOMAIN_AEAD);
    gimli_core_u8(buf, gimli_TAG_PAYLOAD);
}

static void
hydro_kx_aead_xor_dec(uint8_t buf[gimli_BLOCKBYTES], uint8_t *out, const uint8_t *in, size_t inlen)
{
    size_t i;
    size_t leftover;

    for (i = 0; i < inlen / gimli_RATE; i++) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, gimli_RATE);
        memcpy(buf, &in[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(buf, gimli_TAG_PAYLOAD);
    }
    leftover = inlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor2(&out[i * gimli_RATE], &in[i * gimli_RATE], buf, leftover);
        mem_cpy(buf, &in[i * gimli_RATE], leftover);
    }
    gimli_pad_u8(buf, leftover, gimli_DOMAIN_AEAD);
    gimli_core_u8(buf, gimli_TAG_PAYLOAD);
}

static void
hydro_kx_encrypt(const hydro_kx_state *state, uint8_t *c, const uint8_t *m, size_t mlen,
                 const uint8_t psk[hydro_kx_PSKBYTES])
{
    _hydro_attr_aligned_(16) uint8_t buf[gimli_BLOCKBYTES];
    uint8_t *                        mac = &c[0];
    uint8_t *                        ct  = &c[hydro_kx_AEAD_MACBYTES];

    hydro_kx_aead_setup(buf, state, psk);
    hydro_kx_aead_xor_enc(buf, ct, m, mlen);

    hydro_kx_finalize(buf, state->k);
    COMPILER_ASSERT(hydro_kx_AEAD_MACBYTES <= gimli_CAPACITY);
    memcpy(mac, buf + gimli_RATE, hydro_kx_AEAD_MACBYTES);
}

static int hydro_kx_decrypt(hydro_kx_state *state, uint8_t *m, const uint8_t *c, size_t clen,
                            const uint8_t psk[hydro_kx_PSKBYTES]) _hydro_attr_warn_unused_result_;

static int
hydro_kx_decrypt(hydro_kx_state *state, uint8_t *m, const uint8_t *c, size_t clen,
                 const uint8_t psk[hydro_kx_PSKBYTES])
{
    _hydro_attr_aligned_(16) uint32_t int_state[gimli_BLOCKBYTES / 4];
    uint32_t                          pub_mac[hydro_kx_AEAD_MACBYTES / 4];
    uint8_t *                         buf = (uint8_t *) (void *) int_state;
    const uint8_t *                   mac;
    const uint8_t *                   ct;
    size_t                            mlen;
    uint32_t                          cv;

    if (clen < hydro_kx_AEAD_HEADERBYTES) {
        return -1;
    }
    mac  = &c[0];
    ct   = &c[hydro_kx_AEAD_MACBYTES];
    mlen = clen - hydro_kx_AEAD_HEADERBYTES;
    memcpy(pub_mac, mac, sizeof pub_mac);
    hydro_kx_aead_setup(buf, state, psk);
    hydro_kx_aead_xor_dec(buf, m, ct, mlen);

    hydro_kx_finalize(buf, state->k);
    COMPILER_ASSERT(hydro_kx_AEAD_MACBYTES <= gimli_CAPACITY);
    COMPILER_ASSERT(gimli_RATE % 4 == 0);
    cv = hydro_mem_ct_cmp_u32(int_state + gimli_RATE / 4, pub_mac, hydro_kx_AEAD_MACBYTES / 4);
    hydro_mem_ct_zero_u32(int_state, gimli_BLOCKBYTES / 4);
    if (cv != 0) {
        mem_zero(m, mlen);
        return -1;
    }
    return 0;
}

static int
hydro_kx_scalarmult(hydro_kx_state *state, uint8_t dh_res[hydro_x25519_BYTES],
                    const uint8_t scalar[hydro_x25519_BYTES], const uint8_t x1[hydro_x25519_BYTES])
{
    uint8_t ck_k[hydro_hash_BYTES + hydro_hash_KEYBYTES];

    if (hydro_x25519_scalarmult(dh_res, scalar, x1, 1) != 0) {
        return -1;
    }
    COMPILER_ASSERT(sizeof state->ck >= hydro_hash_KEYBYTES);
    hydro_hash_hash(ck_k, sizeof ck_k, dh_res, hydro_x25519_BYTES, hydro_kx_CONTEXT_CK_K,
                    state->ck);
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
    COMPILER_ASSERT(hydro_kx_XX_PACKET1BYTES == hydro_kx_PUBLICKEYBYTES);
    COMPILER_ASSERT(hydro_kx_XX_PACKET2BYTES ==
                    hydro_kx_PUBLICKEYBYTES + hydro_kx_AEAD_HEADERBYTES + hydro_kx_PUBLICKEYBYTES);
    COMPILER_ASSERT(hydro_kx_XX_PACKET3BYTES ==
                    hydro_kx_AEAD_HEADERBYTES + hydro_kx_PUBLICKEYBYTES);

    COMPILER_ASSERT(hydro_kdf_KEYBYTES == hydro_hash_BYTES);
    hydro_kdf_derive_from_key(rx, hydro_kx_SESSIONKEYBYTES, 0, hydro_kx_CONTEXT, state->ck);
    hydro_kdf_derive_from_key(tx, hydro_kx_SESSIONKEYBYTES, 1, hydro_kx_CONTEXT, state->ck);
    hydro_memzero(state, sizeof *state);
}

/* NOISE_N */

int
hydro_kx_n_1(hydro_kx_session_keypair *kp, uint8_t packet1[hydro_kx_N_PACKET1BYTES],
             const uint8_t psk[hydro_kx_PSKBYTES],
             const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES])
{
    hydro_kx_state state;
    uint8_t        dh_res[hydro_x25519_BYTES];

    mem_zero(&state, sizeof state);

    hydro_kx_keygen(&state.eph_kp);
    COMPILER_ASSERT(hydro_kx_PSKBYTES >= hydro_hash_KEYBYTES);
    hydro_hash_hash(state.h, sizeof state.h, peer_static_pk, hydro_kx_PUBLICKEYBYTES,
                    hydro_kx_CONTEXT, psk);
    memcpy(packet1, state.eph_kp.pk, hydro_kx_PUBLICKEYBYTES);

    COMPILER_ASSERT(sizeof state.h >= hydro_hash_KEYBYTES);
    hydro_hash_hash(state.h, sizeof state.h, state.eph_kp.pk, sizeof state.eph_kp.pk,
                    hydro_kx_CONTEXT, state.h);

    if (hydro_kx_scalarmult(&state, dh_res, state.eph_kp.sk, peer_static_pk) != 0) {
        return -1;
    }
    hydro_kx_final(&state, kp->rx, kp->tx);

    return 0;
}

int
hydro_kx_n_2(hydro_kx_session_keypair *kp, const uint8_t packet1[hydro_kx_N_PACKET1BYTES],
             const uint8_t psk[hydro_kx_PSKBYTES], const hydro_kx_keypair *static_kp)
{
    hydro_kx_state state;
    uint8_t        dh_res[hydro_x25519_BYTES];
    const uint8_t *peer_eph_pk = packet1;

    mem_zero(&state, sizeof state);

    COMPILER_ASSERT(hydro_kx_PSKBYTES >= hydro_hash_KEYBYTES);
    hydro_hash_hash(state.h, sizeof state.h, static_kp->pk, sizeof static_kp->pk, hydro_kx_CONTEXT,
                    psk);

    COMPILER_ASSERT(sizeof state.h >= hydro_hash_KEYBYTES);
    hydro_hash_hash(state.h, sizeof state.h, peer_eph_pk, hydro_kx_PUBLICKEYBYTES, hydro_kx_CONTEXT,
                    state.h);

    if (hydro_kx_scalarmult(&state, dh_res, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_kx_final(&state, kp->tx, kp->rx);

    return 0;
}

/* NOISE_KK */

int
hydro_kx_kk_1(hydro_kx_state *state, uint8_t packet1[hydro_kx_KK_PACKET1BYTES],
              const uint8_t           peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const hydro_kx_keypair *static_kp)
{
    uint8_t dh_res[hydro_x25519_BYTES];
    mem_zero(state, sizeof *state);

    hydro_kx_keygen(&state->eph_kp);
    hydro_hash_hash(state->h, sizeof state->h, state->eph_kp.pk, sizeof state->eph_kp.pk,
                    hydro_kx_CONTEXT, NULL);
    memcpy(packet1, state->eph_kp.pk, sizeof state->eph_kp.pk);

    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_static_pk) != 0) {
        return -1;
    }
    if (hydro_kx_scalarmult(state, dh_res, static_kp->sk, peer_static_pk) != 0) {
        return -1;
    }
    return 0;
}

int
hydro_kx_kk_2(hydro_kx_session_keypair *kp, uint8_t packet2[hydro_kx_KK_PACKET2BYTES],
              const uint8_t           packet1[hydro_kx_KK_PACKET1BYTES],
              const uint8_t           peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const hydro_kx_keypair *static_kp)
{
    hydro_kx_state state;
    uint8_t        dh_res[hydro_x25519_BYTES];
    const uint8_t *peer_eph_pk = packet1;

    mem_zero(&state, sizeof state);

    hydro_kx_keygen(&state.eph_kp);
    hydro_hash_hash(state.h, sizeof state.h, state.eph_kp.pk, sizeof state.eph_kp.pk,
                    hydro_kx_CONTEXT, NULL);
    memcpy(packet2, state.eph_kp.pk, sizeof state.eph_kp.pk);

    if (hydro_kx_scalarmult(&state, dh_res, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    if (hydro_kx_scalarmult(&state, dh_res, static_kp->sk, peer_static_pk) != 0) {
        return -1;
    }

    if (hydro_kx_scalarmult(&state, dh_res, state.eph_kp.sk, peer_eph_pk) != 0) {
        return -1;
    }
    if (hydro_kx_scalarmult(&state, dh_res, state.eph_kp.sk, peer_static_pk) != 0) {
        return -1;
    }
    hydro_kx_final(&state, kp->rx, kp->tx);

    return 0;
}

int
hydro_kx_kk_3(hydro_kx_state *state, hydro_kx_session_keypair *kp,
              const uint8_t packet2[hydro_kx_KK_PACKET2BYTES],
              const hydro_kx_keypair *static_kp)
{
    uint8_t        dh_res[hydro_x25519_BYTES];
    const uint8_t *peer_eph_pk = packet2;

    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_eph_pk) != 0) {
        return -1;
    }
    if (hydro_kx_scalarmult(state, dh_res, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_kx_final(state, kp->tx, kp->rx);

    return 0;
}

/* NOISE_XX */

int
hydro_kx_xx_1(hydro_kx_state *state, uint8_t packet1[hydro_kx_XX_PACKET1BYTES],
              const uint8_t psk[hydro_kx_PSKBYTES])
{
    mem_zero(state, sizeof *state);

    hydro_kx_keygen(&state->eph_kp);
    COMPILER_ASSERT(hydro_kx_PSKBYTES >= hydro_hash_KEYBYTES);
    hydro_hash_hash(state->h, sizeof state->h, state->eph_kp.pk, sizeof state->eph_kp.pk,
                    hydro_kx_CONTEXT, psk);
    memcpy(packet1, state->eph_kp.pk, hydro_kx_PUBLICKEYBYTES);

    return 0;
}

int
hydro_kx_xx_2(hydro_kx_state *state, uint8_t packet2[hydro_kx_XX_PACKET2BYTES],
              const uint8_t packet1[hydro_kx_XX_PACKET1BYTES], const uint8_t psk[hydro_kx_PSKBYTES],
              const hydro_kx_keypair *static_kp)
{
    uint8_t        dh_res[hydro_x25519_BYTES];
    const uint8_t *peer_eph_pk = packet1;

    mem_zero(state, sizeof *state);

    hydro_hash_hash(state->h, sizeof state->h, peer_eph_pk, hydro_kx_PUBLICKEYBYTES,
                    hydro_kx_CONTEXT, psk);
    hydro_kx_keygen(&state->eph_kp);
    memcpy(packet2, state->eph_kp.pk, sizeof state->eph_kp.pk);
    COMPILER_ASSERT(sizeof state->h >= hydro_hash_KEYBYTES);
    hydro_hash_hash(state->h, sizeof state->h, state->eph_kp.pk, sizeof state->eph_kp.pk,
                    hydro_kx_CONTEXT, state->h);

    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_kx_encrypt(state, packet2 + sizeof state->eph_kp.pk, static_kp->pk, sizeof static_kp->pk,
                     psk);
    if (hydro_kx_scalarmult(state, dh_res, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    return 0;
}

int
hydro_kx_xx_3(hydro_kx_state *state, hydro_kx_session_keypair *kp,
              uint8_t       packet3[hydro_kx_XX_PACKET3BYTES],
              uint8_t       peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const uint8_t packet2[hydro_kx_XX_PACKET2BYTES], const uint8_t psk[hydro_kx_PSKBYTES],
              const hydro_kx_keypair *static_kp)
{
    uint8_t        dh_res[hydro_x25519_BYTES];
    uint8_t        peer_static_pk_[hydro_kx_PUBLICKEYBYTES];
    const uint8_t *peer_eph_pk              = packet2;
    const uint8_t *peer_encrypted_static_pk = packet2 + hydro_kx_PUBLICKEYBYTES;

    hydro_hash_hash(state->h, sizeof state->h, peer_eph_pk, hydro_kx_PUBLICKEYBYTES,
                    hydro_kx_CONTEXT, state->h);

    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_eph_pk) != 0) {
        return -1;
    }
    if (peer_static_pk == NULL) {
        peer_static_pk = peer_static_pk_;
    }
    if (hydro_kx_decrypt(state, peer_static_pk, peer_encrypted_static_pk,
                         hydro_kx_AEAD_HEADERBYTES + hydro_kx_PUBLICKEYBYTES, psk) != 0) {
        return -1;
    }
    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_static_pk) != 0) {
        return -1;
    }
    hydro_kx_encrypt(state, packet3, static_kp->pk, sizeof static_kp->pk, psk);
    if (hydro_kx_scalarmult(state, dh_res, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_kx_final(state, kp->rx, kp->tx);

    return 0;
}

int
hydro_kx_xx_4(hydro_kx_state *state, hydro_kx_session_keypair *kp,
              uint8_t       peer_static_pk[hydro_kx_PUBLICKEYBYTES],
              const uint8_t packet3[hydro_kx_XX_PACKET3BYTES], const uint8_t psk[hydro_kx_PSKBYTES])
{
    uint8_t        dh_res[hydro_x25519_BYTES];
    uint8_t        peer_static_pk_[hydro_kx_PUBLICKEYBYTES];
    const uint8_t *peer_encrypted_static_pk = packet3;

    if (peer_static_pk == NULL) {
        peer_static_pk = peer_static_pk_;
    }
    if (hydro_kx_decrypt(state, peer_static_pk, peer_encrypted_static_pk,
                         hydro_kx_AEAD_HEADERBYTES + hydro_kx_PUBLICKEYBYTES, psk) != 0) {
        return -1;
    }
    if (hydro_kx_scalarmult(state, dh_res, state->eph_kp.sk, peer_static_pk) != 0) {
        return -1;
    }
    hydro_kx_final(state, kp->tx, kp->rx);

    return 0;
}

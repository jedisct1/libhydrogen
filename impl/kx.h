
#define hydro_dh_AEAD_KEYBYTES hydro_hash_KEYBYTES
#define hydro_dh_AEAD_MACBYTES 16
#define hydro_dh_AEAD_HEADERBYTES hydro_dh_AEAD_MACBYTES

#define hydro_dh_CONTEXT "hydro_dh"
#define hydro_dh_CONTEXT_CK_K "kdf_ck_k"

void hydro_dh_keygen(hydro_dh_keypair *kp)
{
    randombytes_buf(kp->sk, hydro_dh_SECRETKEYBYTES);
    if (hydro_x25519_scalarmult_base(kp->pk, kp->sk) != 0) {
        abort();
    }
}

static void hydro_dh_encrypt(hydro_dh_state *state, uint8_t *c,
    const uint8_t *m, size_t mlen, const uint8_t psk[hydro_dh_PSKBYTES])
{
    uint8_t        keys[hydro_stream_chacha20_KEYBYTES + hydro_hash_KEYBYTES];
    const uint8_t *ek = &keys[0];
    const uint8_t *mk = &keys[hydro_stream_chacha20_KEYBYTES];

    hydro_hash_hash(keys, sizeof keys, state->h, sizeof state->h,
        hydro_dh_CONTEXT, state->k, sizeof state->k);
    hydro_stream_chacha20_xor(c + hydro_dh_AEAD_HEADERBYTES, m, mlen, zero, ek);
    hydro_hash_hash(c, hydro_dh_AEAD_MACBYTES, c + hydro_dh_AEAD_HEADERBYTES,
        mlen, hydro_dh_CONTEXT, mk, hydro_hash_KEYBYTES);

    hydro_hash_hash(state->h, sizeof state->h, c, hydro_dh_AEAD_MACBYTES + mlen,
        hydro_dh_CONTEXT, psk, psk == NULL ? 0 : hydro_dh_PSKBYTES);
}

static int hydro_dh_decrypt(hydro_dh_state *state, uint8_t *m, const uint8_t *c,
    size_t clen, const uint8_t psk[hydro_dh_PSKBYTES])
    __attribute__((warn_unused_result));

static int hydro_dh_decrypt(hydro_dh_state *state, uint8_t *m, const uint8_t *c,
    size_t clen, const uint8_t psk[hydro_dh_PSKBYTES])
{
    uint8_t        keys[hydro_stream_chacha20_KEYBYTES + hydro_hash_KEYBYTES];
    uint8_t        mac[hydro_dh_AEAD_MACBYTES];
    const uint8_t *ek = &keys[0];
    const uint8_t *mk = &keys[hydro_stream_chacha20_KEYBYTES];
    size_t         mlen;

    if (clen < hydro_dh_AEAD_HEADERBYTES) {
        return -1;
    }
    mlen = clen - hydro_dh_AEAD_HEADERBYTES;
    hydro_hash_hash(keys, sizeof keys, state->h, sizeof state->h,
        hydro_dh_CONTEXT, state->k, sizeof state->k);
    hydro_hash_hash(mac, sizeof mac, c + hydro_dh_AEAD_HEADERBYTES, mlen,
        hydro_dh_CONTEXT, mk, hydro_hash_KEYBYTES);
    if (!hydro_equal(mac, c, hydro_dh_AEAD_MACBYTES)) {
        return -1;
    }
    hydro_stream_chacha20_xor(m, c + hydro_dh_AEAD_HEADERBYTES, mlen, zero, ek);
    hydro_hash_hash(state->h, sizeof state->h, c, clen, hydro_dh_CONTEXT, psk,
        psk == NULL ? 0 : hydro_dh_PSKBYTES);

    return 0;
}

static int hydro_dh_scalarmult(hydro_dh_state *state,
    uint8_t                                    dh_res[hydro_x25519_BYTES],
    const uint8_t                              scalar[hydro_x25519_BYTES],
    const uint8_t                              x1[hydro_x25519_BYTES])
{
    uint8_t ck_k[hydro_hash_BYTES + hydro_hash_KEYBYTES];

    if (hydro_x25519_scalarmult(dh_res, scalar, x1, 1) != 0) {
        return -1;
    }
    hydro_hash_hash(ck_k, sizeof ck_k, dh_res, hydro_x25519_BYTES,
        hydro_dh_CONTEXT_CK_K, state->ck, sizeof state->ck);
    memcpy(state->ck, ck_k, sizeof state->ck);
    memcpy(state->k, ck_k + sizeof state->ck, sizeof state->k);

    return 0;
}

static void hydro_dh_final(hydro_dh_state *state,
    uint8_t rx[hydro_dh_SESSIONKEYBYTES], uint8_t tx[hydro_dh_SESSIONKEYBYTES])
{
    COMPILER_ASSERT(hydro_dh_SESSIONKEYBYTES == hydro_secretbox_KEYBYTES);
    COMPILER_ASSERT(hydro_dh_PUBLICKEYBYTES == hydro_x25519_BYTES);
    COMPILER_ASSERT(hydro_dh_SECRETKEYBYTES == hydro_x25519_BYTES);
    COMPILER_ASSERT(hydro_dh_PSKBYTES == hydro_hash_KEYBYTES);
    COMPILER_ASSERT(sizeof(state->h) == hydro_hash_BYTES);
    COMPILER_ASSERT(sizeof(state->ck) == hydro_hash_KEYBYTES);
    COMPILER_ASSERT(sizeof(state->k) == hydro_dh_AEAD_KEYBYTES);
    COMPILER_ASSERT(hydro_dh_RESPONSE1BYTES == hydro_dh_PUBLICKEYBYTES);
    COMPILER_ASSERT(hydro_dh_RESPONSE2BYTES ==
                    hydro_dh_PUBLICKEYBYTES + hydro_dh_AEAD_HEADERBYTES +
                        hydro_dh_PUBLICKEYBYTES);
    COMPILER_ASSERT(hydro_dh_RESPONSE3BYTES ==
                    hydro_dh_AEAD_HEADERBYTES + hydro_dh_PUBLICKEYBYTES);

    COMPILER_ASSERT(hydro_kdf_KEYBYTES == hydro_hash_BYTES);
    hydro_kdf_derive_from_key(
        rx, hydro_dh_SESSIONKEYBYTES, 0, hydro_dh_CONTEXT, state->ck);
    hydro_kdf_derive_from_key(
        tx, hydro_dh_SESSIONKEYBYTES, 1, hydro_dh_CONTEXT, state->ck);
    hydro_memzero(state, sizeof *state);
}

int hydro_dh_xx_1(hydro_dh_state *state,
    uint8_t                       response1[hydro_dh_RESPONSE1BYTES],
    const uint8_t                 psk[hydro_dh_PSKBYTES])
{
    memset(state, 0, sizeof *state);

    hydro_dh_keygen(&state->eph_kp);
    hydro_hash_hash(state->h, sizeof state->h, state->eph_kp.pk,
        sizeof state->eph_kp.pk, hydro_dh_CONTEXT, psk,
        psk == NULL ? 0 : hydro_dh_PSKBYTES);
    memcpy(response1, state->eph_kp.pk, hydro_dh_PUBLICKEYBYTES);

    return 0;
}

int hydro_dh_xx_2(hydro_dh_state *state,
    uint8_t                       response2[hydro_dh_RESPONSE2BYTES],
    const uint8_t                 response1[hydro_dh_PUBLICKEYBYTES],
    const uint8_t psk[hydro_dh_PSKBYTES], const hydro_dh_keypair *static_kp)
{
    uint8_t        dh_res[hydro_x25519_BYTES];
    const uint8_t *peer_eph_pk = response1;

    memset(state, 0, sizeof *state);

    hydro_hash_hash(state->h, sizeof state->h, peer_eph_pk,
        hydro_dh_PUBLICKEYBYTES, hydro_dh_CONTEXT, psk,
        psk == NULL ? 0 : hydro_dh_PSKBYTES);
    hydro_dh_keygen(&state->eph_kp);
    memcpy(response2, state->eph_kp.pk, sizeof state->eph_kp.pk);
    hydro_hash_hash(state->h, sizeof state->h, state->eph_kp.pk,
        sizeof state->eph_kp.pk, hydro_dh_CONTEXT, state->h, sizeof state->h);

    if (hydro_dh_scalarmult(state, dh_res, state->eph_kp.sk, peer_eph_pk) !=
        0) {
        return -1;
    }
    hydro_dh_encrypt(state, response2 + sizeof state->eph_kp.pk, static_kp->pk,
        sizeof static_kp->pk, psk);
    if (hydro_dh_scalarmult(state, dh_res, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    return 0;
}

int hydro_dh_xx_3(hydro_dh_state *state, hydro_dh_session_keypair *kp,
    uint8_t       response3[hydro_dh_RESPONSE3BYTES],
    uint8_t       peer_static_pk[hydro_dh_PUBLICKEYBYTES],
    const uint8_t response2[hydro_dh_RESPONSE2BYTES],
    const uint8_t psk[hydro_dh_PSKBYTES], const hydro_dh_keypair *static_kp)
{

    uint8_t        dh_res[hydro_x25519_BYTES];
    uint8_t        peer_static_pk_[hydro_dh_PUBLICKEYBYTES];
    const uint8_t *peer_eph_pk = response2;
    const uint8_t *peer_encrypted_static_pk =
        response2 + hydro_dh_PUBLICKEYBYTES;

    hydro_hash_hash(state->h, sizeof state->h, peer_eph_pk,
        hydro_dh_PUBLICKEYBYTES, hydro_dh_CONTEXT, state->h, sizeof state->h);

    if (hydro_dh_scalarmult(state, dh_res, state->eph_kp.sk, peer_eph_pk) !=
        0) {
        return -1;
    }
    if (peer_static_pk == NULL) {
        peer_static_pk = peer_static_pk_;
    }
    if (hydro_dh_decrypt(state, peer_static_pk, peer_encrypted_static_pk,
            hydro_dh_AEAD_HEADERBYTES + hydro_dh_PUBLICKEYBYTES, psk) != 0) {
        return -1;
    }
    if (hydro_dh_scalarmult(state, dh_res, state->eph_kp.sk, peer_static_pk) !=
        0) {
        return -1;
    }
    hydro_dh_encrypt(
        state, response3, static_kp->pk, sizeof static_kp->pk, psk);
    if (hydro_dh_scalarmult(state, dh_res, static_kp->sk, peer_eph_pk) != 0) {
        return -1;
    }
    hydro_dh_final(state, kp->rx, kp->tx);

    return 0;
}

int hydro_dh_xx_4(hydro_dh_state *state, hydro_dh_session_keypair *kp,
    uint8_t       peer_static_pk[hydro_dh_PUBLICKEYBYTES],
    const uint8_t response3[hydro_dh_RESPONSE3BYTES],
    const uint8_t psk[hydro_dh_PSKBYTES])
{
    uint8_t        dh_res[hydro_x25519_BYTES];
    uint8_t        peer_static_pk_[hydro_dh_PUBLICKEYBYTES];
    const uint8_t *peer_encrypted_static_pk = response3;

    if (peer_static_pk == NULL) {
        peer_static_pk = peer_static_pk_;
    }
    if (hydro_dh_decrypt(state, peer_static_pk, peer_encrypted_static_pk,
            hydro_dh_AEAD_HEADERBYTES + hydro_dh_PUBLICKEYBYTES, psk) != 0) {
        return -1;
    }
    if (hydro_dh_scalarmult(state, dh_res, state->eph_kp.sk, peer_static_pk) !=
        0) {
        return -1;
    }
    hydro_dh_final(state, kp->tx, kp->rx);

    return 0;
}

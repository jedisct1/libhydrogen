#define hydro_kx_AEAD_KEYBYTES hydro_hash_KEYBYTES
#define hydro_kx_AEAD_MACBYTES 16
#define hydro_kx_AEAD_HEADERBYTES hydro_kx_AEAD_MACBYTES

#define hydro_kx_CONTEXT "hydro_kx"
#define hydro_kx_CONTEXT_CK_K "kdf_ck_k"

void
hydro_kx_keygen(hydro_kx_keypair *static_kp)
{
    randombytes_buf(static_kp->sk, hydro_kx_SECRETKEYBYTES);
    if (hydro_x25519_scalarmult_base(static_kp->pk, static_kp->sk) != 0) {
        abort();
    }
}

static void
hydro_kx_encrypt(hydro_kx_state *state, uint8_t *c, const uint8_t *m,
                 size_t mlen, const uint8_t psk[hydro_kx_PSKBYTES])
{
    uint8_t        keys[hydro_stream_chacha20_KEYBYTES + hydro_hash_KEYBYTES];
    const uint8_t *ek = &keys[0];
    const uint8_t *mk = &keys[hydro_stream_chacha20_KEYBYTES];

    hydro_hash_hash(keys, sizeof keys, state->h, sizeof state->h,
                    hydro_kx_CONTEXT, state->k, sizeof state->k);
    hydro_stream_chacha20_xor(c + hydro_kx_AEAD_HEADERBYTES, m, mlen, zero, ek);
    hydro_hash_hash(c, hydro_kx_AEAD_MACBYTES, c + hydro_kx_AEAD_HEADERBYTES,
                    mlen, hydro_kx_CONTEXT, mk, hydro_hash_KEYBYTES);

    hydro_hash_hash(state->h, sizeof state->h, c, hydro_kx_AEAD_MACBYTES + mlen,
                    hydro_kx_CONTEXT, psk, psk == NULL ? 0 : hydro_kx_PSKBYTES);
}

static int hydro_kx_decrypt(hydro_kx_state *state, uint8_t *m, const uint8_t *c,
                            size_t clen, const uint8_t psk[hydro_kx_PSKBYTES])
    __attribute__((warn_unused_result));

static int
hydro_kx_decrypt(hydro_kx_state *state, uint8_t *m, const uint8_t *c,
                 size_t clen, const uint8_t psk[hydro_kx_PSKBYTES])
{
    uint8_t        keys[hydro_stream_chacha20_KEYBYTES + hydro_hash_KEYBYTES];
    uint8_t        mac[hydro_kx_AEAD_MACBYTES];
    const uint8_t *ek = &keys[0];
    const uint8_t *mk = &keys[hydro_stream_chacha20_KEYBYTES];
    size_t         mlen;

    if (clen < hydro_kx_AEAD_HEADERBYTES) {
        return -1;
    }
    mlen = clen - hydro_kx_AEAD_HEADERBYTES;
    hydro_hash_hash(keys, sizeof keys, state->h, sizeof state->h,
                    hydro_kx_CONTEXT, state->k, sizeof state->k);
    hydro_hash_hash(mac, sizeof mac, c + hydro_kx_AEAD_HEADERBYTES, mlen,
                    hydro_kx_CONTEXT, mk, hydro_hash_KEYBYTES);
    if (!hydro_equal(mac, c, hydro_kx_AEAD_MACBYTES)) {
        return -1;
    }
    hydro_stream_chacha20_xor(m, c + hydro_kx_AEAD_HEADERBYTES, mlen, zero, ek);
    hydro_hash_hash(state->h, sizeof state->h, c, clen, hydro_kx_CONTEXT, psk,
                    psk == NULL ? 0 : hydro_kx_PSKBYTES);

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
    COMPILER_ASSERT(hydro_kx_SESSIONKEYBYTES == hydro_secretbox_KEYBYTES);
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


void hydro_secretbox_keygen(uint8_t key[hydro_secretbox_KEYBYTES])
{
    randombytes_buf(key, hydro_secretbox_KEYBYTES);
}

int hydro_secretbox_encrypt(uint8_t *c, const uint8_t *m, size_t mlen,
    const uint8_t key[hydro_secretbox_KEYBYTES])
{
    hydro_hash128_state st;
    uint8_t             t0[hydro_stream_chacha20_block_BYTES];
    uint8_t             k0[hydro_stream_hchacha20_KEYBYTES];
    uint8_t             nonce[hydro_stream_hchacha20_BYTES];
    const uint8_t *mac_key = &t0[0], *nonce_key = &t0[16], *ct_key = &t0[32];

    COMPILER_ASSERT(hydro_stream_chacha20_block_BYTES ==
                    32 + hydro_stream_xchacha20_KEYBYTES);
    COMPILER_ASSERT(
        hydro_secretbox_KEYBYTES == hydro_stream_chacha20_block_KEYBYTES);
    hydro_stream_chacha20_block(t0, zero, key);
    hydro_hash128_hash(k0, m, mlen, nonce_key);
    randombytes_buf(&k0[hydro_hash128_BYTES], sizeof k0 - hydro_hash128_BYTES);
    hydro_stream_hchacha20(nonce, zero, k0);
    memset(nonce + hydro_secretbox_NONCEBYTES, 0,
        hydro_stream_xchacha20_NONCEBYTES - hydro_secretbox_NONCEBYTES);
    hydro_stream_xchacha20_xor(
        c + hydro_secretbox_HEADERBYTES, m, mlen, nonce, ct_key);
    COMPILER_ASSERT(hydro_secretbox_NONCEBYTES + hydro_secretbox_MACBYTES ==
                    hydro_secretbox_HEADERBYTES);
    hydro_hash128_init(&st, mac_key);
    hydro_hash128_update(&st, nonce, hydro_secretbox_NONCEBYTES);
    hydro_hash128_update(&st, c + hydro_secretbox_HEADERBYTES, mlen);
    hydro_hash128_final(&st, c + hydro_secretbox_NONCEBYTES);
    memcpy(c, nonce, hydro_secretbox_NONCEBYTES);

    return 0;
}

int hydro_secretbox_decrypt(uint8_t *m, const uint8_t *c, size_t clen,
    const uint8_t key[hydro_secretbox_KEYBYTES])
{
    hydro_hash128_state st;
    uint8_t             t0[hydro_stream_chacha20_block_BYTES];
    uint8_t             nonce[hydro_stream_hchacha20_BYTES];
    uint8_t             mac[hydro_secretbox_MACBYTES];
    const uint8_t *     mac_key = &t0[0], *ct_key = &t0[32];
    size_t              mlen;

    if (clen < hydro_secretbox_HEADERBYTES) {
        return -1;
    }
    mlen = clen - hydro_secretbox_HEADERBYTES;
    hydro_stream_chacha20_block(t0, zero, key);
    COMPILER_ASSERT(hydro_secretbox_MACBYTES == hydro_hash128_BYTES);
    memcpy(nonce, c, hydro_secretbox_NONCEBYTES);
    memset(nonce + hydro_secretbox_NONCEBYTES, 0,
        hydro_stream_xchacha20_NONCEBYTES - hydro_secretbox_NONCEBYTES);
    hydro_hash128_init(&st, mac_key);
    hydro_hash128_update(&st, nonce, hydro_secretbox_NONCEBYTES);
    hydro_hash128_update(&st, c + hydro_secretbox_HEADERBYTES, mlen);
    hydro_hash128_final(&st, mac);
    if (!hydro_equal(
            mac, c + hydro_secretbox_NONCEBYTES, hydro_secretbox_MACBYTES)) {
        return -1;
    }
    hydro_stream_xchacha20_xor(
        m, c + hydro_secretbox_HEADERBYTES, mlen, nonce, ct_key);

    return 0;
}

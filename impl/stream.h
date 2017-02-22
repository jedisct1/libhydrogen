#define HYDRO_STREAM_CHACHA20_ROUNDS 12

#define HYDRO_STREAM_CHACHA20_QUARTERROUND(a, b, c, d) \
    a += b;                                            \
    d = ROTL32(d ^ a, 16);                             \
    c += d;                                            \
    b = ROTL32(b ^ c, 12);                             \
    a += b;                                            \
    d = ROTL32(d ^ a, 8);                              \
    c += d;                                            \
    b = ROTL32(b ^ c, 7)

static void
hydro_stream_chacha20_rounds(uint32_t st[16])
{
    int i;

    for (i = 0; i < HYDRO_STREAM_CHACHA20_ROUNDS; i += 2) {
        HYDRO_STREAM_CHACHA20_QUARTERROUND(st[0], st[4], st[8], st[12]);
        HYDRO_STREAM_CHACHA20_QUARTERROUND(st[1], st[5], st[9], st[13]);
        HYDRO_STREAM_CHACHA20_QUARTERROUND(st[2], st[6], st[10], st[14]);
        HYDRO_STREAM_CHACHA20_QUARTERROUND(st[3], st[7], st[11], st[15]);
        HYDRO_STREAM_CHACHA20_QUARTERROUND(st[0], st[5], st[10], st[15]);
        HYDRO_STREAM_CHACHA20_QUARTERROUND(st[1], st[6], st[11], st[12]);
        HYDRO_STREAM_CHACHA20_QUARTERROUND(st[2], st[7], st[8], st[13]);
        HYDRO_STREAM_CHACHA20_QUARTERROUND(st[3], st[4], st[9], st[14]);
    }
}

static void
hydro_stream_chacha20_update(uint32_t ks[16], uint32_t st[16])
{
    int i;

    memcpy(ks, st, 4 * 16);
    hydro_stream_chacha20_rounds(st);
    for (i = 0; i < 16; i++) {
        ks[i] += st[i];
    }
    if (++st[12] == 0) {
        ++st[13];
    }
}

static void
hydro_stream_chacha20_init(
    uint32_t st[16], const uint8_t nonce[hydro_stream_chacha20_NONCEBYTES],
    const uint8_t key[hydro_stream_chacha20_KEYBYTES])
{
    int i;

    st[0] = 0x61707865UL;
    st[1] = 0x3120646eUL;
    st[2] = 0x79622d36UL;
    st[3] = 0x6b206574UL;
    for (i = 0; i < 8; i++) {
        st[4 + i] = LOAD32_LE(&key[4 * i]);
    }
    st[12] = 0;
    st[13] = LOAD32_LE(&nonce[4 * 0]);
    st[14] = LOAD32_LE(&nonce[4 * 1]);
    st[15] = LOAD32_LE(&nonce[4 * 2]);
}

static int
hydro_stream_chacha20_xor(uint8_t *c, const uint8_t *m, size_t len,
                          const uint8_t nonce[hydro_stream_chacha20_NONCEBYTES],
                          const uint8_t key[hydro_stream_chacha20_KEYBYTES])
{
    uint8_t  tmp[64];
    uint32_t ks[16];
    uint32_t st[16];
    uint32_t x;
    int      i;

    hydro_stream_chacha20_init(st, nonce, key);
    while (len >= 64) {
        hydro_stream_chacha20_update(ks, st);
        for (i = 0; i < 16; i++) {
            x = ks[i] ^ LOAD32_LE(m + 4 * i);
            STORE32_LE(c + 4 * i, x);
        }
        c += 64;
        m += 64;
        len -= 64;
    }
    if (len > 0) {
        hydro_stream_chacha20_update(ks, st);
        memset(tmp, 0, 64);
        for (i = 0; i < (int) len; i++) {
            tmp[i] = m[i];
        }
        for (i = 0; i < 16; i++) {
            x = ks[i] ^ LOAD32_LE(tmp + 4 * i);
            STORE32_LE(tmp + 4 * i, x);
        }
        for (i = 0; i < (int) len; i++) {
            c[i] = tmp[i];
        }
    }
    return 0;
}

static int
hydro_stream_chacha20(uint8_t *c, size_t len,
                      const uint8_t nonce[hydro_stream_chacha20_NONCEBYTES],
                      const uint8_t key[hydro_stream_chacha20_KEYBYTES])
{
    memset(c, 0, len);
    return hydro_stream_chacha20_xor(c, c, len, nonce, key);
}

static void
hydro_stream_chacha20_block(
    uint8_t       block[hydro_stream_chacha20_block_BYTES],
    const uint8_t nonce[hydro_stream_chacha20_block_NONCEBYTES],
    const uint8_t key[hydro_stream_chacha20_block_KEYBYTES])
{
    uint32_t ks[16];
    uint32_t st[16];
    int      i;

    hydro_stream_chacha20_init(st, &nonce[4], key);
    st[12] = LOAD32_LE(&nonce[0]);
    hydro_stream_chacha20_update(ks, st);
    for (i = 0; i < 16; i++) {
        STORE32_LE(block + 4 * i, ks[i]);
    }
}

static void
hydro_stream_hchacha20(uint8_t       subkey[hydro_stream_hchacha20_BYTES],
                       const uint8_t nonce[hydro_stream_hchacha20_NONCEBYTES],
                       const uint8_t key[hydro_stream_hchacha20_KEYBYTES])
{
    uint32_t st[16];
    int      i;

    hydro_stream_chacha20_init(st, &nonce[4], key);
    st[12] = LOAD32_LE(&nonce[0]);
    hydro_stream_chacha20_rounds(st);
    for (i = 0; i < 4; i++) {
        STORE32_LE(subkey + 4 * i, st[i]);
    }
    for (; i < 8; i++) {
        STORE32_LE(subkey + 4 * i, st[i + 12 - 4]);
    }
}

static int
hydro_stream_xchacha20_xor(
    uint8_t *c, const uint8_t *m, size_t len,
    const uint8_t nonce[hydro_stream_xchacha20_NONCEBYTES],
    const uint8_t key[hydro_stream_xchacha20_KEYBYTES])
{
    uint8_t subkey[hydro_stream_chacha20_KEYBYTES];
    uint8_t subnonce[hydro_stream_chacha20_NONCEBYTES];

    hydro_stream_hchacha20(subkey, nonce, key);
    COMPILER_ASSERT(hydro_stream_chacha20_KEYBYTES <=
                    hydro_stream_hchacha20_BYTES);
    COMPILER_ASSERT(hydro_stream_xchacha20_NONCEBYTES -
                        hydro_stream_hchacha20_NONCEBYTES ==
                    8);
    COMPILER_ASSERT(sizeof subnonce == 12);
    memset(subnonce, 0, 4);
    memcpy(subnonce + 4, nonce + hydro_stream_hchacha20_NONCEBYTES, 8);

    return hydro_stream_chacha20_xor(c, m, len, subnonce, subkey);
}

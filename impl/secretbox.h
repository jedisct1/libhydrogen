#define hydro_secretbox_IVBYTES 20
#define hydro_secretbox_SIVBYTES 20
#define hydro_secretbox_MACBYTES 16

static inline void
hydro_mem_ct_zero_u32(uint32_t *dst_, size_t n)
{
    volatile uint32_t volatile * dst =
        (volatile uint32_t volatile *) (void *) dst_;
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = 0;
    }
}

static inline uint32_t
hydro_mem_ct_cmp_u32(const uint32_t *b1_, const uint32_t *b2, size_t n)
__attribute__((warn_unused_result));

static inline uint32_t
hydro_mem_ct_cmp_u32(const uint32_t *b1_, const uint32_t *b2, size_t n)
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
hydro_secretbox_keygen(uint8_t key[hydro_secretbox_KEYBYTES])
{
    randombytes_buf(key, hydro_secretbox_KEYBYTES);
}

static void
hydro_secretbox_xor_enc(uint8_t buf[gimli_BLOCKBYTES],
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
hydro_secretbox_xor_dec(uint8_t buf[gimli_BLOCKBYTES],
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
hydro_secretbox_setup(uint8_t buf[gimli_BLOCKBYTES],
                      uint64_t      msg_id,
                      const char    ctx[hydro_secretbox_CONTEXTBYTES],
                      const uint8_t key[hydro_secretbox_KEYBYTES],
                      const uint8_t iv[hydro_secretbox_IVBYTES],
                      int           first_pass)
{
    static const uint8_t prefix[] = { 6, 's', 'b', 'x', '2', '5', '6', 8 };
    uint8_t msg_id_le[8];

    mem_zero(buf, gimli_BLOCKBYTES);
    COMPILER_ASSERT(hydro_secretbox_CONTEXTBYTES == 8);
    COMPILER_ASSERT(sizeof prefix + hydro_secretbox_CONTEXTBYTES <= gimli_RATE);
    mem_cpy(buf, prefix, sizeof prefix);
    mem_cpy(buf + sizeof prefix, ctx, hydro_secretbox_CONTEXTBYTES);
    if (first_pass != 0) {
        buf[0] ^= 0x1f;
        buf[gimli_RATE - 1] ^= 0x80;
    }
    COMPILER_ASSERT(sizeof prefix + hydro_secretbox_CONTEXTBYTES == gimli_RATE);
    gimli_core_u8(buf);

    COMPILER_ASSERT(hydro_secretbox_KEYBYTES == 2 * gimli_RATE);
    mem_xor(buf, key, gimli_RATE);
    gimli_core_u8(buf);
    mem_xor(buf, key + gimli_RATE, gimli_RATE);
    gimli_core_u8(buf);

    COMPILER_ASSERT(hydro_secretbox_IVBYTES < gimli_RATE * 2);
    buf[0] ^= hydro_secretbox_IVBYTES;
    mem_xor(&buf[1], iv, gimli_RATE - 1);
    gimli_core_u8(buf);
    mem_xor(buf, iv + gimli_RATE - 1, hydro_secretbox_IVBYTES - (gimli_RATE - 1));
    STORE64_LE(msg_id_le, msg_id);
    COMPILER_ASSERT(hydro_secretbox_IVBYTES - gimli_RATE + 8 <= gimli_RATE);
    mem_xor(buf + hydro_secretbox_IVBYTES - gimli_RATE, msg_id_le, 8);
    gimli_core_u8(buf);
}

static int
hydro_secretbox_encrypt_iv(uint8_t *c, const void *m_, size_t mlen,
                           uint64_t      msg_id,
                           const char    ctx[hydro_secretbox_CONTEXTBYTES],
                           const uint8_t key[hydro_secretbox_KEYBYTES],
                           const uint8_t iv[hydro_secretbox_IVBYTES])
{
    uint32_t       state[gimli_BLOCKBYTES / 4];
    uint8_t       *buf = (uint8_t *) (void *) state;
    const uint8_t *m = (const uint8_t *) m_;
    uint8_t       *siv = &c[0];
    uint8_t       *mac = &c[hydro_secretbox_SIVBYTES];
    uint8_t       *ct = &c[hydro_secretbox_SIVBYTES + hydro_secretbox_MACBYTES];
    size_t         i;
    size_t         leftover;

    /* first pass: compute the siv */

    hydro_secretbox_setup(buf, msg_id, ctx, key, iv, 1);
    for (i = 0; i < mlen / gimli_RATE; i++) {
        mem_xor(buf, &m[i * gimli_RATE], gimli_RATE);
        gimli_core_u8(buf);
    }
    leftover = mlen % gimli_RATE;
    if (leftover != 0) {
        mem_xor(buf, &m[i * gimli_RATE], leftover);
        gimli_core_u8(buf);
    }
    buf[leftover] ^= 0x1f;
    buf[gimli_RATE - 1] ^= 0x80;
    gimli_core_u8(buf);

    COMPILER_ASSERT(hydro_secretbox_SIVBYTES <= gimli_RATE * 2);
    mem_cpy(siv, buf, hydro_secretbox_SIVBYTES);
    gimli_core_u8(buf);
    mem_cpy(siv + gimli_RATE, buf, hydro_secretbox_SIVBYTES - gimli_RATE);

    /* second pass: encrypt the message, squeeze an extra block for the MAC */

    COMPILER_ASSERT(hydro_secretbox_SIVBYTES == hydro_secretbox_IVBYTES);
    hydro_secretbox_setup(buf, msg_id, ctx, key, siv, 0);

    buf[0] ^= 0x1f;
    buf[gimli_RATE - 1] ^= 0x80;
    gimli_core_u8(buf);

    hydro_secretbox_xor_enc(buf, ct, m, mlen);

    COMPILER_ASSERT(hydro_secretbox_KEYBYTES <= gimli_BLOCKBYTES - gimli_RATE);
    buf[0] ^= 0x1f;
    buf[gimli_RATE - 1] ^= 0x80;
    mem_xor(buf + gimli_RATE, key, hydro_secretbox_KEYBYTES);
    gimli_core_u8(buf);

    COMPILER_ASSERT(hydro_secretbox_MACBYTES <= gimli_BLOCKBYTES - gimli_RATE);
    mem_cpy(mac, buf + gimli_RATE, hydro_secretbox_MACBYTES);

    return 0;
}

int
hydro_secretbox_encrypt(uint8_t *c, const void *m_, size_t mlen,
                        uint64_t      msg_id,
                        const char    ctx[hydro_secretbox_CONTEXTBYTES],
                        const uint8_t key[hydro_secretbox_KEYBYTES])
{
    uint8_t iv[hydro_secretbox_IVBYTES];

    randombytes_buf(iv, sizeof iv);

    return hydro_secretbox_encrypt_iv(c, m_, mlen, msg_id, ctx, key, iv);
}


int
hydro_secretbox_decrypt(void *m_, const uint8_t *c, size_t clen,
                        uint64_t      msg_id,
                        const char    ctx[hydro_secretbox_CONTEXTBYTES],
                        const uint8_t key[hydro_secretbox_KEYBYTES])
{
    uint32_t       pub_mac[hydro_secretbox_MACBYTES / 4];
    uint32_t       state[gimli_BLOCKBYTES / 4];
    uint8_t       *buf = (uint8_t *) (void *) state;
    const uint8_t *siv = &c[0];
    const uint8_t *mac = &c[hydro_secretbox_SIVBYTES];
    const uint8_t *ct = &c[hydro_secretbox_SIVBYTES + hydro_secretbox_MACBYTES];
    uint8_t       *m = (uint8_t *) m_;
    size_t         mlen;
    uint32_t       cv;

    if (clen < hydro_secretbox_HEADERBYTES) {
        return -1;
    }

    mlen = clen - hydro_secretbox_HEADERBYTES;
    mem_cpy(pub_mac, mac, sizeof pub_mac);
    COMPILER_ASSERT(hydro_secretbox_SIVBYTES == hydro_secretbox_IVBYTES);
    hydro_secretbox_setup(buf, msg_id, ctx, key, siv, 0);
    buf[0] ^= 0x1f;
    buf[gimli_RATE - 1] ^= 0x80;
    gimli_core_u8(buf);

    hydro_secretbox_xor_dec(buf, m, ct, mlen);

    COMPILER_ASSERT(hydro_secretbox_KEYBYTES <= gimli_BLOCKBYTES - gimli_RATE);
    buf[0] ^= 0x1f;
    buf[gimli_RATE - 1] ^= 0x80;
    mem_xor(buf + gimli_RATE, key, hydro_secretbox_KEYBYTES);
    gimli_core_u8(buf);

    COMPILER_ASSERT(hydro_secretbox_MACBYTES <= gimli_BLOCKBYTES - gimli_RATE);
    COMPILER_ASSERT(gimli_RATE % 4 == 0);
    cv = hydro_mem_ct_cmp_u32(state + gimli_RATE / 4, pub_mac,
                              hydro_secretbox_MACBYTES / 4);
    hydro_mem_ct_zero_u32(state, gimli_BLOCKBYTES / 4);
    if (cv != 0) {
        mem_zero(m, mlen);
        return -1;
    }
    return 0;
}

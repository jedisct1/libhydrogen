int
hydro_hash_update(hydro_hash_state *state, const void *in_, size_t in_len)
{
    const uint8_t *in = (const uint8_t *) in_;
    uint8_t       *buf = (uint8_t *) (void *) state->state;
    size_t         left;
    size_t         ps;
    size_t         i;

    while (in_len > 0) {
        if ((left = gimli_RATE - state->buf_off) == 0) {
            gimli_core_u8(buf, 0);
            state->buf_off = 0;
            left = gimli_RATE;
        }
        if ((ps = in_len) > left) {
            ps = left;
        }
        for (i = 0; i < ps; i++) {
            buf[state->buf_off + i] ^= in[i];
        }
        state->buf_off += (uint8_t) ps;
        in += ps;
        in_len -= ps;
    }
    return 0;
}

/* pad(str_enc("kmac") || str_enc(context)) || pad(str_enc(k)) ||
   msg || right_enc(msg_len) || 0x00 */

int
hydro_hash_init(hydro_hash_state *state,
                const char ctx[hydro_hash_CONTEXTBYTES],
                const uint8_t *key, size_t key_len)
{
    uint8_t block[64] = { 4, 'k', 'm', 'a', 'c', 8 };
    size_t  p;

    if ((key != NULL && (key_len < hydro_hash_KEYBYTES_MIN ||
                         key_len > hydro_hash_KEYBYTES_MAX)) ||
        (key == NULL && key_len > 0)) {
        return -1;
    }
    COMPILER_ASSERT(hydro_hash_KEYBYTES_MAX <= sizeof block - gimli_RATE - 1);
    COMPILER_ASSERT(hydro_hash_CONTEXTBYTES == 8);
    mem_zero(block + 14, sizeof block - 14);
    mem_cpy(block + 6, ctx, 8);
    block[gimli_RATE] = (uint8_t) key_len;
    mem_cpy(block + gimli_RATE + 1, key, key_len);
    p = (gimli_RATE + 1 + key_len + (gimli_RATE - 1)) & ~ (size_t) (gimli_RATE - 1);
    mem_zero(state, sizeof *state);
    hydro_hash_update(state, block, p);

    return 0;
}

/* pad(str_enc("tmac") || str_enc(context)) || pad(str_enc(k)) ||
   pad(right_enc(tweak)) || msg || right_enc(msg_len) || 0x00 */

static int
hydro_hash_init_with_tweak(hydro_hash_state *state,
                           const char ctx[hydro_hash_CONTEXTBYTES],
                           uint64_t tweak, const uint8_t *key, size_t key_len)
{
    uint8_t block[80] = { 4, 't', 'm', 'a', 'c', 8 };
    size_t  p;

    if ((key != NULL && (key_len < hydro_hash_KEYBYTES_MIN ||
                         key_len > hydro_hash_KEYBYTES_MAX)) ||
        (key == NULL && key_len > 0)) {
        return -1;
    }
    COMPILER_ASSERT(hydro_hash_KEYBYTES_MAX <= sizeof block - 2 * gimli_RATE - 1);
    COMPILER_ASSERT(hydro_hash_CONTEXTBYTES == 8);
    mem_zero(block + 14, sizeof block - 14);
    mem_cpy(block + 6, ctx, 8);
    block[gimli_RATE] = (uint8_t) key_len;
    mem_cpy(block + gimli_RATE + 1, key, key_len);
    p = (gimli_RATE + 1 + key_len + (gimli_RATE - 1)) & ~ (size_t) (gimli_RATE - 1);
    block[p] = (uint8_t) sizeof tweak;
    STORE64_LE(&block[p + 1], tweak);
    p += gimli_RATE;
    mem_zero(state, sizeof *state);
    hydro_hash_update(state, block, p);

    return 0;
}

int
hydro_hash_final(hydro_hash_state *state, uint8_t *out, size_t out_len)
{
    uint8_t  lc[4];
    uint8_t *buf = (uint8_t *) (void *) state->state;
    size_t   i;
    size_t   lc_len;

    if (out_len < hydro_hash_BYTES_MIN || out_len > hydro_hash_BYTES_MAX) {
        return -1;
    }
    COMPILER_ASSERT(hydro_hash_BYTES_MAX <= 0xffff);
    lc[1] = (uint8_t) out_len;
    lc[2] = (uint8_t) (out_len >> 8);
    lc[3] = 0;
    lc_len = (size_t) (1 + (lc[2] != 0));
    lc[0] = (uint8_t) lc_len;
    hydro_hash_update(state, lc, 1 + lc_len + 1);
    gimli_pad_u8(buf, state->buf_off);
    for (i = 0; out_len > 0; i++) {
        const size_t block_size = (out_len < gimli_BLOCKBYTES) ? out_len : gimli_BLOCKBYTES;
        gimli_core_u8(buf, 0);
        mem_cpy(out + i * gimli_BLOCKBYTES, buf, block_size);
        out_len -= block_size;
    }
    return 0;
}

int
hydro_hash_hash(uint8_t *out, size_t out_len, const void *in_, size_t in_len,
                const char ctx[hydro_hash_CONTEXTBYTES], const uint8_t *key,
                size_t key_len)
{
    hydro_hash_state st;
    const uint8_t *  in = (const uint8_t *) in_;

    if (hydro_hash_init(&st, ctx, key, key_len) != 0 ||
        hydro_hash_update(&st, in, in_len) != 0 ||
        hydro_hash_final(&st, out, out_len) != 0) {
        return -1;
    }
    return 0;
}

void
hydro_hash_keygen(uint8_t *key, size_t key_len)
{
    randombytes_buf(key, key_len);
}

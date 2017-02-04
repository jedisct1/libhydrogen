/*
 * BLAKE2XS - Based on the BLAKE2 reference source code
 * Copyright 2016, JP Aumasson <jeanphilippe.aumasson@gmail.com>.
 * Copyright 2016, Samuel Neves <sneves@dei.uc.pt>.
 */

#define hydro_hash_BLAKE2S_BYTES 32
#define hydro_hash_BLOCKBYTES 64

static const uint32_t hydro_hash_IV[8] = { 0x6A09E667UL, 0xBB67AE85UL,
    0x3C6EF372UL, 0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL,
    0x5BE0CD19UL };

static const uint8_t hydro_hash_SIGMA[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

static void hydro_hash_increment_counter(
    hydro_hash_state *state, const uint32_t inc)
{
    state->t[0] += inc;
    state->t[1] += (state->t[0] < inc);
}

#define hydro_hash_G(r, i, a, b, c, d)                                         \
    do {                                                                       \
        a += b + m[hydro_hash_SIGMA[r][2 * i + 0]];                            \
        d = ROTR32(d ^ a, 16);                                                 \
        c += d;                                                                \
        b = ROTR32(b ^ c, 12);                                                 \
        a += b + m[hydro_hash_SIGMA[r][2 * i + 1]];                            \
        d = ROTR32(d ^ a, 8);                                                  \
        c += d;                                                                \
        b = ROTR32(b ^ c, 7);                                                  \
    } while (0)

#define hydro_hash_ROUND(r)                                                    \
    do {                                                                       \
        hydro_hash_G(r, 0, v[0], v[4], v[8], v[12]);                           \
        hydro_hash_G(r, 1, v[1], v[5], v[9], v[13]);                           \
        hydro_hash_G(r, 2, v[2], v[6], v[10], v[14]);                          \
        hydro_hash_G(r, 3, v[3], v[7], v[11], v[15]);                          \
        hydro_hash_G(r, 4, v[0], v[5], v[10], v[15]);                          \
        hydro_hash_G(r, 5, v[1], v[6], v[11], v[12]);                          \
        hydro_hash_G(r, 6, v[2], v[7], v[8], v[13]);                           \
        hydro_hash_G(r, 7, v[3], v[4], v[9], v[14]);                           \
    } while (0)

static void hydro_hash_hashblock(
    hydro_hash_state *state, const uint8_t mb[hydro_hash_BLOCKBYTES])
{
    uint32_t m[16];
    uint32_t v[16];
    int      i;

    for (i = 0; i < 16; i++) {
        m[i] = LOAD32_LE(mb + i * sizeof m[i]);
    }
    for (i = 0; i < 8; i++) {
        v[i] = state->h[i];
    }
    v[8]  = hydro_hash_IV[0];
    v[9]  = hydro_hash_IV[1];
    v[10] = hydro_hash_IV[2];
    v[11] = hydro_hash_IV[3];
    v[12] = state->t[0] ^ hydro_hash_IV[4];
    v[13] = state->t[1] ^ hydro_hash_IV[5];
    v[14] = state->f[0] ^ hydro_hash_IV[6];
    v[15] = state->f[1] ^ hydro_hash_IV[7];
    for (i = 0; i < 10; i++) {
        hydro_hash_ROUND(i);
    }
    for (i = 0; i < 8; i++) {
        state->h[i] = state->h[i] ^ v[i] ^ v[i + 8];
    }
}

static void hydro_hash_init_params(hydro_hash_state *state)
{
    int i;

    for (i = 0; i < 8; i++) {
        state->h[i] =
            hydro_hash_IV[i] ^ LOAD32_LE(&state->digest_length + i * 4);
    }
    memset(state->t, 0, sizeof state->t);
    memset(state->f, 0, sizeof state->f);
    state->buf_len = 0;
}

static int hydro_hash_blake2s_final(
    hydro_hash_state *state, uint8_t *out, size_t out_len)
{
    uint8_t buffer[hydro_hash_BLAKE2S_BYTES];
    int     i;

    memset(buffer, 0, sizeof buffer);
    if (state->f[0] != 0) {
        return -1;
    }
    state->f[0] = (uint32_t)-1;
    hydro_hash_increment_counter(state, state->buf_len);
    mem_zero(
        state->buf + state->buf_len, hydro_hash_BLOCKBYTES - state->buf_len);
    hydro_hash_hashblock(state, state->buf);
    for (i = 0; i < 8; i++) {
        STORE32_LE(buffer + sizeof(state->h[i]) * i, state->h[i]);
    }
    mem_cpy(out, buffer, out_len);

    return 0;
}

int hydro_hash_init(
    hydro_hash_state *state, const uint8_t *key, size_t key_len, size_t out_len)
{
    if ((key != NULL && (key_len < hydro_hash_KEYBYTES_MIN ||
                            key_len > hydro_hash_KEYBYTES_MAX)) ||
        (key == NULL && key_len > 0)) {
        return -1;
    }
    if (out_len < hydro_hash_BYTES_MIN || out_len > hydro_hash_BYTES_MAX) {
        return -1;
    }
    memset(state, 0, sizeof *state);
    state->key_length = key_len;
    if (out_len > hydro_hash_BLAKE2S_BYTES) {
        state->fanout        = 1;
        state->depth         = 1;
        state->digest_length = hydro_hash_BLAKE2S_BYTES;
        STORE16_LE(state->xof_length, out_len);
    } else {
        state->digest_length = (uint8_t)out_len;
    }
    hydro_hash_init_params(state);
    if (key != NULL) {
        uint8_t block[hydro_hash_BLOCKBYTES];
        memset(block, 0, sizeof block);
        mem_cpy(block, key, key_len);
        hydro_hash_update(state, block, sizeof block);
        hydro_memzero(block, sizeof block);
    }
    return 0;
}

int hydro_hash_update(hydro_hash_state *state, const uint8_t *in, size_t in_len)
{
    size_t left;
    size_t fill;

    if (in_len <= 0) {
        return 0;
    }
    left = state->buf_len;
    fill = hydro_hash_BLOCKBYTES - left;
    if (in_len > fill) {
        state->buf_len = 0;
        mem_cpy(state->buf + left, in, fill);
        hydro_hash_increment_counter(state, hydro_hash_BLOCKBYTES);
        hydro_hash_hashblock(state, state->buf);
        in += fill;
        in_len -= fill;
        while (in_len > hydro_hash_BLOCKBYTES) {
            hydro_hash_increment_counter(state, hydro_hash_BLOCKBYTES);
            hydro_hash_hashblock(state, in);
            in += hydro_hash_BLOCKBYTES;
            in_len -= hydro_hash_BLOCKBYTES;
        }
    }
    mem_cpy(state->buf + state->buf_len, in, in_len);
    state->buf_len += in_len;

    return 0;
}

int hydro_hash_final(hydro_hash_state *state, uint8_t *out, size_t out_len)
{
    uint8_t  root[hydro_hash_BLOCKBYTES];
    uint32_t i;
    uint16_t xof_length;

    if (out_len < hydro_hash_BYTES_MIN || out_len > hydro_hash_BYTES_MAX) {
        return -1;
    }
    xof_length = LOAD16_LE(state->xof_length);
    if (xof_length == 0) {
        if (state->digest_length != out_len) {
            return -1;
        }
        return hydro_hash_blake2s_final(state, out, out_len);
    } else if (xof_length != out_len) {
        return -1;
    }
    if (hydro_hash_blake2s_final(state, root, hydro_hash_BLAKE2S_BYTES) != 0) {
        return -1;
    }
    state->key_length = 0;
    state->fanout     = 0;
    state->depth      = 0;
    STORE32_LE(state->leaf_length, hydro_hash_BLAKE2S_BYTES);
    state->inner_length = hydro_hash_BLAKE2S_BYTES;
    for (i = 0; out_len > 0; i++) {
        const size_t block_size = (out_len < hydro_hash_BLAKE2S_BYTES)
                                      ? out_len
                                      : hydro_hash_BLAKE2S_BYTES;
        state->digest_length = block_size;
        STORE32_LE(state->node_offset, i);
        hydro_hash_init_params(state);
        hydro_hash_update(state, root, hydro_hash_BLAKE2S_BYTES);
        if (hydro_hash_blake2s_final(
                state, out + i * hydro_hash_BLAKE2S_BYTES, block_size) != 0) {
            return -1;
        }
        out_len -= block_size;
    }
    return 0;
}

int hydro_hash_hash(uint8_t *out, size_t out_len, const uint8_t *in,
    size_t in_len, const uint8_t *key, size_t key_len)
{
    hydro_hash_state st;

    if (hydro_hash_init(&st, key, key_len, out_len) != 0 ||
        hydro_hash_update(&st, in, in_len) != 0 ||
        hydro_hash_final(&st, out, out_len) != 0) {
        return -1;
    }
    return 0;
}

void hydro_hash_keygen(uint8_t *key, size_t key_len)
{
    randombytes_buf(key, key_len);
}

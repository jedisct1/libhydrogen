#ifdef __SSSE3__

#include <tmmintrin.h>

#define S 9

typedef unsigned int uint32;

static inline __m128i
shift(__m128i x, int bits)
{
    return _mm_slli_epi32(x, bits);
}

static inline __m128i
rotate(__m128i x, int bits)
{
    return _mm_slli_epi32(x, bits) | _mm_srli_epi32(x, 32 - bits);
}

static inline __m128i
rotate24(__m128i x)
{
    return _mm_shuffle_epi8(
        x, _mm_set_epi8(12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1));
}

static const uint32_t coeffs[24] CRYPTO_ALIGN(16) = {
    0x9e377904, 0, 0, 0, 0x9e377908, 0, 0, 0, 0x9e37790c, 0, 0, 0,
    0x9e377910, 0, 0, 0, 0x9e377914, 0, 0, 0, 0x9e377918, 0, 0, 0,
};

static void
gimli_core(uint32_t state[gimli_BLOCKBYTES / 4])
{
    __m128i x = _mm_loadu_si128((const __m128i *)
                                (const void *) &state[0]);
    __m128i y = _mm_loadu_si128((const __m128i *)
                                (const void *) &state[4]);
    __m128i z = _mm_loadu_si128((const __m128i *)
                                (const void *) &state[8]);
    __m128i newy;
    __m128i newz;
    int     round;

    for (round = 5; round >= 0; round--) {
        x    = rotate24(x);
        y    = rotate(y, S);
        newz = x ^ shift(z, 1) ^ shift(y & z, 2);
        newy = y ^ x ^ shift(x | z, 1);
        x    = z ^ y ^ shift(x & y, 3);
        y    = newy;
        z    = newz;

        x = _mm_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1));
        x ^= ((const __m128i *) (const void *) coeffs)[round];

        x    = rotate24(x);
        y    = rotate(y, S);
        newz = x ^ shift(z, 1) ^ shift(y & z, 2);
        newy = y ^ x ^ shift(x | z, 1);
        x    = z ^ y ^ shift(x & y, 3);
        y    = newy;
        z    = newz;

        x    = rotate24(x);
        y    = rotate(y, S);
        newz = x ^ shift(z, 1) ^ shift(y & z, 2);
        newy = y ^ x ^ shift(x | z, 1);
        x    = z ^ y ^ shift(x & y, 3);
        y    = newy;
        z    = newz;

        x = _mm_shuffle_epi32(x, _MM_SHUFFLE(1, 0, 3, 2));

        x    = rotate24(x);
        y    = rotate(y, S);
        newz = x ^ shift(z, 1) ^ shift(y & z, 2);
        newy = y ^ x ^ shift(x | z, 1);
        x    = z ^ y ^ shift(x & y, 3);
        y    = newy;
        z    = newz;
    }

    _mm_storeu_si128((__m128i *) (void *) &state[0], x);
    _mm_storeu_si128((__m128i *) (void *) &state[4], y);
    _mm_storeu_si128((__m128i *) (void *) &state[8], z);
}

#else

static void
gimli_core(uint32_t state[gimli_BLOCKBYTES / 4])
{
    unsigned int round;
    unsigned int column;
    uint32_t     x;
    uint32_t     y;
    uint32_t     z;

    for (round = 24; round > 0; round--) {
        for (column = 0; column < 4; column++) {
            x = ROTL32(state[column], 24);
            y = ROTL32(state[4 + column], 9);
            z = state[8 + column];

            state[8 + column] = x ^ (z << 1) ^ ((y & z) << 2);
            state[4 + column] = y ^ x ^ ((x | z) << 1);
            state[column]     = z ^ y ^ ((x & y) << 3);
        }
        switch (round & 3) {
        case 0:
            x        = state[0];
            state[0] = state[1];
            state[1] = x;
            x        = state[2];
            state[2] = state[3];
            state[3] = x;
            state[0] ^= ((uint32_t) 0x9e377900 | round);
            break;
        case 2:
            x        = state[0];
            state[0] = state[2];
            state[2] = x;
            x        = state[1];
            state[1] = state[3];
            state[3] = x;
        }
    }
}

#endif

void
gimli_core_u8(uint8_t state_u8[gimli_BLOCKBYTES])
{
#ifndef NATIVE_LITTLE_ENDIAN
    uint32_t state_u32[12];
    int      i;

    for (i = 0; i < 12; i++) {
        state_u32[i] = LOAD32_LE(&state_u8[i * 4]);
    }
    gimli_core(state_u32);
    for (i = 0; i < 12; i++) {
        STORE32_LE(&state_u8[i * 4], state_u32[i]);
    }
#else
    gimli_core((uint32_t *) (void *) state_u8); /* state_u8 must be properly aligned */
#endif
}

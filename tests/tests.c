#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../hydrogen.h"

static uint8_t ctx[8] = { 'l', 'i', 'b', 't', 'e', 's', 't', 's' };

static void test_randombytes(void)
{
    uint8_t       key[randombytes_buf_deterministic_KEYBYTES];
    uint8_t       tmp[10000];
    unsigned long b = 0U;
    unsigned long bp;
    uint32_t      x;
    size_t        i, j;

    for (i = 0; i < 10000; i++) {
        x = randombytes_random();
        for (j = 0; j < sizeof x; j++) {
            b += (x >> j) & 1;
        }
    }
    assert(b > 18000 && b < 22000);

    b = 0;
    randombytes_buf(tmp, sizeof tmp);
    for (i = 0; i < 10000; i++) {
        for (j = 0; j < sizeof tmp[0]; j++) {
            b += (tmp[i] >> j) & 1;
        }
    }
    assert(b > 4500 && b < 5500);

    memcpy(key, tmp, sizeof key);
    b = 0;
    randombytes_buf_deterministic(tmp, 10000, key);
    for (i = 0; i < 10000; i++) {
        for (j = 0; j < sizeof tmp[0]; j++) {
            b += (tmp[i] >> j) & 1;
        }
    }
    assert(b > 4500 && b < 5500);
    bp = b;
    b  = 0;
    randombytes_buf_deterministic(tmp, 10000, key);
    for (i = 0; i < 10000; i++) {
        for (j = 0; j < sizeof tmp[0]; j++) {
            b += (tmp[i] >> j) & 1;
        }
    }
    assert(b == bp);

    for (i = 0; i < 1000; i++) {
        for (j = 1; j < 100; j++) {
            x = randombytes_uniform(j);
            assert(x < j);
        }
    }
}

static void test_hash(void)
{
    hydro_hash_state    st;
    uint8_t             dk[randombytes_buf_deterministic_KEYBYTES];
    uint8_t             h[100];
    uint8_t             key[hydro_hash_KEYBYTES_MAX];
    uint8_t             msg[1000];
    char                hex[100 * 2 + 1];
    size_t              i;

    memset(dk, 0, sizeof dk);
    randombytes_buf_deterministic(key, sizeof key, dk);
    hydro_increment(dk, sizeof dk);
    hydro_hash_init(&st, ctx, key, sizeof key, sizeof h);
    for (i = 0; i <= sizeof msg; i++) {
        randombytes_buf_deterministic(msg, i, dk);
        hydro_increment(dk, sizeof dk);
        hydro_hash_update(&st, msg, i);
    }
    hydro_hash_final(&st, h, sizeof h);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert(hydro_equal("7137d87ad55fdf061789e1e8bebf7572525d4d08f7f4371a960b02c6242724a71cd2a88d50c32bc9e118044a2d539c01b5cccc3b52e67fc5eae283de5dcbd501a933c4b9c5aaddbaf81693ec485811459e6edb5257a7573a573525d9f1874e71556d9ad3", hex, sizeof hex));
    hydro_hash_hash(h, sizeof h, msg, sizeof msg, ctx, key, sizeof key);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert(hydro_equal("b453c8627089d4b38ac87a5a89503c5a5740eb4206be37d4c5c50e956b3d56f0bc96b14a87061cce9bb69b89f57a0d13dab0ad7b4985139492d8cd8eaea4e1c59f971a8cc817e62485c2a0c19faa7b32967009a16a405a679970637f8f11536db65c416f", hex, sizeof hex));
    hydro_hash_hash(h, hydro_hash_BYTES, msg, sizeof msg, ctx, key, sizeof key);
    hydro_bin2hex(hex, sizeof hex, h, hydro_hash_BYTES);
    assert(hydro_equal("f13a6f6e56c7799bdf6cb2f7787419a703cd617110b67d951ed04b3ddde7fde8", hex, strlen(hex) + 1));
}

static void test_hash128(void)
{
    hydro_hash128_state st;
    uint8_t             dk[randombytes_buf_deterministic_KEYBYTES];
    uint8_t             h[hydro_hash128_BYTES];
    uint8_t             key[hydro_hash128_KEYBYTES];
    uint8_t             msg[1000];
    char                hex[hydro_hash128_BYTES * 2 + 1];
    size_t              i;

    memset(dk, 0, sizeof dk);
    randombytes_buf_deterministic(key, sizeof key, dk);
    hydro_increment(dk, sizeof dk);
    hydro_hash128_init(&st, ctx, key);
    for (i = 0; i <= sizeof msg; i++) {
        randombytes_buf_deterministic(msg, i, dk);
        hydro_increment(dk, sizeof dk);
        hydro_hash128_update(&st, msg, i);
    }
    hydro_hash128_final(&st, h);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert(hydro_equal("3d266a5ae418ba26607d611d49942567", hex, sizeof hex));
    hydro_hash128_hash(h, msg, sizeof msg, ctx, key);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert(hydro_equal("d4a32e2f38ab334dd4d4e252bb46d76b", hex, sizeof hex));
}

static void test_core(void)
{
    uint8_t x[100];
    uint8_t y[100];
    uint8_t a[5] = { 1, 2, 3, 4, 5 };
    uint8_t b[5] = { 1, 2, 3, 4, 5 };
    char    hex[201];

    memset(x, 0xd0, sizeof x);
    hydro_memzero(x, sizeof x);
    assert(x[0] == 0);
    assert(x[sizeof x - 1] == 0);
    hydro_increment(x, sizeof x);
    assert(x[0] == 1);
    assert(x[sizeof x - 1] == 0);
    x[0] = 0xff;
    hydro_increment(x, sizeof x);
    assert(x[0] == 0);
    assert(x[1] == 1);
    assert(x[sizeof x - 1] == 0);
    assert(hydro_equal(a, b, sizeof a));
    assert(!hydro_equal(a, a, sizeof a));
    assert(hydro_compare(a, b, sizeof a) == 0);
    assert(hydro_compare(a, a, sizeof a) == 0);
    a[0]++;
    assert(hydro_compare(a, b, sizeof a) == 1);
    assert(hydro_compare(b, a, sizeof a) == -1);
    randombytes_buf(x, sizeof x);
    assert(hydro_bin2hex(hex, sizeof hex, x, sizeof x) != NULL);
    assert(hydro_hex2bin(y, 1, hex, sizeof hex, NULL, NULL, NULL) == -1);
    assert(hydro_hex2bin(y, sizeof y, hex, sizeof hex, NULL, NULL, NULL) == 0);
    assert(hydro_equal(x, y, sizeof x));
}

static void test_secretbox(void)
{
    uint8_t key[hydro_secretbox_KEYBYTES];
    uint8_t m[25];
    uint8_t m2[25];
    uint8_t c[hydro_secretbox_HEADERBYTES + 25];
    uint8_t dk[randombytes_buf_deterministic_KEYBYTES];

    memset(dk, 0, sizeof dk);
    randombytes_buf_deterministic(m, sizeof m, dk);
    hydro_increment(dk, sizeof dk);
    randombytes_buf_deterministic(key, sizeof key, dk);
    hydro_increment(dk, sizeof dk);
    hydro_secretbox_encrypt(c, m, sizeof m, ctx, key);
    assert(hydro_secretbox_decrypt(m2, c, 0, ctx, key) == -1);
    assert(hydro_secretbox_decrypt(m2, c, 1, ctx, key) == -1);
    assert(
        hydro_secretbox_decrypt(m2, c, hydro_secretbox_HEADERBYTES, ctx, key) == -1);
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, ctx, key) == 0);
    assert(hydro_equal(m, m2, sizeof m));
    key[0]++;
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, ctx, key) == -1);
    key[0]--;
    c[randombytes_uniform(sizeof c)]++;
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, ctx, key) == -1);
}

int main(void)
{
    int ret;

    ret = hydro_init();
    assert(ret == 0);

    test_core();
    test_hash();
    test_hash128();
    test_randombytes();
    test_secretbox();

    return 0;
}

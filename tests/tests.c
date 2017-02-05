#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../hydrogen.h"

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
    hydro_hash_init(&st, key, sizeof key, sizeof h);
    for (i = 0; i <= sizeof msg; i++) {
        randombytes_buf_deterministic(msg, i, dk);
        hydro_increment(dk, sizeof dk);
        hydro_hash_update(&st, msg, i);
    }
    hydro_hash_final(&st, h, sizeof h);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert(hydro_equal("fb329ba1831cdc26aa2cdc9ea901ca979d970a31709f7c15ca102af797d3ecfe8f21d8483d102ef43001b12099f54cbefce732a0ca02014dc6e27939a31f59b91388c0bbe982d3b3983b48b4ed2d46ce61e7b32c6680254c8e98f13bb88d4e8be92e96ba", hex, sizeof hex));
    hydro_hash_hash(h, sizeof h, msg, sizeof msg, key, sizeof key);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert(hydro_equal("1e3be527db0e0447368ae4053b475503957ce487b593b168e197ffa5124adca07145d54402b1965a0fc6429f9425fd46ca3d34c03ba405bf3fd6c5ded32461c869f199232f4885bb33ce05bb290bbcf59839c25b3d031e4e64730484219608062ec3d7c8", hex, sizeof hex));
    hydro_hash_hash(h, hydro_hash_BYTES, msg, sizeof msg, key, sizeof key);
    hydro_bin2hex(hex, sizeof hex, h, hydro_hash_BYTES);
    assert(hydro_equal("61e8bdb2c7e6eb0e885876524287b2383662d25aba62f4016c0a8a56d9f57d9f", hex, strlen(hex) + 1));
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
    hydro_hash128_init(&st, key);
    for (i = 0; i <= sizeof msg; i++) {
        randombytes_buf_deterministic(msg, i, dk);
        hydro_increment(dk, sizeof dk);
        hydro_hash128_update(&st, msg, i);
    }
    hydro_hash128_final(&st, h);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert(hydro_equal("4ea163585a80ac8e11f313a82187ddbf", hex, sizeof hex));
    hydro_hash128_hash(h, msg, sizeof msg, key);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert(hydro_equal("10d17ef502821c231af4720c5ed7a721", hex, sizeof hex));
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
    hydro_secretbox_encrypt(c, m, sizeof m, key);
    assert(hydro_secretbox_decrypt(m2, c, 0, key) == -1);
    assert(hydro_secretbox_decrypt(m2, c, 1, key) == -1);
    assert(
        hydro_secretbox_decrypt(m2, c, hydro_secretbox_HEADERBYTES, key) == -1);
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, key) == 0);
    assert(hydro_equal(m, m2, sizeof m));
    key[0]++;
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, key) == -1);
    key[0]--;
    c[randombytes_uniform(sizeof c)]++;
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, key) == -1);
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

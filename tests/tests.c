#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../hydrogen.h"

static const char *ctx = "libtests";

static void test_randombytes(void)
{
    uint8_t       dk[randombytes_SEEDBYTES];
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

    memcpy(dk, tmp, sizeof dk);
    b = 0;
    randombytes_buf_deterministic(tmp, 10000, dk);
    for (i = 0; i < 10000; i++) {
        for (j = 0; j < sizeof tmp[0]; j++) {
            b += (tmp[i] >> j) & 1;
        }
    }
    assert(b > 4500 && b < 5500);
    bp = b;
    b  = 0;
    randombytes_buf_deterministic(tmp, 10000, dk);
    for (i = 0; i < 10000; i++) {
        for (j = 0; j < sizeof tmp[0]; j++) {
            b += (tmp[i] >> j) & 1;
        }
    }
    assert(b == bp);

    for (i = 0; i < 1000; i++) {
        for (j = 1; j < 100; j++) {
            x = randombytes_uniform((uint32_t)j);
            assert(x < j);
        }
    }
}

static void test_hash(void)
{
    hydro_hash_state st;
    uint8_t          dk[randombytes_SEEDBYTES];
    uint8_t          h[100];
    uint8_t          key[hydro_hash_KEYBYTES_MAX];
    uint8_t          msg[1000];
    char             hex[100 * 2 + 1];
    size_t           i;

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
    assert(hydro_equal("7137d87ad55fdf061789e1e8bebf7572525d4d08f7f4371a960b02c"
                       "6242724a71cd2a88d50c32bc9e118044a2d539c01b5cccc3b52e67f"
                       "c5eae283de5dcbd501a933c4b9c5aaddbaf81693ec485811459e6ed"
                       "b5257a7573a573525d9f1874e71556d9ad3",
        hex, sizeof hex));
    hydro_hash_hash(h, sizeof h, msg, sizeof msg, ctx, key, sizeof key);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert(hydro_equal("b453c8627089d4b38ac87a5a89503c5a5740eb4206be37d4c5c50e9"
                       "56b3d56f0bc96b14a87061cce9bb69b89f57a0d13dab0ad7b498513"
                       "9492d8cd8eaea4e1c59f971a8cc817e62485c2a0c19faa7b3296700"
                       "9a16a405a679970637f8f11536db65c416f",
        hex, sizeof hex));
    hydro_hash_hash(h, hydro_hash_BYTES, msg, sizeof msg, ctx, key, sizeof key);
    hydro_bin2hex(hex, sizeof hex, h, hydro_hash_BYTES);
    assert(hydro_equal(
        "f13a6f6e56c7799bdf6cb2f7787419a703cd617110b67d951ed04b3ddde7fde8", hex,
        strlen(hex) + 1));
}

static void test_hash128(void)
{
    hydro_hash128_state st;
    uint8_t             dk[randombytes_SEEDBYTES];
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
    uint8_t dk[randombytes_SEEDBYTES];

    memset(dk, 0, sizeof dk);
    randombytes_buf_deterministic(m, sizeof m, dk);
    hydro_increment(dk, sizeof dk);
    randombytes_buf_deterministic(key, sizeof key, dk);
    hydro_increment(dk, sizeof dk);
    hydro_secretbox_encrypt(c, m, sizeof m, 0, ctx, key);
    assert(hydro_secretbox_decrypt(m2, c, 0, 0, ctx, key) == -1);
    assert(hydro_secretbox_decrypt(m2, c, 1, 0, ctx, key) == -1);
    assert(hydro_secretbox_decrypt(
               m2, c, hydro_secretbox_HEADERBYTES, 0, ctx, key) == -1);
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, 0, ctx, key) == 0);
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, 1, ctx, key) == -1);
    assert(hydro_equal(m, m2, sizeof m));
    key[0]++;
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, 0, ctx, key) == -1);
    key[0]--;
    c[randombytes_uniform(sizeof c)]++;
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, 0, ctx, key) == -1);
}

static void test_kdf(void)
{
    uint8_t key[hydro_kdf_KEYBYTES];
    uint8_t dk[randombytes_SEEDBYTES];
    uint8_t subkey1[16];
    uint8_t subkey2[16];
    uint8_t subkey3[32];
    uint8_t subkey4[50];
    char    subkey1_hex[16 * 2 + 1];
    char    subkey2_hex[16 * 2 + 1];
    char    subkey3_hex[32 * 2 + 1];
    char    subkey4_hex[50 * 2 + 1];

    memset(dk, 0, sizeof dk);
    randombytes_buf_deterministic(key, sizeof key, dk);
    hydro_kdf_derive_from_key(subkey1, sizeof subkey1, 1, ctx, key);
    hydro_kdf_derive_from_key(subkey2, sizeof subkey2, 2, ctx, key);
    hydro_kdf_derive_from_key(subkey3, sizeof subkey3, 0, ctx, key);
    hydro_kdf_derive_from_key(subkey4, sizeof subkey4, 0, ctx, key);
    hydro_bin2hex(subkey1_hex, sizeof subkey1_hex, subkey1, sizeof subkey1);
    hydro_bin2hex(subkey2_hex, sizeof subkey2_hex, subkey2, sizeof subkey2);
    hydro_bin2hex(subkey3_hex, sizeof subkey3_hex, subkey3, sizeof subkey3);
    hydro_bin2hex(subkey4_hex, sizeof subkey4_hex, subkey4, sizeof subkey4);
    assert(hydro_equal(
        "b6dadc6c3594b305fac7160e89fb628e", subkey1_hex, sizeof subkey1_hex));
    assert(hydro_equal(
        "baf03b412086d54067cac64f583bcd16", subkey2_hex, sizeof subkey2_hex));
    assert(hydro_equal(
        "d583dc8833f19dbd544f057d0cebaed5507306a134361119d4e4eb172d903be3",
        subkey3_hex, sizeof subkey3_hex));
    assert(hydro_equal("ef289ae126182038ae57ab4c07f0eab94676f85f5462cffd2586fa6"
                       "ae881c2eacd863c8f3335abb70ced9d5360462d693ec1",
        subkey4_hex, sizeof subkey4_hex));
}

static void test_sign(void)
{
    uint8_t            msg[500];
    uint8_t            sig[hydro_sign_BYTES];
    hydro_sign_state   st;
    hydro_sign_keypair kp;

    randombytes_buf(msg, sizeof msg);
    hydro_sign_keygen(&kp);
    hydro_sign_create(sig, msg, sizeof msg, ctx, kp.sk);
    assert(hydro_sign_verify(sig, msg, sizeof msg, ctx, kp.pk) == 0);
    sig[0]++;
    assert(hydro_sign_verify(sig, msg, sizeof msg, ctx, kp.pk) == -1);
    sig[0]--;
    sig[hydro_sign_BYTES - 1]++;
    assert(hydro_sign_verify(sig, msg, sizeof msg, ctx, kp.pk) == -1);
    sig[hydro_sign_BYTES - 1]--;
    msg[0]++;
    assert(hydro_sign_verify(sig, msg, sizeof msg, ctx, kp.pk) == -1);
    msg[0]++;
    hydro_sign_create(sig, msg, sizeof msg, ctx, kp.sk);

    hydro_sign_init(&st, ctx);
    hydro_sign_update(&st, msg, (sizeof msg) / 3);
    hydro_sign_update(
        &st, msg + (sizeof msg) / 3, (sizeof msg) - (sizeof msg) / 3);
    assert(hydro_sign_final_verify(&st, sig, kp.pk) == 0);

    hydro_sign_init(&st, ctx);
    hydro_sign_update(&st, msg, (sizeof msg) / 3);
    hydro_sign_update(
        &st, msg + (sizeof msg) / 3, (sizeof msg) - (sizeof msg) / 3);
    hydro_sign_final_create(&st, sig, kp.sk);

    hydro_sign_init(&st, ctx);
    hydro_sign_update(&st, msg, (sizeof msg) / 3);
    hydro_sign_update(
        &st, msg + (sizeof msg) / 3, (sizeof msg) - (sizeof msg) / 3);
    assert(hydro_sign_final_verify(&st, sig, kp.pk) == 0);
    sig[0]++;
    assert(hydro_sign_final_verify(&st, sig, kp.pk) == -1);

    hydro_sign_create(sig, msg, 0, ctx, kp.sk);
    assert(hydro_sign_verify(sig, msg, sizeof msg, ctx, kp.pk) == -1);
    assert(hydro_sign_verify(sig, msg, 0, ctx, kp.pk) == 0);
}

static void test_kx(void)
{
    hydro_kx_state           st_client;
    hydro_kx_state           st_server;
    hydro_kx_keypair         client_static_kp;
    hydro_kx_keypair         server_static_kp;
    uint8_t                  psk[hydro_kx_PSKBYTES];
    uint8_t                  client_peer_pk[hydro_kx_PUBLICKEYBYTES];
    uint8_t                  server_peer_pk[hydro_kx_PUBLICKEYBYTES];
    uint8_t                  response1[hydro_kx_RESPONSE1BYTES];
    uint8_t                  response2[hydro_kx_RESPONSE2BYTES];
    uint8_t                  response3[hydro_kx_RESPONSE3BYTES];
    hydro_kx_session_keypair kp_client;
    hydro_kx_session_keypair kp_server;

    hydro_kx_keygen(&client_static_kp);
    hydro_kx_keygen(&server_static_kp);

    hydro_kx_xx_1(&st_client, response1, NULL);
    hydro_kx_xx_2(&st_server, response2, response1, NULL, &server_static_kp);
    hydro_kx_xx_3(&st_client, &kp_client, response3, NULL, response2, NULL,
        &client_static_kp);
    hydro_kx_xx_4(&st_server, &kp_server, NULL, response3, NULL);

    assert(hydro_equal(kp_client.tx, kp_server.rx, hydro_kx_SESSIONKEYBYTES));
    assert(hydro_equal(kp_client.rx, kp_server.tx, hydro_kx_SESSIONKEYBYTES));

    randombytes_buf(psk, sizeof psk);
    hydro_kx_xx_1(&st_client, response1, psk);
    hydro_kx_xx_2(&st_server, response2, response1, psk, &server_static_kp);
    hydro_kx_xx_3(&st_client, &kp_client, response3, client_peer_pk, response2,
        psk, &client_static_kp);
    hydro_kx_xx_4(&st_server, &kp_server, server_peer_pk, response3, psk);

    assert(hydro_equal(kp_client.tx, kp_server.rx, hydro_kx_SESSIONKEYBYTES));
    assert(hydro_equal(kp_client.rx, kp_server.tx, hydro_kx_SESSIONKEYBYTES));
    assert(hydro_equal(
        client_peer_pk, server_static_kp.pk, hydro_kx_PUBLICKEYBYTES));
    assert(hydro_equal(
        server_peer_pk, client_static_kp.pk, hydro_kx_PUBLICKEYBYTES));
}

int main(void)
{
    int ret;

    ret = hydro_init();
    assert(ret == 0);

    test_core();
    test_hash();
    test_hash128();
    test_kdf();
    test_randombytes();
    test_secretbox();
    test_kx();

    return 0;
}

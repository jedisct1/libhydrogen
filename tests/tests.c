#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../hydrogen.h"

static const char *ctx = "libtests";

static void
assert_streq(const char *expected, const char *found)
{
    if (strcmp(expected, found) != 0) {
        fprintf(stderr, "Expected: [%s] - Found: [%s]\n", expected, found);
        assert(0);
    }
}

static void
test_randombytes(void)
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
            x = randombytes_uniform((uint32_t) j);
            assert(x < j);
        }
    }
}

static void
test_hash(void)
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
    hydro_hash_init(&st, ctx, key, sizeof key);
    for (i = 0; i <= sizeof msg; i++) {
        randombytes_buf_deterministic(msg, i, dk);
        hydro_increment(dk, sizeof dk);
        hydro_hash_update(&st, msg, i);
    }
    hydro_hash_final(&st, h, sizeof h);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert_streq(
        "6ff6bd27fc51dbe7dae007a23a55141500ce3067e1e54a72bd0ce6665c916853bdbfa3240dd73f"
        "da0bf2ee39718098f70a3cff128ffbe4c7b7c2978eb0747e225ca9a54ea04f6440f1683bbb58c2"
        "000817de5166f298aa2988dbd4465d82584e0a8b73cf",
        hex);
    hydro_hash_hash(h, sizeof h, msg, sizeof msg, ctx, key, sizeof key);
    hydro_bin2hex(hex, sizeof hex, h, sizeof h);
    assert_streq(
        "cfedeaf17eba400b48d0ff0cca511414d50577e6baa70794652ecaf546539688aafa4a82f72c51"
        "8e7f14a99a0cd9b128b9b7f4cffdd6ac31fe4fe1899af07ea8be66cc837bb40d45c2119b62cf32"
        "98b4f9f6dd88945563c0b6226ca270e5c4bf37ff4d87",
        hex);
    hydro_hash_hash(h, hydro_hash_BYTES, msg, sizeof msg, ctx, key, sizeof key);
    hydro_bin2hex(hex, sizeof hex, h, hydro_hash_BYTES);
    assert_streq("3d3b3c9bb1bc10c5dccd1f62e3e6b90e4b0680453ca63ebdab9e8d3551060d5f", hex);
}

static void
test_core(void)
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
    assert(hydro_hex2bin(y, sizeof y, hex, sizeof hex, NULL, NULL, NULL) == -1);
    assert(hydro_hex2bin(y, sizeof y, hex, sizeof hex - 1, NULL, NULL, NULL) == 0);
    assert(hydro_equal(x, y, sizeof x));
}

static void
test_secretbox(void)
{
    uint8_t key[hydro_secretbox_KEYBYTES];
    uint8_t m[25];
    uint8_t m2[25];
    uint8_t c[hydro_secretbox_HEADERBYTES + 25];
    uint8_t dk[randombytes_SEEDBYTES];
    uint8_t probe[hydro_secretbox_PROBEBYTES];

    memset(dk, 0, sizeof dk);
    randombytes_buf_deterministic(m, sizeof m, dk);
    hydro_increment(dk, sizeof dk);
    randombytes_buf_deterministic(key, sizeof key, dk);
    hydro_increment(dk, sizeof dk);
    hydro_secretbox_encrypt(c, m, sizeof m, 0, ctx, key);
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, 0, ctx, key) == 0);
    assert(hydro_equal(m, m2, sizeof m));

    hydro_secretbox_probe_create(probe, c, sizeof c, ctx, key);
    assert(hydro_secretbox_probe_verify(probe, c, sizeof c, ctx, key) == 0);
    probe[0]++;
    assert(hydro_secretbox_probe_verify(probe, c, sizeof c, ctx, key) == -1);
    probe[0]--;
    key[0]++;
    assert(hydro_secretbox_probe_verify(probe, c, sizeof c, ctx, key) == -1);
    key[0]--;

    assert(hydro_secretbox_decrypt(m2, c, 0, 0, ctx, key) == -1);
    assert(hydro_secretbox_decrypt(m2, c, 1, 0, ctx, key) == -1);
    assert(hydro_secretbox_decrypt(m2, c, hydro_secretbox_HEADERBYTES, 0, ctx, key) == -1);
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, 1, ctx, key) == -1);
    assert(!hydro_equal(m, m2, sizeof m));
    key[0]++;
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, 0, ctx, key) == -1);
    key[0]--;
    c[randombytes_uniform(sizeof c)]++;
    assert(hydro_secretbox_decrypt(m2, c, sizeof c, 0, ctx, key) == -1);
}

static void
test_kdf(void)
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
    assert_streq("41db0de11bed2cccd4013ff13e17b21c", subkey1_hex);
    assert_streq("fae22553f3a1833ab529faefbf2aef0b", subkey2_hex);
    assert_streq("b45886fe09f7b9b06315e48922e8f89cf253ab1eae932d3242fe874ea4dac25f", subkey3_hex);
    assert_streq(
        "dfdcd22e49d36e5433b7331b5b2c02e5b7601f8bb32a315f6e13da2f1d10560d3b76d31d2bb299"
        "d6b30b15a07dea6232f9ae",
        subkey4_hex);
}

static void
test_sign(void)
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
    hydro_sign_update(&st, msg + (sizeof msg) / 3, (sizeof msg) - (sizeof msg) / 3);
    assert(hydro_sign_final_verify(&st, sig, kp.pk) == 0);

    hydro_sign_init(&st, ctx);
    hydro_sign_update(&st, msg, (sizeof msg) / 3);
    hydro_sign_update(&st, msg + (sizeof msg) / 3, (sizeof msg) - (sizeof msg) / 3);
    hydro_sign_final_create(&st, sig, kp.sk);

    hydro_sign_init(&st, ctx);
    hydro_sign_update(&st, msg, (sizeof msg) / 3);
    hydro_sign_update(&st, msg + (sizeof msg) / 3, (sizeof msg) - (sizeof msg) / 3);
    assert(hydro_sign_final_verify(&st, sig, kp.pk) == 0);

    hydro_sign_init(&st, ctx);
    hydro_sign_update(&st, msg, (sizeof msg) / 3);
    hydro_sign_update(&st, msg + (sizeof msg) / 3, (sizeof msg) - (sizeof msg) / 3);
    sig[0]++;
    assert(hydro_sign_final_verify(&st, sig, kp.pk) == -1);

    hydro_sign_create(sig, msg, 0, ctx, kp.sk);
    assert(hydro_sign_verify(sig, msg, sizeof msg, ctx, kp.pk) == -1);
    assert(hydro_sign_verify(sig, msg, 0, ctx, kp.pk) == 0);
}

static void
test_kx(void)
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
    hydro_kx_xx_3(&st_client, &kp_client, response3, NULL, response2, NULL, &client_static_kp);
    hydro_kx_xx_4(&st_server, &kp_server, NULL, response3, NULL);

    assert(hydro_equal(kp_client.tx, kp_server.rx, hydro_kx_SESSIONKEYBYTES));
    assert(hydro_equal(kp_client.rx, kp_server.tx, hydro_kx_SESSIONKEYBYTES));

    randombytes_buf(psk, sizeof psk);
    hydro_kx_xx_1(&st_client, response1, psk);
    hydro_kx_xx_2(&st_server, response2, response1, psk, &server_static_kp);
    hydro_kx_xx_3(&st_client, &kp_client, response3, client_peer_pk, response2, psk,
                  &client_static_kp);
    hydro_kx_xx_4(&st_server, &kp_server, server_peer_pk, response3, psk);

    assert(hydro_equal(kp_client.tx, kp_server.rx, hydro_kx_SESSIONKEYBYTES));
    assert(hydro_equal(kp_client.rx, kp_server.tx, hydro_kx_SESSIONKEYBYTES));
    assert(hydro_equal(client_peer_pk, server_static_kp.pk, hydro_kx_PUBLICKEYBYTES));
    assert(hydro_equal(server_peer_pk, client_static_kp.pk, hydro_kx_PUBLICKEYBYTES));
}

static void
test_pwhash(void)
{
    uint8_t            master_key[hydro_pwhash_MASTERKEYBYTES];
    uint8_t            new_master_key[hydro_pwhash_MASTERKEYBYTES];
    uint8_t            stored[hydro_pwhash_STOREDBYTES];
    uint8_t            h[64];
    uint8_t            static_key[64];
    char               h_hex[2 * 64 + 1];
    unsigned long long ops = 1000;

    memset(master_key, 'x', sizeof master_key);
    hydro_pwhash_deterministic(h, sizeof h, "test", sizeof "test" - 1, ctx, master_key, ops, 0, 1);
    hydro_bin2hex(h_hex, sizeof h_hex, h, sizeof h);
    if (ops == 1000) {
        assert_streq(
            "5e1d6adfb99d0067ae5bf8677c4e9bd7fe4cc7ea482aa0f673bdfd85d04e3257af17a354304d5f9c9be52a"
            "c8bcdbe1c9e445280831885c70093d8ca45aad849a",
            h_hex);
    }

    hydro_pwhash_keygen(master_key);
    assert(hydro_pwhash_create(stored, "test", sizeof "test" - 1, master_key, ops, 0, 1) == 0);
    assert(hydro_pwhash_verify(stored, "test", sizeof "test" - 1, master_key, ops, 0, 1) == 0);
    assert(hydro_pwhash_verify(stored, "test", sizeof "test" - 1, master_key, ops * 2, 10, 10) ==
           0);
    assert(hydro_pwhash_verify(stored, "test", sizeof "test" - 1, master_key, ops / 2, 10, 10) ==
           -1);
    assert(hydro_pwhash_verify(stored, "Test", sizeof "Test" - 1, master_key, ops, 0, 1) == -1);
    assert(hydro_pwhash_verify(stored, "test", sizeof "tes" - 1, master_key, ops, 0, 1) == -1);

    assert(hydro_pwhash_derive_static_key(static_key, sizeof static_key, stored, "test",
                                          sizeof "test" - 1, ctx, master_key, ops, 0, 1) == 0);
    assert(hydro_pwhash_derive_static_key(static_key, sizeof static_key, stored, "Test",
                                          sizeof "Test" - 1, ctx, master_key, ops, 0, 1) == -1);

    assert(hydro_pwhash_reencrypt(stored, master_key, master_key) == 0);
    assert(hydro_pwhash_verify(stored, "test", sizeof "test" - 1, master_key, ops, 0, 1) == 0);
    hydro_pwhash_keygen(new_master_key);
    assert(hydro_pwhash_reencrypt(stored, master_key, new_master_key) == 0);
    assert(hydro_pwhash_verify(stored, "test", sizeof "test" - 1, master_key, ops, 0, 1) == -1);
    assert(hydro_pwhash_verify(stored, "test", sizeof "test" - 1, new_master_key, ops, 0, 1) == 0);

    assert(hydro_pwhash_upgrade(stored, new_master_key, ops * 2, 0, 1) == 0);
    assert(hydro_pwhash_verify(stored, "test", sizeof "test" - 1, new_master_key, ops, 0, 1) == -1);
    assert(hydro_pwhash_verify(stored, "test", sizeof "test" - 1, new_master_key, ops * 2, 0, 1) ==
           0);
}

int
main(void)
{
    int ret;

    ret = hydro_init();
    assert(ret == 0);

    test_core();
    test_hash();
    test_kdf();
    test_kx();
    test_pwhash();
    test_randombytes();
    test_secretbox();
    test_sign();

    return 0;
}

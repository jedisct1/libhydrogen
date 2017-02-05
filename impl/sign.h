#define hydro_sign_CHALLENGEBYTES 32
#define hydro_sign_NONCEBYTES 32
#define hydro_sign_PUBLICKEYBYTES 32
#define hydro_sign_SECRETKEYBYTES 32
#define hydro_sign_BYTES (hydro_sign_NONCEBYTES + hydro_x25519_BYTES)

static void hydro_sign_p2(uint8_t sig[hydro_x25519_BYTES],
    const uint8_t                  challenge[hydro_x25519_BYTES],
    const uint8_t                  eph_sk[hydro_x25519_BYTES],
    const uint8_t                  sk[hydro_x25519_BYTES])
{
    hydro_x25519_scalar_t scalar1, scalar2, scalar3;

    hydro_x25519_swapin(scalar1, eph_sk);
    hydro_x25519_swapin(scalar2, sk);
    hydro_x25519_swapin(scalar3, challenge);
    hydro_x25519_sc_montmul(scalar1, scalar2, scalar3);
    memset(scalar2, 0, sizeof scalar2);
    hydro_x25519_sc_montmul(scalar2, scalar1, hydro_x25519_sc_r2);
    hydro_x25519_swapout(sig, scalar2);
}

static void hydro_x25519_sign_challenge(uint8_t csig[hydro_sign_BYTES],
    const uint8_t              challenge[hydro_sign_CHALLENGEBYTES],
    const uint8_t              sk[hydro_sign_SECRETKEYBYTES])
{
    uint8_t *nonce  = &csig[0];
    uint8_t *sig    = &csig[hydro_sign_NONCEBYTES];
    uint8_t *eph_sk = sig;

    randombytes_buf(eph_sk, hydro_sign_SECRETKEYBYTES);
    hydro_x25519_scalarmult_base_uniform(nonce, eph_sk);
    hydro_sign_p2(sig, challenge, eph_sk, sk);
}

static int hydro_sign_verify_core(
    hydro_x25519_fe xs[5], const hydro_x25519_limb_t *other1, const uint8_t other2[hydro_x25519_BYTES])
{
    hydro_x25519_fe           xo2;
    const hydro_x25519_limb_t sixteen = 16;
    hydro_x25519_limb_t *     z2 = xs[1], *x3 = xs[2], *z3 = xs[3];

    hydro_x25519_swapin(xo2, other2);
    memcpy(x3, other1, 2 * sizeof(hydro_x25519_fe));
    hydro_x25519_ladder_part1(xs);

    /* Here z2 = t2^2 */
    hydro_x25519_mul1(z2, other1);
    hydro_x25519_mul1(z2, other1 + hydro_x25519_NLIMBS);
    hydro_x25519_mul1(z2, xo2);

    hydro_x25519_mul(z2, z2, &sixteen, 1);

    hydro_x25519_mul1(z3, xo2);
    hydro_x25519_sub(z3, z3, x3);
    hydro_x25519_sqr1(z3);

    /* check equality */
    hydro_x25519_sub(z3, z3, z2);

    /* canon(z2): both sides are zero. canon(z3): the two sides are equal. */
    /* Reject sigs where both sides are zero. */
    return hydro_x25519_canon(z2) | ~hydro_x25519_canon(z3);
}

static int hydro_sign_verify_p2(const uint8_t sig[hydro_x25519_BYTES],
    const uint8_t challenge[hydro_sign_CHALLENGEBYTES],
    const uint8_t nonce[hydro_sign_NONCEBYTES],
    const uint8_t pk[hydro_x25519_BYTES])
{
    hydro_x25519_fe xs[7];

    hydro_x25519_core(&xs[0], challenge, pk, 0);
    hydro_x25519_core(&xs[2], sig, hydro_x25519_BASE_POINT, 0);

    return hydro_sign_verify_core(&xs[2], xs[0], nonce);
}

static int hydro_sign_verify_challenge(const uint8_t csig[hydro_sign_BYTES],
    const uint8_t                      challenge[hydro_sign_CHALLENGEBYTES],
    const uint8_t                      pk[hydro_sign_PUBLICKEYBYTES])
{
    const uint8_t *nonce = &csig[0];
    const uint8_t *sig   = &csig[hydro_sign_NONCEBYTES];

    return hydro_sign_verify_p2(sig, challenge, nonce, pk);
}

/* add a keypair_seed */
static int hydro_sign_keypair(uint8_t pk[hydro_sign_PUBLICKEYBYTES],
    uint8_t                           sk[hydro_sign_SECRETKEYBYTES])
{
    randombytes_buf(sk, hydro_sign_SECRETKEYBYTES);
    hydro_x25519_scalarmult_base_uniform(pk, sk);

    return 0;
}

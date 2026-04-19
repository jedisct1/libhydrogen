#include <hw_rng.h>
#include <rtthread.h>

#define DBG_TAG "libhydrogen"
#define DBG_LVL DBG_LOG
#include <rtdbg.h>

static int
hydrogen_init(void)
{
    if (hydro_init() != 0) {
        abort();
    }
    LOG_I("libhydrogen initialized");
    return 0;
}
INIT_APP_EXPORT(hydrogen_init);

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    uint16_t         ebits = 0;
    uint32_t         prev = 0;
    uint8_t          have_prev = 0;
    uint16_t         retries = 0;

    hydro_hash_init(&st, ctx, NULL);

    while (ebits < 256) {
        uint32_t r = rt_hwcrypto_rng_update();

        /* Reject stuck output instead of seeding from repeated hardware RNG words. */
        if (have_prev != 0 && r == prev) {
            if (++retries >= 32) {
                return -1;
            }
            continue;
        }
        prev = r;
        have_prev = 1;
        retries = 0;

        hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
        ebits += 32;
    }

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

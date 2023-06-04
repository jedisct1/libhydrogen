#if defined(CH32V30x_D8) || defined(CH32V30x_D8C)
# include <ch32v30x_rng.h>
#else
# error CH32 implementation missing!
#endif

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    uint16_t         ebits = 0;

    // Enable RNG clock source
    RCC_AHBPeriphClockCmd(RCC_AHBPeriph_RNG, ENABLE);

    // RNG Peripheral enable
    RNG_Cmd(ENABLE);

    hydro_hash_init(&st, ctx, NULL);

    while (ebits < 256) {
        while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET);
        uint32_t r = RNG_GetRandomNumber();

        hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
        ebits += 32;
    }

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

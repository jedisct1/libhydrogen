#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Declarations from ChibiOS HAL TRNG module */

extern struct hal_trng_driver TRNGD1;

void trngStart(struct hal_trng_driver *, const void *);
bool trngGenerate(struct hal_trng_driver *, size_t size, uint8_t *);

static int
hydro_random_init(void)
{
    trngStart(&TRNGD1, NULL);

    if (trngGenerate(&TRNGD1, sizeof hydro_random_context.state,
                     hydro_random_context.state)) {
        return -1;
    }
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

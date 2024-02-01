#include <zephyr/random/rand32.h>

static int
hydro_random_init(void)
{
    if (sys_csrand_get(&hydro_random_context.state, sizeof hydro_random_context.state) != 0) {
        return -1;
    }

    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

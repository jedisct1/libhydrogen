/* The application has to provide arc4random_buf(). */

static int
hydro_random_init(void)
{
    arc4random_buf(hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}


// Use hardware RNG peripheral
// Working with HAL, LL Driver (untested)
#if defined(STM32F4) || defined(STM32L4)

# if defined(STM32F4)
#  include "stm32f4xx.h"
# elif defined(STM32L4)
#  include "stm32l4xx_hal_rng.h"

static RNG_HandleTypeDef RngHandle;
# endif

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    uint16_t         ebits = 0;

    __IO uint32_t tmpreg;

# if defined(STM32F4)
    // Enable RNG clock source
    SET_BIT(RCC->AHB2ENR, RCC_AHB2ENR_RNGEN);

    // Delay after an RCC peripheral clock enabling
    tmpreg = READ_BIT(RCC->AHB2ENR, RCC_AHB2ENR_RNGEN);
    UNUSED(tmpreg);

    // RNG Peripheral enable
    SET_BIT(RNG->CR, RNG_CR_RNGEN);
# elif defined(STM32L4)
    RngHandle.Instance = RNG;
    HAL_RNG_Init(&RngHandle);
# endif

    hydro_hash_init(&st, ctx, NULL);

    while (ebits < 256) {
        uint32_t r = 0;
# if defined(STM32F4)
        while (!(READ_BIT(RNG->SR, RNG_SR_DRDY))) {
        }

        r = RNG->DR;
# elif defined(STM32L4)
        if (HAL_RNG_GenerateRandomNumber(&RngHandle, &r) != HAL_OK) {
            continue;
        }
# endif
        hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
        ebits += 32;
    }

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}
#else
# error SMT32 implementation missing!
#endif

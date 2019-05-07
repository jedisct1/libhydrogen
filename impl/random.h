static TLS struct {
    _hydro_attr_aligned_(16) uint8_t state[gimli_BLOCKBYTES];
    uint64_t counter;
    uint8_t  initialized;
    uint8_t  available;
} hydro_random_context;

#if defined(AVR) && !defined(__unix__)
#include <Arduino.h>

static bool
hydro_random_rbit(uint16_t x)
{
    uint8_t x8;

    x8 = ((uint8_t) (x >> 8)) ^ (uint8_t) x;
    x8 = (x8 >> 4) ^ (x8 & 0xf);
    x8 = (x8 >> 2) ^ (x8 & 0x3);
    x8 = (x8 >> 1) ^ x8;

    return (bool) (x8 & 1);
}

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    uint16_t         ebits = 0;
    uint16_t         tc;
    bool             a, b;

    cli();
    MCUSR = 0;
    WDTCSR |= _BV(WDCE) | _BV(WDE);
    WDTCSR = _BV(WDIE);
    sei();

    hydro_hash_init(&st, ctx, NULL);

    while (ebits < 256) {
        delay(1);
        tc = TCNT1;
        hydro_hash_update(&st, (const uint8_t *) &tc, sizeof tc);
        a = hydro_random_rbit(tc);
        delay(1);
        tc = TCNT1;
        b  = hydro_random_rbit(tc);
        hydro_hash_update(&st, (const uint8_t *) &tc, sizeof tc);
        if (a == b) {
            continue;
        }
        hydro_hash_update(&st, (const uint8_t *) &b, sizeof b);
        ebits++;
    }

    cli();
    MCUSR = 0;
    WDTCSR |= _BV(WDCE) | _BV(WDE);
    WDTCSR = 0;
    sei();

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

ISR(WDT_vect) {}

#elif defined(STM32) && !defined(__unix__)

/*
 * We can not easily guess what series of micro-controllers are being used so
 * we exploit the fact that STM32CubeMX (the standard project generator from ST)
 * generates the required includes in main.h
 */
#include "main.h"

/*
 * We support two types of entropy - the "True Random Number Generator" (RNG)
 * peripheral and/or the entropy generated from the LPTIM1 timer peripheral
 * which we asynchronously drive using the 37KHz LSI clock - the differences
 * between the main clock and the LSI clock become our entropy
 *
 * We expect a working and configured 1ms SysTick timer
 *
 * If RNG exists then the user is expected to configure and enable the
 * RNG peripheral before calling hydro_init or hydro_random_reseed
 *
 * If LPTIM1 exists then the user is expected to de-configure and disable the
 * LPTIM1 peripheral before calling hydro_init or hydro_random_reseed
 *
 * If your STM32 micro-controller supports neither of these peripherals then it
 * is currently not supported
 */
# if !defined(RNG) && !defined(LPTIM1)
#  error "The RNG and/or LPTIM1 STM32 peripherals are not found"
# endif

#define STM32_REQUIRED_BITS_FOR_SEED (256U)

#define HYDRO_STM32_DELAY_MS(ms) do {                                          \
    uint32_t _ms = ms;                                                         \
    __IO uint32_t tmpreg = SysTick->CTRL;                                      \
    (void)tmpreg;                                                              \
    while (_ms) {                                                              \
        if (READ_BIT(SysTick->CTRL, SysTick_CTRL_COUNTFLAG_Msk)) {             \
            _ms--;                                                             \
        }                                                                      \
    }                                                                          \
} while (0)

#define STM32_LSI_READY_TIMEOUT_MS       (2U)
#define STM32_RNG_READY_TIMEOUT_MS       (2U)
#define STM32_LPTIM_READ_TRIES_MAX       (100U)

# if defined(RNG)
static int
hydro_random_get_rng_r(uint32_t *r)
{
    uint32_t timeout = STM32_RNG_READY_TIMEOUT_MS;

    /* wait for DRDY ready flag */
    while (!READ_BIT(RNG->SR, RNG_SR_DRDY)) {
        if (READ_BIT(SysTick->CTRL, SysTick_CTRL_COUNTFLAG_Msk)) {
            if (--timeout == 0U) {
                return -1;
            }
        }
    }

    /* check for errors */
    if (READ_BIT(RNG->SR, RNG_SR_CECS) || READ_BIT(RNG->SR, RNG_SR_SECS)) {
        return -1;
    }

    *r = (uint32_t) READ_REG(RNG->DR);

    return 0;
}
# endif /* defined(RNG) */

# if defined(LPTIM1)
static int
hydro_random_get_lptim_c(uint16_t *c)
{
    uint16_t c1, c2;
    unsigned int tries;

    /*
     * When the LPTIM1 instance is running with an asynchronous clock,
     * reading the CNT register may return unreliable values
     *
     * So it is necessary to perform two consecutive reads and verify
     * that the two returned values are identical
     */
    tries = STM32_LPTIM_READ_TRIES_MAX;
    do {
        c1 = (uint16_t) READ_BIT(LPTIM1->CNT, LPTIM_CNT_CNT);
        c2 = (uint16_t) READ_BIT(LPTIM1->CNT, LPTIM_CNT_CNT);
    } while (c1 != c2 || --tries == 0U);

    if (tries == 0U) {
        return -1;
    }

    *c = c1;

    return 0;
}

static bool
hydro_random_rbit(uint16_t x)
{
    uint8_t x8;

    x8 = ((uint8_t) (x >> 8)) ^ (uint8_t) x;
    x8 = (x8 >> 4) ^ (x8 & 0xf);
    x8 = (x8 >> 2) ^ (x8 & 0x3);
    x8 = (x8 >> 1) ^ x8;

    return (bool) (x8 & 1);
}
# endif /* defined(LPTIM1) */

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    unsigned int     ebits_rng = 0U, ebits_lptim = 0U;

    hydro_hash_init(&st, ctx, NULL);

# if defined(RNG)
    for (;;) {
        bool old_ie;

        /* Check if the RNG peripheral's clock is enabled */
#  if defined (RCC_AHBENR_RNGEN)
        if (!READ_BIT(RCC->AHBENR, RCC_AHBENR_RNGEN)) {
            break;
        }
#  elif defined(RCC_AHB1ENR_RNGEN)
        if (!READ_BIT(RCC->AHB1ENR, RCC_AHB1ENR_RNGEN)) {
            break;
        }
#  elif defined(RCC_AHB2ENR_RNGEN)
        if (!READ_BIT(RCC->AHB2ENR, RCC_AHB2ENR_RNGEN)) {
            break;
        }
#  elif defined(RCC_AHB3ENR_RNGEN)
        if (!READ_BIT(RCC->AHB3ENR, RCC_AHB3ENR_RNGEN)) {
            break;
        }
#  else
#   error "unsupported STM32 RNG peripheral"
#  endif

        /* Check if the RNG peripheral is enabled */
        if (!READ_BIT(RNG->CR, RNG_CR_RNGEN)) {
            break;
        }

        /*
         * We will temporarily disable RNG's interrupt so that we can be sure
         * that we are the only consumer of its output
         */
        old_ie = READ_BIT(RNG->CR, RNG_CR_IE);
        if (old_ie) {
            CLEAR_BIT(RNG->CR, RNG_CR_IE);
        }

        while (ebits_rng < STM32_REQUIRED_BITS_FOR_SEED) {
            uint32_t r;

            if (hydro_random_get_rng_r(&r) != 0) {
                break;
            }
            hydro_hash_update(&st, (const uint8_t *) &r, sizeof r);

            ebits_rng += 8U * sizeof r;
        }

        /* Re-enable the RNG interrupt if it was enabled previously */
        if (old_ie) {
            SET_BIT(RNG->CR, RNG_CR_IE);
        }

        break;
    }
# endif /* defined(RNG) */

# if defined(LPTIM1)
    for (;;) {
        /*
         * We need the LPTIM1 to be free, if it is being used the user should
         * restructure their program so that they don't use the LPTIM1 when
         * initializing or reseeding the random number generator
         */
#  if defined(RCC_APB1ENR_LPTIM1EN)
        if (READ_BIT(RCC->APB1ENR, RCC_APB1ENR_LPTIM1EN) &&
                READ_BIT(LPTIM1->CR, LPTIM_CR_ENABLE)) {
            break;
        }
#  elif defined(RCC_APB1ENR1_LPTIM1EN)
        if (READ_BIT(RCC->APB1ENR1, RCC_APB1ENR1_LPTIM1EN) &&
                READ_BIT(LPTIM1->CR, LPTIM_CR_ENABLE)) {
            break;
        }
#  else
#   error "Unsupported STM32 LPTIM1 peripheral"
#  endif

        /* We need the SysTick enabled */
        if (!READ_BIT(SysTick->CTRL, SysTick_CTRL_ENABLE_Msk)) {
            break;
        }

        /* Enable the low-precision LSI clock if it is disabled */
        if (READ_BIT(RCC->CSR, RCC_CSR_LSIRDY) != RCC_CSR_LSIRDY) {
            uint32_t timeout = STM32_LSI_READY_TIMEOUT_MS;

            SET_BIT(RCC->CSR, RCC_CSR_LSION);

            /* Wait for LSI to be ready, with timeout */
            while (READ_BIT(RCC->CSR, RCC_CSR_LSIRDY) != RCC_CSR_LSIRDY) {
                if (READ_BIT(SysTick->CTRL, SysTick_CTRL_COUNTFLAG_Msk)) {
                    if (--timeout == 0U) {
                        break;
                    }
                }
            }
            if (timeout == 0U) {
                break;
            }
        }

        /* Enable LPTIM1's peripheral clock if it is disabled */
#  if defined(RCC_APB1ENR_LPTIM1EN)
        if (!READ_BIT(RCC->APB1ENR, RCC_APB1ENR_LPTIM1EN)) {
            __IO uint32_t tmpreg;

            SET_BIT(RCC->APB1ENR, RCC_APB1ENR_LPTIM1EN);

            /* a tiny delay is needed after an RCC peripheral clock enabling */
            tmpreg = READ_BIT(RCC->APB1ENR, RCC_APB1ENR_LPTIM1EN);
            (void)tmpreg;
        }
#  elif defined(RCC_APB1ENR1_LPTIM1EN)
        if (!READ_BIT(RCC->APB1ENR1, RCC_APB1ENR1_LPTIM1EN)) {
            __IO uint32_t tmpreg;

            SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_LPTIM1EN);

            /* A tiny delay is needed after an RCC peripheral clock enabling */
            tmpreg = READ_BIT(RCC->APB1ENR1, RCC_APB1ENR1_LPTIM1EN);
            (void)tmpreg;
        }
#  else
#   error "unsupported STM32 LPTIM1 peripheral"
#  endif

        /* Make sure we have the desired configuration of LPTIM1 */
        CLEAR_BIT(LPTIM1->CFGR,
                  LPTIM_CFGR_CKSEL     | /* don't use an external clock */
                  LPTIM_CFGR_PRESC     | /* don't use a clock pre-scaler */
                  LPTIM_CFGR_WAVPOL    | /* don't use an inverted polarity */
                  LPTIM_CFGR_PRELOAD   | /* don't preload the registers */
                  LPTIM_CFGR_COUNTMODE | /* don't use an external counter */
                  LPTIM_CFGR_TRIGEN    | /* use software trigger */
                  0U);

        /* Use the LSI's clock as LPTIM1's clock source */
        MODIFY_REG(RCC->CCIPR, RCC_CCIPR_LPTIM1SEL,
                   (uint32_t)RCC_CCIPR_LPTIM1SEL_0);

        /* Enable LPTIM1 */
        SET_BIT(LPTIM1->CR, LPTIM_CR_ENABLE);

        /* Set autoreload value to the maximum */
        LPTIM1->ARR = UINT16_MAX;

        /* Start LPTIM1's counter */
        MODIFY_REG(LPTIM1->CR,
                   LPTIM_CR_CNTSTRT | LPTIM_CR_SNGSTRT, LPTIM_CR_CNTSTRT);

        while (ebits_lptim < STM32_REQUIRED_BITS_FOR_SEED) {
            uint16_t c;
            bool     a, b;

            HYDRO_STM32_DELAY_MS(1U);
            if (hydro_random_get_lptim_c(&c) != 0) {
                break;
            }
            hydro_hash_update(&st, (const uint8_t *) &c, sizeof c);
            a = hydro_random_rbit(c);

            HYDRO_STM32_DELAY_MS(1U);
            if (hydro_random_get_lptim_c(&c) != 0) {
                break;
            }
            hydro_hash_update(&st, (const uint8_t *) &c, sizeof c);
            b = hydro_random_rbit(c);

            if (a == b) {
                continue;
            }

            hydro_hash_update(&st, (const uint8_t *) &b, sizeof b);

            ebits_lptim++;
        }

        /* Disable LPTIM1 */
        CLEAR_BIT(LPTIM1->CR, LPTIM_CR_ENABLE);

        break;
    }
# endif /* defined(LPTIM1) */

    if (ebits_rng + ebits_lptim < STM32_REQUIRED_BITS_FOR_SEED) {
        return -1;
    }

    hydro_hash_final(&st, hydro_random_context.state,
                     sizeof hydro_random_context.state);

    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

#elif (defined(ESP32) || defined(ESP8266)) && !defined(__unix__)

// Important: RF *must* be activated on ESP board
// https://techtutorialsx.com/2017/12/22/esp32-arduino-random-number-generation/

#include <esp_system.h>

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    uint16_t         ebits = 0;

    hydro_hash_init(&st, ctx, NULL);

    while (ebits < 256) {
        uint32_t r = esp_random();

        delay(10);
        hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
        ebits += 32;
    }

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

#elif (defined(NRF52832_XXAA) || defined(NRF52832_XXAB)) && !defined(__unix__)

// Important: The SoftDevice *must* be activated to enable reading from the RNG
// http://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.nrf52832.ps.v1.1%2Frng.html

#include <nrf_soc.h>

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    const uint8_t    total_bytes = 32;
    uint8_t          remaining_bytes = total_bytes;
    uint8_t          available_bytes;
    uint8_t          rand_buffer[32];

    hydro_hash_init(&st, ctx, NULL);

    for (;;) {
        if (sd_rand_application_bytes_available_get(&available_bytes) != NRF_SUCCESS) {
            return -1;
        }
        if (available_bytes > 0) {
            if (available_bytes > remaining_bytes) {
                available_bytes = remaining_bytes;
            }
            if (sd_rand_application_vector_get(rand_buffer, available_bytes) != NRF_SUCCESS) {
                return -1;
            }
            hydro_hash_update(&st, rand_buffer, total_bytes);
            remaining_bytes -= available_bytes;
        }
        if (remaining_bytes <= 0) {
            break;
        }
        delay(10);
    }
    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

#elif defined(_WIN32)

#include <windows.h>
#define RtlGenRandom SystemFunction036
#if defined(__cplusplus)
extern "C"
#endif
    BOOLEAN NTAPI
            RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#pragma comment(lib, "advapi32.lib")

static int
hydro_random_init(void)
{
    if (!RtlGenRandom((PVOID) hydro_random_context.state,
                      (ULONG) sizeof hydro_random_context.state)) {
        return -1;
    }
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

#elif defined(__wasi__)

#include <unistd.h>

static int
hydro_random_init(void)
{
    if (getentropy(hydro_random_context.state,
                   sizeof hydro_random_context.state) != 0) {
        return -1;
    }
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

#elif defined(__unix__)

#include <errno.h>
#include <fcntl.h>
#ifdef __linux__
# include <poll.h>
#endif
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
static int
hydro_random_block_on_dev_random(void)
{
    struct pollfd pfd;
    int           fd;
    int           pret;

    fd = open("/dev/random", O_RDONLY);
    if (fd == -1) {
        return 0;
    }
    pfd.fd      = fd;
    pfd.events  = POLLIN;
    pfd.revents = 0;
    do {
        pret = poll(&pfd, 1, -1);
    } while (pret < 0 && (errno == EINTR || errno == EAGAIN));
    if (pret != 1) {
        (void) close(fd);
        errno = EIO;
        return -1;
    }
    return close(fd);
}
#endif

static ssize_t
hydro_random_safe_read(const int fd, void *const buf_, size_t len)
{
    unsigned char *buf = (unsigned char *) buf_;
    ssize_t        readnb;

    do {
        while ((readnb = read(fd, buf, len)) < (ssize_t) 0 &&
               (errno == EINTR || errno == EAGAIN)) { }
        if (readnb < (ssize_t) 0) {
            return readnb;
        }
        if (readnb == (ssize_t) 0) {
            break;
        }
        len -= (size_t) readnb;
        buf += readnb;
    } while (len > (ssize_t) 0);

    return (ssize_t)(buf - (unsigned char *) buf_);
}

static int
hydro_random_init(void)
{
    uint8_t tmp[gimli_BLOCKBYTES + 8];
    int     fd;
    int     ret = -1;

#ifdef __linux__
    if (hydro_random_block_on_dev_random() != 0) {
        return -1;
    }
#endif
    do {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd == -1 && errno != EINTR) {
            return -1;
        }
    } while (fd == -1);
    if (hydro_random_safe_read(fd, tmp, sizeof tmp) == (ssize_t) sizeof tmp) {
        memcpy(hydro_random_context.state, tmp, gimli_BLOCKBYTES);
        memcpy(&hydro_random_context.counter, tmp + gimli_BLOCKBYTES, 8);
        hydro_memzero(tmp, sizeof tmp);
        ret = 0;
    }
    ret |= close(fd);

    return ret;
}

#elif defined(TARGET_LIKE_MBED)

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#if defined(MBEDTLS_ENTROPY_C)

static int
hydro_random_init(void)
{
    mbedtls_entropy_context entropy;
    uint16_t                pos = 0;

    mbedtls_entropy_init(&entropy);

    // Pull data directly out of the entropy pool for the state, as it's small enough.
    if (mbedtls_entropy_func(&entropy, (uint8_t *) &hydro_random_context.counter,
                             sizeof hydro_random_context.counter) != 0) {
        return -1;
    }
    // mbedtls_entropy_func can't provide more than MBEDTLS_ENTROPY_BLOCK_SIZE in one go.
    // This constant depends of mbedTLS configuration (whether the PRNG is backed by SHA256/SHA512
    // at this time) Therefore, if necessary, we get entropy multiple times.

    do {
        const uint8_t dataLeftToConsume = gimli_BLOCKBYTES - pos;
        const uint8_t currentChunkSize  = (dataLeftToConsume > MBEDTLS_ENTROPY_BLOCK_SIZE)
                                             ? MBEDTLS_ENTROPY_BLOCK_SIZE
                                             : dataLeftToConsume;

        // Forces mbedTLS to fetch fresh entropy, then get some to feed libhydrogen.
        if (mbedtls_entropy_gather(&entropy) != 0 ||
            mbedtls_entropy_func(&entropy,
                                 &hydro_random_context.state[pos], currentChunkSize) != 0) {
            return -1;
        }
        pos += MBEDTLS_ENTROPY_BLOCK_SIZE;
    } while (pos < gimli_BLOCKBYTES);

    mbedtls_entropy_free(&entropy);

    return 0;
}

#else
# error Need an entropy source
#endif

#else
# error Unsupported platform
#endif

static void
hydro_random_check_initialized(void)
{
    if (hydro_random_context.initialized == 0) {
        if (hydro_random_init() != 0) {
            abort();
        }
        gimli_core_u8(hydro_random_context.state, 0);
        hydro_random_ratchet();
        hydro_random_context.initialized = 1;
    }
}

void
hydro_random_ratchet(void)
{
    mem_zero(hydro_random_context.state, gimli_RATE);
    STORE64_LE(hydro_random_context.state, hydro_random_context.counter);
    hydro_random_context.counter++;
    gimli_core_u8(hydro_random_context.state, 0);
    hydro_random_context.available = gimli_RATE;
}

uint32_t
hydro_random_u32(void)
{
    uint32_t v;

    hydro_random_check_initialized();
    if (hydro_random_context.available < 4) {
        hydro_random_ratchet();
    }
    memcpy(&v, &hydro_random_context.state[gimli_RATE - hydro_random_context.available], 4);
    hydro_random_context.available -= 4;

    return v;
}

uint32_t
hydro_random_uniform(const uint32_t upper_bound)
{
    uint32_t min;
    uint32_t r;

    if (upper_bound < 2U) {
        return 0;
    }
    min = (1U + ~upper_bound) % upper_bound; /* = 2**32 mod upper_bound */
    do {
        r = hydro_random_u32();
    } while (r < min);
    /* r is now clamped to a set whose size mod upper_bound == 0
     * the worst case (2**31+1) requires 2 attempts on average */

    return r % upper_bound;
}

void
hydro_random_buf(void *out, size_t out_len)
{
    uint8_t *p = (uint8_t *) out;
    size_t   i;
    size_t   leftover;

    hydro_random_check_initialized();
    for (i = 0; i < out_len / gimli_RATE; i++) {
        gimli_core_u8(hydro_random_context.state, 0);
        memcpy(p + i * gimli_RATE, hydro_random_context.state, gimli_RATE);
    }
    leftover = out_len % gimli_RATE;
    if (leftover != 0) {
        gimli_core_u8(hydro_random_context.state, 0);
        mem_cpy(p + i * gimli_RATE, hydro_random_context.state, leftover);
    }
    hydro_random_ratchet();
}

void
hydro_random_buf_deterministic(void *out, size_t out_len,
                               const uint8_t seed[hydro_random_SEEDBYTES])
{
    static const uint8_t             prefix[] = { 7, 'd', 'r', 'b', 'g', '2', '5', '6' };
    _hydro_attr_aligned_(16) uint8_t state[gimli_BLOCKBYTES];
    uint8_t *                        p = (uint8_t *) out;
    size_t                           i;
    size_t                           leftover;

    mem_zero(state, gimli_BLOCKBYTES);
    COMPILER_ASSERT(sizeof prefix + 8 <= gimli_RATE);
    memcpy(state, prefix, sizeof prefix);
    STORE64_LE(state + sizeof prefix, (uint64_t) out_len);
    gimli_core_u8(state, 1);
    COMPILER_ASSERT(hydro_random_SEEDBYTES == gimli_RATE * 2);
    mem_xor(state, seed, gimli_RATE);
    gimli_core_u8(state, 2);
    mem_xor(state, seed + gimli_RATE, gimli_RATE);
    gimli_core_u8(state, 2);
    for (i = 0; i < out_len / gimli_RATE; i++) {
        gimli_core_u8(state, 0);
        memcpy(p + i * gimli_RATE, state, gimli_RATE);
    }
    leftover = out_len % gimli_RATE;
    if (leftover != 0) {
        gimli_core_u8(state, 0);
        mem_cpy(p + i * gimli_RATE, state, leftover);
    }
    hydro_random_ratchet();
}

void
hydro_random_reseed(void)
{
    hydro_random_context.initialized = 0;
    hydro_random_check_initialized();
}

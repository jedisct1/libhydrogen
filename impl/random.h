static TLS struct {
    CRYPTO_ALIGN(16) uint8_t state[gimli_BLOCKBYTES];
    uint64_t counter;
    uint8_t  initialized;
    uint8_t  available;
} hydro_random_context;

#if defined(AVR) && !defined(__unix__)
#include <Arduino.h>

static bool
hydro_random_rbit(unsigned int x)
{
    size_t i;
    bool   res = 0;

    for (i = 0; i < sizeof x; i++) {
        res ^= ((x >> i) & 1);
    }
    return res;
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

    hydro_hash_init(&st, ctx, NULL, 0);

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
    hydro_random_context.counter     = LOAD64_LE(hydro_random_context.state);
    hydro_random_context.initialized = 1;

    return 0;
}

ISR(WDT_vect) {}

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
    hydro_random_context.counter     = LOAD64_LE(hydro_random_context.state);
    hydro_random_context.initialized = 1;
    return 0;
}

#elif defined(__unix__)

#include <errno.h>
#include <fcntl.h>
#ifdef __linux__
#include <poll.h>
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
        while ((readnb = read(fd, buf, len)) < (ssize_t) 0 && (errno == EINTR || errno == EAGAIN))
            ;
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
    int fd;
    int ret = -1;

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
    if (hydro_random_safe_read(fd, hydro_random_context.state, sizeof hydro_random_context.state) ==
        (ssize_t) sizeof hydro_random_context.state) {
        hydro_random_context.counter     = LOAD64_LE(hydro_random_context.state);
        ret                              = 0;
        hydro_random_context.initialized = 1;
    }
    ret |= close(fd);

    return ret;
}

#else
#error Unsupported platform
#endif

static void
hydro_random_check_initialized(void)
{
    if (hydro_random_context.initialized == 0) {
        hydro_random_context.available = 0;
        if (hydro_random_init() != 0) {
            abort();
        }
    }
}

void
randombytes_ratchet(void)
{
    mem_zero(hydro_random_context.state, gimli_RATE);
    STORE64_LE(hydro_random_context.state, hydro_random_context.counter);
    hydro_random_context.counter++;
    gimli_core_u8(hydro_random_context.state, 0);
    hydro_random_context.available = gimli_RATE;
}

uint32_t
randombytes_random(void)
{
    uint32_t v;

    hydro_random_check_initialized();
    if (hydro_random_context.available < 4) {
        randombytes_ratchet();
    }
    memcpy(&v, &hydro_random_context.state[gimli_RATE - hydro_random_context.available], 4);
    hydro_random_context.available -= 4;

    return v;
}

uint32_t
randombytes_uniform(const uint32_t upper_bound)
{
    uint32_t min;
    uint32_t r;

    if (upper_bound < 2U) {
        return 0;
    }
    min = (1U + ~upper_bound) % upper_bound; /* = 2**32 mod upper_bound */
    do {
        r = randombytes_random();
    } while (r < min);
    /* r is now clamped to a set whose size mod upper_bound == 0
     * the worst case (2**31+1) requires 2 attempts on average */

    return r % upper_bound;
}

void
randombytes_buf(void *out, size_t out_len)
{
    uint8_t *p = (uint8_t *) out;
    size_t   i;
    size_t   leftover;

    gimli_core_u8(hydro_random_context.state, 0);
    for (i = 0; i < out_len / gimli_RATE; i++) {
        memcpy(p + i * gimli_RATE, hydro_random_context.state, gimli_RATE);
        gimli_core_u8(hydro_random_context.state, 0);
    }
    leftover = out_len % gimli_RATE;
    if (leftover != 0) {
        mem_cpy(p + i * gimli_RATE, hydro_random_context.state, leftover);
    }
    COMPILER_ASSERT(gimli_RATE <= 0xff);
    randombytes_ratchet();
}

void
randombytes_buf_deterministic(void *out, size_t out_len, const uint8_t seed[randombytes_SEEDBYTES])
{
    static const uint8_t      prefix[] = { 7, 'd', 'r', 'b', 'g', '2', '5', '6' };
    CRYPTO_ALIGN(16) uint32_t state[gimli_BLOCKBYTES / 4];
    uint8_t *                 buf = (uint8_t *) (void *) state;
    int                       i;

    COMPILER_ASSERT(sizeof prefix <= gimli_RATE);
    memcpy(buf, prefix, sizeof prefix);
    mem_zero(buf + sizeof prefix, gimli_BLOCKBYTES - sizeof prefix);
    gimli_core_u8(buf, 0);

    COMPILER_ASSERT(randombytes_SEEDBYTES == 2 * gimli_RATE);
    mem_xor(buf, seed, gimli_RATE);
    gimli_core_u8(buf, 0);
    mem_xor(buf, seed + gimli_RATE, gimli_RATE);
    mem_zero(buf, gimli_RATE);
    STORE64_LE(buf, (uint64_t) out_len);
    for (i = 0; out_len > 0; i++) {
        const size_t block_size = (out_len < gimli_BLOCKBYTES) ? out_len : gimli_BLOCKBYTES;
        gimli_core_u8(buf, 0);
        mem_cpy((uint8_t *) out + i * gimli_BLOCKBYTES, buf, block_size);
        out_len -= block_size;
    }
    randombytes_ratchet();
}

void
randombytes_reseed(void)
{
    hydro_random_context.initialized = 0;
    hydro_random_check_initialized();
}

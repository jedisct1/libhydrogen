static uint8_t hydro_random_key[hydro_stream_chacha20_KEYBYTES];
static uint8_t hydro_random_nonce[hydro_stream_chacha20_NONCEBYTES];
static uint8_t hydro_random_initialized;

#if defined(AVR) && !defined(__unix__)
#include <Arduino.h>

static _Bool hydro_random_rbit(unsigned int x)
{
    int   i;
    _Bool res = 0;

    for (i = 0; i < sizeof x; i++) {
        res ^= ((x >> i) & 1);
    }
    return res;
}

static int hydro_random_init(void)
{
    const uint8_t hydrokey[hydro_hash128_KEYBYTES] = { 'h', 'y', 'd', 'r', 'o',
        'g', 'e', 'n', ' ', 'k', 'e', 'y', 's', 'e', 'e', 'd' };
    hydro_hash128_state st;
    uint16_t            ebits = 0;
    uint16_t            tc;
    _Bool               a, b;

    cli();
    MCUSR = 0;
    WDTCSR |= _BV(WDCE) | _BV(WDE);
    WDTCSR = _BV(WDIE);
    sei();

    hydro_hash128_init(&st, hydrokey);

    while (ebits < 256) {
        delay(1);
        tc = TCNT1;
        hydro_hash128_update(&st, (const uint8_t *)&tc, sizeof tc);
        a = hydro_random_rbit(tc);
        delay(1);
        tc = TCNT1;
        b  = hydro_random_rbit(tc);
        hydro_hash128_update(&st, (const uint8_t *)&tc, sizeof tc);
        if (a == b) {
            continue;
        }
        hydro_hash128_update(&st, (const uint8_t *)&b, sizeof b);
        ebits++;
    }

    cli();
    MCUSR = 0;
    WDTCSR |= _BV(WDCE) | _BV(WDE);
    WDTCSR = 0;
    sei();

    COMPILER_ASSERT(hydro_stream_chacha20_KEYBYTES == hydro_hash128_BYTES * 2);
    hydro_hash128_final(&st, hydro_random_key);
    memcpy(hydro_random_key + hydro_hash128_BYTES, hydro_random_key,
        hydro_hash128_BYTES);
    hydro_random_initialized = 1;

    return 0;
}

ISR(WDT_vect)
{
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
static int hydro_random_block_on_dev_random(void)
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
        (void)close(fd);
        errno = EIO;
        return -1;
    }
    return close(fd);
}
#endif

static ssize_t hydro_random_safe_read(
    const int fd, void *const buf_, size_t len)
{
    unsigned char *buf = (unsigned char *)buf_;
    ssize_t        readnb;

    do {
        while ((readnb = read(fd, buf, len)) < (ssize_t)0 &&
               (errno == EINTR || errno == EAGAIN))
            ;
        if (readnb < (ssize_t)0) {
            return readnb;
        }
        if (readnb == (ssize_t)0) {
            break;
        }
        len -= (size_t)readnb;
        buf += readnb;
    } while (len > (ssize_t)0);

    return (ssize_t)(buf - (unsigned char *)buf_);
}

static int hydro_random_init(void)
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
    if (hydro_random_safe_read(fd, hydro_random_key, sizeof hydro_random_key) ==
        (ssize_t)sizeof hydro_random_key) {
        ret                      = 0;
        hydro_random_initialized = 1;
    }
    ret |= close(fd);

    return ret;
}

#else
#error Unsupported platform
#endif

static void hydro_random_check_initialized(void)
{
    if (hydro_random_initialized == 0 && hydro_random_init() != 0) {
        abort();
    }
}

uint32_t randombytes_random(void)
{
    uint32_t v;

    hydro_random_check_initialized();
    if (hydro_random_nonce[0] == 0x0) {
        hydro_stream_chacha20_xor(hydro_random_key, hydro_random_key,
            sizeof hydro_random_key, hydro_random_nonce, hydro_random_key);
    }
    hydro_stream_chacha20(
        (uint8_t *)&v, sizeof v, hydro_random_nonce, hydro_random_key);
    hydro_increment(hydro_random_nonce, sizeof hydro_random_nonce);

    return v;
}

uint32_t randombytes_uniform(const uint32_t upper_bound)
{
    uint32_t min;
    uint32_t r;

    if (upper_bound < 2) {
        return 0;
    }
    min = (uint32_t)(-upper_bound % upper_bound);
    do {
        r = randombytes_random();
    } while (r < min);

    return r % upper_bound;
}

void randombytes_buf(void *const buf, const size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t   i;
    uint32_t v;

    for (i = (size_t)0U; i < len; i += sizeof v) {
        v = randombytes_random();
        memcpy(p + i, &v, sizeof v);
    }
    for (; i < len; i++) {
        p[i] = (uint8_t)randombytes_random();
    }
}

void randombytes_buf_deterministic(void *const buf, const size_t len,
    const uint8_t key[randombytes_buf_deterministic_KEYBYTES])
{
    COMPILER_ASSERT(randombytes_buf_deterministic_KEYBYTES ==
                    hydro_stream_chacha20_KEYBYTES);
    hydro_stream_chacha20(buf, len, zero, key);
}

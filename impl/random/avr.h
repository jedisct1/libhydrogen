#include <avr/interrupt.h> // cli / sei
#include <avr/io.h>
#include <avr/sfr_defs.h> // for _BV
#include <avr/wdt.h> // Watchdog functions

#if !defined(WDIE)
#error Chip does not support Watchdog Interrupt without reset
#endif

volatile uint8_t hydro_rng_avr_tim1_sample       = 0;
volatile uint8_t hydro_rng_avr_tim1_sample_ready = false;
volatile bool    hydro_rng_avr_wdt_active        = false;

// If ISR(WDT_vect) is used in the user application, it has to include HYDRO_RANDOM_WDTISR() to be
// able to work
#if !defined(HYDRO_RNG_USER_WDT_CALLBACK)

// Watchdog Timer Interrupt
ISR(WDT_vect)
{
    hydro_rng_avr_tim1_sample       = TCNT1L;
    hydro_rng_avr_tim1_sample_ready = true;
}

#endif

#if !defined(TCNT2)
#define TIMER1_RESOLUTION 256UL // Timer1 is 8 bit
#else
#define TIMER1_RESOLUTION 65536UL // Timer1 is 16 bit
#endif

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    uint16_t         tim1_period;
    uint8_t          tim1_prescaler;
    uint8_t          ebytes      = 0;
    uint8_t          r           = 0;
    uint8_t          current_bit = 0;
    uint8_t          wdtcsr_bak  = WDTCSR;
    uint8_t          tccr1a_bak  = TCCR1A;
    uint8_t          tccr1b_bak  = TCCR1B;

    // Setup WDT in interrupt mode with no system reset
    cli();
    MCUSR = 0;
    WDTCSR |= _BV(WDCE) | _BV(WDE); // Start timed WDT update sequence
    WDTCSR = _BV(WDIE); // WDT interrupt mode with 16ms
    sei();

    // Init TIM1
    TCCR1B = 0; // stop the timer
    TCCR1A = 0; // clear control register A

// Calculate Timer prescaler
#define TIMER1_US 25000 // shall be larger than WDT timeout of 16000us
    const uint32_t tim1_cycles = ((F_CPU / 100000UL * TIMER1_US) / 20);

    if (tim1_cycles < TIMER1_RESOLUTION) {
        tim1_prescaler = _BV(CS10);
        tim1_period    = tim1_cycles;
    } else if (tim1_cycles < TIMER1_RESOLUTION * 8) {
        tim1_prescaler = _BV(CS11);
        tim1_period    = tim1_cycles / 8;
    } else if (tim1_cycles < TIMER1_RESOLUTION * 64) {
        tim1_prescaler = _BV(CS11) | _BV(CS10);
        tim1_period    = tim1_cycles / 64;
    } else if (tim1_cycles < TIMER1_RESOLUTION * 256) {
        tim1_prescaler = _BV(CS12);
        tim1_period    = tim1_cycles / 256;
    } else if (tim1_cycles < TIMER1_RESOLUTION * 1024) {
        tim1_prescaler = _BV(CS12) | _BV(CS10);
        tim1_period    = tim1_cycles / 1024;
    } else {
        tim1_prescaler = _BV(CS12) | _BV(CS10);
        tim1_period    = TIMER1_RESOLUTION - 1;
    }

    ICR1   = tim1_period;
    TCCR1B = tim1_prescaler;

    // Start gathering randomness for approximately 4 seconds (256 * 16ms)
    hydro_hash_init(&st, ctx, NULL);

    hydro_rng_avr_wdt_active = true;
    do {
        if (hydro_rng_avr_tim1_sample_ready) {
            hydro_rng_avr_tim1_sample_ready = false;

            r = ((r << 1) | (r >> 7)); // rotate result
            r ^= hydro_rng_avr_tim1_sample; // XOR with next sample

            current_bit++;

            if (current_bit > 7) {
                current_bit = 0;
                ebytes++;
                hydro_hash_update(&st, (const uint8_t *) &r, sizeof r);
            }
        }

    } while (ebytes < hydro_random_SEEDBYTES);
    hydro_rng_avr_wdt_active = false;

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    wdt_disable();

    cli();

    // Restore watchdog settings
    MCUSR = 0;
    WDTCSR |= _BV(WDCE) | _BV(WDE); // Start timed WDT update sequence
    WDTCSR = wdtcsr_bak; // restore watchdog control register

    // Restore TIM1 settings
    TCCR1B = 0; // stop the timer
    TCCR1A = 0; // clear control register A

    TCCR1B = tccr1b_bak;
    TCCR1A = tccr1a_bak;

    sei();

    return 0;
}

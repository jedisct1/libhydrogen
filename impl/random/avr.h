// Based on https://electronics.stackexchange.com/a/582756

#include <avr/interrupt.h>
#include <avr/io.h>

static uint8_t
hydro_random_rbyte()
{
    uint8_t rnd = 0, low, high;
    // 20 works really fine for uint8, can be increased to reduce patterns. Each cicle takes
    // around 80us on 16Mhz main clock which give a random nmumber almost every 1.5ms.
    int nConversions = 20;

    for (int i = 0; i < nConversions; i++) {

        if (i % 2 == 0) {
            ADMUX = 0b01001110; // High (1.1V)
        } else {
            ADMUX = 0b01001111; // Low (0V)
        }

        ADCSRA |= 1 << ADSC; // Start a conversion

        // ADSC is cleared when the conversion finishes
        while ((ADCSRA >> ADSC) % 2) {
            // wait for the conversion to complete
        }

        low  = ADCL; // do not swap this sequence. Low has to be fetched first.
        high = ADCH; // the value is always between 0-3
        rnd ^= low;
        rnd ^= high;

        // Lets shift rotate the number;
        uint8_t last = rnd % 2;
        rnd >>= 1;
        rnd |= last << 7;

        // Disable the ADC
        ADCSRA = 0;
        // Enable the ADC with a randomly selected clock Prescaler between 2 and 128. since each
        // conversion takes 13 ADC cycles, at 16Mhz system clock, the ADC will now take something in
        // between 1.6us and 104us for each conversion.
        ADCSRA = 0b10000000 | ((rnd % 4) << 1);
    }
    return rnd;
}

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    uint16_t         ebits = 0;
    uint8_t          r;

    // Disable Watchdog
    cli();
    MCUSR = 0;
    WDTCSR |= _BV(WDCE) | _BV(WDE);
    WDTCSR = _BV(WDIE);
    sei();

    hydro_hash_init(&st, ctx, NULL);

    while (ebits < 256) {
        r = hydro_random_rbyte();
        hydro_hash_update(&st, (const uint8_t *) &r, sizeof r);
        ebits += 8;
    }

    // Enable Watchdog
    cli();
    MCUSR = 0;
    WDTCSR |= _BV(WDCE) | _BV(WDE);
    WDTCSR = 0;
    sei();

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

ISR(WDT_vect)
{
}

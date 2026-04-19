// Important: RF *must* be activated on ESP board
// https://techtutorialsx.com/2017/12/22/esp32-arduino-random-number-generation/
#ifdef ESP32
#    include <esp_system.h>
#    include <bootloader_random.h>
#endif

#ifdef ARDUINO
#    include <Arduino.h>
#endif

static int
hydro_random_init(void)
{
    const char       ctx[hydro_hash_CONTEXTBYTES] = { 'h', 'y', 'd', 'r', 'o', 'P', 'R', 'G' };
    hydro_hash_state st;
    uint16_t         ebits = 0;

    hydro_hash_init(&st, ctx, NULL);
#ifdef ESP32
    bootloader_random_enable();
#endif
    while (ebits < 256) {
        uint32_t r = esp_random();

#ifdef ARDUINO
        delay(10);
#endif
        hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
        ebits += 32;
    }
#ifdef ESP32
    bootloader_random_disable();
#endif

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

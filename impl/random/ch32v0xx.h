/**********************************************************************************
 * File Name          : ch32v0xx.h (Tentative)
 * Author             : Charles Lee Scoville
 * Version            : V0.0.1 (PoC)
 * Start Date         : 2024/01/02
 * Description        : TRNG initialization shim
 *
 * The CH32V0XX does not have a hardware random number generator. This leaves us with
 * only a few options for collecting entropy.
 *
 *  - Attach an entropy source circuit to the chip. (biased Zener, transistor, etc.)
 *  - Use uninitialized data from SRAM proceeding chip power on.
 *  - Timing difference (jitter) between two *independent* clock sources.
 *  - Read some voltage with the ADC and look only at low bit(s).
 *
 *  *TODO* I intend to survey all options and make code for each, and a complete
 *  write up. Until then, at least I have something working today. Tangible PoC
 *  beats "good ideas" that haven't been written yet any day.
 *
 *  *TODO* Compilation flags to switch between the different entropy options
 *  in a way that is transparent to this shim would be really neato.
 *********************************************************************************/

#include <ch32v00x.h>

/* The following external function will be defined in end user code, and should
 * be everything this shim needs beyond itself to work properly. */
extern uint32_t RNG_GetCondensedEntropy(void);

extern int hydro_random_init(void) {
    const char       ctx[hydro_hash_CONTEXTBYTES] = {'h','y','d','r','o','P','R','G'};
    hydro_hash_state st;
    uint16_t         ebits = 0;

    hydro_hash_init(&st, ctx, NULL);

    while (ebits < 512) {

        uint32_t r = RNG_GetCondensedEntropy();

        hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
        ebits += 32;
    }

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state); // @suppress("Field cannot be resolved")
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state); // @suppress("Field cannot be resolved")

    return 0;
}

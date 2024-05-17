/**********************************************************************************
 * File Name          : ch32v0xx.h (Tentative)
 * Author             : Charles Lee Scoville
 * Version            : V0.0.2 (Pull request #153 modifications)
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

/* This must be defined in your CH32V003 project, and must be filled with raw /
 * unfiltered samples from the internal reference voltage, as the name implies*/
extern uint16_t ADC_Channel_Vrefint_value;


uint32_t entropy_condenser_extractor(void) {

	volatile uint64_t entropy_buffer = 0;
	volatile uint8_t entropy_buffer_count = 0;

	volatile uint32_t extract = 0;
	volatile uint8_t extract_count = 0;
	volatile FlagStatus extract_RDY = RESET;

	if ( !((ADC1->CTLR2 & 1) != 0) )
		while(1); /* ADC1 OFF!!! PANIK! */

    while (extract_RDY == RESET) {

    	volatile uint32_t compare = ADC_Channel_Vrefint_value;

		/* Wait for new ADC data */
		while (compare == ADC_Channel_Vrefint_value)
			__NOP();


		entropy_buffer = entropy_buffer << 1;

		entropy_buffer = entropy_buffer + ((ADC_Channel_Vrefint_value & 0x40) == 0x40);

		entropy_buffer_count++;
		if (entropy_buffer_count > 63) {
			entropy_buffer_count = 0;

			for (uint8_t j = 0; (j < 31); j++) {

				/* 64->32 bit Von Neuman extractor */
				if ((entropy_buffer & 1) ^ ((entropy_buffer >> 1) & 1)) {
					extract = (extract << 1)+((entropy_buffer >> 1) & 1);
					extract_count++;
				}

				entropy_buffer = entropy_buffer >> 2;

				if (extract_count > 31) {
					extract_count = 0;
					extract_RDY = SET;
				}
			}
		}
    }
	return extract;
}


extern int hydro_random_init(void) {
    const char       ctx[hydro_hash_CONTEXTBYTES] = {'h','y','d','r','o','P','R','G'};
    hydro_hash_state st;
    uint16_t         ebits = 0;

    hydro_hash_init(&st, ctx, NULL);

    while (ebits < 512) {

        uint32_t r = entropy_condenser_extractor();

        hydro_hash_update(&st, (const uint32_t *) &r, sizeof r);
        ebits += 32;
    }

    hydro_hash_final(&st, hydro_random_context.state, sizeof hydro_random_context.state);
    hydro_random_context.counter = ~LOAD64_LE(hydro_random_context.state);

    return 0;
}

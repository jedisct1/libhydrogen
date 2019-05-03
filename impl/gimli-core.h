#ifndef hydrogen_gimli_core_H
#define hydrogen_gimli_core_H

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#ifdef __SSE2__
# include "gimli-core/sse2.h"
#else
# include "gimli-core/portable.h"
#endif

#include "common.h"
#include "hydrogen_p.h"

static void
gimli_core_u8(uint8_t state_u8[gimli_BLOCKBYTES], uint8_t tag)
{
    state_u8[gimli_BLOCKBYTES - 1] ^= tag;
#ifndef NATIVE_LITTLE_ENDIAN
    uint32_t state_u32[12];
    int      i;

    for (i = 0; i < 12; i++) {
        state_u32[i] = LOAD32_LE(&state_u8[i * 4]);
    }
    gimli_core(state_u32);
    for (i = 0; i < 12; i++) {
        STORE32_LE(&state_u8[i * 4], state_u32[i]);
    }
#else
    gimli_core((uint32_t *) (void *) state_u8); /* state_u8 must be properly aligned */
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* hydrogen_gimli_core_H */

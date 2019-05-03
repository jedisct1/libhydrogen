#ifndef hydrogen_kdf_H
#define hydrogen_kdf_H

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

int
hydro_kdf_derive_from_key(uint8_t *subkey, size_t subkey_len, uint64_t subkey_id,
                          const char    ctx[hydro_kdf_CONTEXTBYTES],
                          const uint8_t key[hydro_kdf_KEYBYTES])
{
    hydro_hash_state st;

    COMPILER_ASSERT(hydro_kdf_CONTEXTBYTES >= hydro_hash_CONTEXTBYTES);
    COMPILER_ASSERT(hydro_kdf_KEYBYTES >= hydro_hash_KEYBYTES);
    if (hydro_hash_init_with_tweak(&st, ctx, subkey_id, key) != 0) {
        return -1;
    }
    return hydro_hash_final(&st, subkey, subkey_len);
}

void
hydro_kdf_keygen(uint8_t key[hydro_kdf_KEYBYTES])
{
    hydro_random_buf(key, hydro_kdf_KEYBYTES);
}

#ifdef __cplusplus
}
#endif

#endif /* hydrogen_kdf_H */

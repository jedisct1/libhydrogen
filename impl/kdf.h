int hydro_kdf_derive_from_key(uint8_t *subkey, size_t subkey_len,
    const uint8_t ctx[hydro_kdf_CONTEXTBYTES], uint64_t subkey_id,
    const uint8_t key[hydro_kdf_KEYBYTES])
{
    hydro_hash_state st;

    COMPILER_ASSERT(hydro_kdf_CONTEXTBYTES == hydro_hash_CONTEXTBYTES);
    if (hydro_hash_init_with_tweak(
            &st, ctx, subkey_id, key, hydro_kdf_KEYBYTES, subkey_len) != 0) {
        return -1;
    }
    return hydro_hash_final(&st, subkey, subkey_len);
}

int
hydro_kdf_derive_from_key(uint8_t *subkey, size_t subkey_len,
                          uint64_t      subkey_id,
                          const char    ctx[hydro_kdf_CONTEXTBYTES],
                          const uint8_t key[hydro_kdf_KEYBYTES])
{
    hydro_hash_state st;

    COMPILER_ASSERT(hydro_kdf_CONTEXTBYTES == hydro_hash_CONTEXTBYTES);
    if (hydro_hash_init_with_tweak(&st, ctx, subkey_id, key,
                                   hydro_kdf_KEYBYTES) != 0) {
        return -1;
    }
    return hydro_hash_final(&st, subkey, subkey_len);
}

void
hydro_kdf_keygen(uint8_t key[hydro_kdf_KEYBYTES])
{
    randombytes_buf(key, hydro_kdf_KEYBYTES);
}

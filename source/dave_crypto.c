static void* DaveGetOrCreateDecryptor(u32 ssrc, u64 userId) {
    for (u32 i = 0; i < g_dave.decryptor_count; ++i) {
        if (g_dave.decryptors[i].ssrc == ssrc) {
            if (g_dave.decryptors[i].userId == 0 && userId != 0) {
                // NOTE(geni): We've learned the userId for this ssrc
                g_dave.decryptors[i].userId = userId;
                char    uid_buf[32];
                String8 uid_str = S8FromU64(userId, uid_buf, sizeof uid_buf);
                void*   ratchet = daveSessionGetKeyRatchet(g_dave.session, uid_str.cstr);
                if (ratchet) {
                    daveDecryptorTransitionToKeyRatchet(g_dave.decryptors[i].decryptor, ratchet);
                    daveKeyRatchetDestroy(ratchet);
                }
            }

            return g_dave.decryptors[i].decryptor;
        }
    }

    if (g_dave.decryptor_count >= DAVE_MAX_DECRYPTORS) {
        return NULL;
    }

    void* dec = daveDecryptorCreate();

    if (userId != 0) {
        char    uid_buf[32];
        String8 uid_str = S8FromU64(userId, uid_buf, sizeof uid_buf);
        void*   ratchet = daveSessionGetKeyRatchet(g_dave.session, uid_str.cstr);
        if (ratchet) {
            daveDecryptorTransitionToKeyRatchet(dec, ratchet);
            daveKeyRatchetDestroy(ratchet);
        }
    }

    g_dave.decryptors[g_dave.decryptor_count].decryptor = dec;
    g_dave.decryptors[g_dave.decryptor_count].ssrc      = ssrc;
    g_dave.decryptors[g_dave.decryptor_count++].userId  = userId;
    return dec;
}

static void DaveApplyKeyRatchetForSsrc(u32 ssrc, u64 userId) {
    if (!g_dave.session || !g_dave.dave_enabled) {
        return;
    }

    char    uid_buf[32];
    String8 uid_str = S8FromU64(userId, uid_buf, sizeof uid_buf);
    void*   ratchet = daveSessionGetKeyRatchet(g_dave.session, uid_str.cstr);
    if (!ratchet) {
        return;
    }

    for (u32 i = 0; i < g_dave.decryptor_count; ++i) {
        if (g_dave.decryptors[i].ssrc == ssrc) {
            daveDecryptorTransitionToKeyRatchet(g_dave.decryptors[i].decryptor, ratchet);
            daveKeyRatchetDestroy(ratchet);
            g_dave.decryptors[i].userId = userId;
            return;
        }
    }

    daveKeyRatchetDestroy(ratchet);
}

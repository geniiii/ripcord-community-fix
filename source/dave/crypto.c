static DAVEKeyRatchetHandle Dave_GetRatchet(u64 userId) {
    char buf[32];
    return daveSessionGetKeyRatchet(g_dave.session, S8_FromU64(userId, buf, sizeof buf).cstr);
}

static void Dave_ApplyRatchet(DAVEDecryptorHandle decryptor, u64 userId) {
    DAVEKeyRatchetHandle ratchet = Dave_GetRatchet(userId);
    if (ratchet) {
        daveDecryptorTransitionToKeyRatchet(decryptor, ratchet);
        daveKeyRatchetDestroy(ratchet);
    }
}

static void Dave_RefreshDecryptors(void) {
    for (u32 i = 0; i < g_dave.ssrc_count; ++i) {
        if (g_dave.ssrcs[i].decryptor) {
            Dave_ApplyRatchet(g_dave.ssrcs[i].decryptor, g_dave.ssrcs[i].userId);
        }
    }
}

static void Dave_DestroyDecryptors(void) {
    for (u32 i = 0; i < g_dave.ssrc_count; ++i) {
        if (g_dave.ssrcs[i].decryptor) {
            daveDecryptorDestroy(g_dave.ssrcs[i].decryptor);
            g_dave.ssrcs[i].decryptor = NULL;
        }
    }
}

static void Dave_SetSsrcUser(u32 ssrc, u64 userId) {
    DaveSsrc* entry = Dave_FindSsrc(ssrc);
    if (!entry) {
        if (g_dave.ssrc_count < DAVE_MAX_USERS) {
            g_dave.ssrcs[g_dave.ssrc_count++] = (DaveSsrc) {
                .ssrc   = ssrc,
                .userId = userId,
            };
        }
        return;
    }
    if (entry->userId == userId) {
        return;
    }
    if (entry->decryptor) {
        daveDecryptorDestroy(entry->decryptor);
        entry->decryptor = NULL;
    }
    entry->userId = userId;
}

static void Dave_RemoveUserSsrcs(u64 userId) {
    for (u32 i = 0; i < g_dave.ssrc_count;) {
        DaveSsrc* entry = &g_dave.ssrcs[i];
        if (entry->userId != userId) {
            ++i;
            continue;
        }
        if (entry->decryptor) {
            daveDecryptorDestroy(entry->decryptor);
        }
        *entry = g_dave.ssrcs[--g_dave.ssrc_count];
    }
}

static DAVEDecryptorHandle Dave_GetDecryptor(u32 ssrc) {
    DaveSsrc* entry = Dave_FindSsrc(ssrc);
    if (!entry) {
        return NULL;
    }
    if (!entry->decryptor) {
        entry->decryptor = daveDecryptorCreate();
        Dave_ApplyRatchet(entry->decryptor, entry->userId);
    }
    return entry->decryptor;
}

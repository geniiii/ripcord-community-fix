static DAVEKeyRatchetHandle DaveGetRatchet(u64 userId) {
    char buf[32];
    return daveSessionGetKeyRatchet(g_dave.session, S8FromU64(userId, buf, sizeof buf).cstr);
}

static void DaveApplyRatchet(DAVEDecryptorHandle decryptor, u64 userId) {
    DAVEKeyRatchetHandle ratchet = DaveGetRatchet(userId);
    if (ratchet) {
        daveDecryptorTransitionToKeyRatchet(decryptor, ratchet);
        daveKeyRatchetDestroy(ratchet);
    }
}

static void DaveRefreshDecryptors(void) {
    for (u32 i = 0; i < g_dave.ssrc_count; ++i) {
        if (g_dave.ssrcs[i].decryptor) {
            DaveApplyRatchet(g_dave.ssrcs[i].decryptor, g_dave.ssrcs[i].userId);
        }
    }
}

static void DaveDestroyDecryptors(void) {
    for (u32 i = 0; i < g_dave.ssrc_count; ++i) {
        if (g_dave.ssrcs[i].decryptor) {
            daveDecryptorDestroy(g_dave.ssrcs[i].decryptor);
            g_dave.ssrcs[i].decryptor = NULL;
        }
    }
}

static void DaveSetSsrcUser(u32 ssrc, u64 userId) {
    DaveSsrc* entry = DaveFindSsrc(ssrc);
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

static void DaveRemoveUserSsrcs(u64 userId) {
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

static DAVEDecryptorHandle DaveGetDecryptor(u32 ssrc) {
    DaveSsrc* entry = DaveFindSsrc(ssrc);
    if (!entry) {
        return NULL;
    }
    if (!entry->decryptor) {
        entry->decryptor = daveDecryptorCreate();
        DaveApplyRatchet(entry->decryptor, entry->userId);
    }
    return entry->decryptor;
}

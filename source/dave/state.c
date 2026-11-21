static DaveState g_dave;

static void* g_binary_msg_signal_fn;
static void* g_qwebsocket_static_meta;

static DaveSsrc* DaveFindSsrc(u32 ssrc) {
    for (u32 i = 0; i < g_dave.ssrc_count; ++i) {
        if (g_dave.ssrcs[i].ssrc == ssrc) {
            return &g_dave.ssrcs[i];
        }
    }
    return NULL;
}

static void DaveAddRecognizedUser(u64 userId) {
    for (u32 i = 0; i < g_dave.recognized_user_count; ++i) {
        if (g_dave.recognized_user_ids[i] == userId) {
            return;
        }
    }
    if (g_dave.recognized_user_count < DAVE_MAX_USERS) {
        g_dave.recognized_user_ids[g_dave.recognized_user_count++] = userId;
    }
}

static void DaveRemoveRecognizedUser(u64 userId) {
    for (u32 i = 0; i < g_dave.recognized_user_count; ++i) {
        if (g_dave.recognized_user_ids[i] == userId) {
            g_dave.recognized_user_ids[i] = g_dave.recognized_user_ids[--g_dave.recognized_user_count];
            return;
        }
    }
}

static void DaveBuildRecognizedUsers(DaveRecognizedUsers* r) {
    u32 count = g_dave.recognized_user_count;
    for (u32 i = 0; i < count; ++i) {
        String8 uid = S8FromU64(g_dave.recognized_user_ids[i], r->bufs[i], 32);
        r->ptrs[i]  = uid.cstr;
    }
    String8 self     = S8FromU64(g_dave.user_id, r->bufs[count], 32);
    r->ptrs[count++] = self.cstr;
    r->count         = count;
}

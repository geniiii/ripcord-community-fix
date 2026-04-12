static DaveState g_dave;

static void* g_binary_msg_signal_fn;
static void* g_qwebsocket_static_meta;

static void DaveAddSsrcMapping(u32 ssrc, u64 userId) {
    for (u32 i = 0; i < g_dave.ssrc_map_count; ++i) {
        if (g_dave.ssrc_map[i].ssrc == ssrc) {
            g_dave.ssrc_map[i].userId = userId;
            return;
        }
    }
    if (g_dave.ssrc_map_count < DAVE_MAX_SSRC_MAP) {
        g_dave.ssrc_map[g_dave.ssrc_map_count].ssrc     = ssrc;
        g_dave.ssrc_map[g_dave.ssrc_map_count++].userId = userId;
    }
}

static u64 DaveLookupUserId(u32 ssrc) {
    for (u32 i = 0; i < g_dave.ssrc_map_count; ++i) {
        if (g_dave.ssrc_map[i].ssrc == ssrc) {
            return g_dave.ssrc_map[i].userId;
        }
    }
    return 0;
}

static void DaveAddConnectedUser(u64 userId) {
    for (u32 i = 0; i < g_dave.connected_user_count; ++i) {
        if (g_dave.connected_user_ids[i] == userId) {
            return;
        }
    }
    if (g_dave.connected_user_count < DAVE_MAX_USERS) {
        g_dave.connected_user_ids[g_dave.connected_user_count++] = userId;
    }
}

static u32 DaveBuildUserPtrs(const char** ptrs, char bufs[][32]) {
    for (u32 i = 0; i < g_dave.connected_user_count; ++i) {
        S8FromU64(g_dave.connected_user_ids[i], bufs[i], 32);
        ptrs[i] = bufs[i];
    }
    return g_dave.connected_user_count;
}

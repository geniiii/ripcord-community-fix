static void HandleDaveExternalSender(u8* data, size_t len) {
    DAVE_LOCK();
    if (!g_dave.session) {
        g_dave.session = daveSessionCreate(NULL, NULL, NULL, NULL);
    }
    if (g_dave.session) {
        daveSessionSetExternalSender(g_dave.session, data, len);
    }
    DAVE_UNLOCK();
}

static void HandleDaveProposals(u8* data, size_t len) {
    DAVE_LOCK();
    if (!g_dave.session) {
        DAVE_UNLOCK();
        return;
    }

    char        uid_bufs[DAVE_MAX_USERS][32];
    const char* user_ptrs[DAVE_MAX_USERS];
    u32         user_count = DaveBuildUserPtrs(user_ptrs, uid_bufs);

    u8*    resp      = NULL;
    size_t resp_size = 0;
    daveSessionProcessProposals(g_dave.session, data, len,
                                user_ptrs, user_count, &resp, &resp_size);
    DAVE_UNLOCK();

    if (resp && resp_size > 0) {
        DaveSendBinary(g_dave.webSocket, DAVE_MLS_COMMIT_WELCOME, resp, resp_size);
        daveFree(resp);
    }
}

static void DaveTransitionReady(i32 transition_id) {
    g_dave.pending_transition_id    = transition_id;
    g_dave.pending_transition_ready = 1;
    DaveSendJson1Int(g_dave.webSocket, VOICE_OP_READY_FOR_TRANSITION,
                     S8Lit("transition_id"), transition_id);
    if (transition_id == 0) {
        DaveCompleteTransition();
    } else if (g_dave.pending_transition_executed && g_dave.pending_transition_id == transition_id) {
        // NOTE(geni): EXECUTE_TRANSITION already arrived
        DaveCompleteTransition();
    }
}

static void HandleDaveAnnounceCommit(u8* data, size_t len) {
    DAVE_LOCK();
    if (!g_dave.session || (len) < 2) {
        DAVE_UNLOCK();
        return;
    }
    i32    transition_id         = ((data)[0] << 8) | (data)[1];
    u8*    commit_data           = (data) + 2;
    size_t commit_len            = (len) -2;
    g_dave.pending_transition_id = transition_id;

    DAVECommitResultHandle result = daveSessionProcessCommit(g_dave.session, commit_data, commit_len);
    DAVE_UNLOCK();

    if (result && !daveCommitResultIsFailed(result) && !daveCommitResultIsIgnored(result)) {
        DebugMsg("ProcessCommit succeeded: transition_id=%d\n", transition_id);
        DaveTransitionReady(transition_id);
    } else if (result && daveCommitResultIsFailed(result)) {
        DebugMsg("ProcessCommit failed\n");
        DaveSendJson1Int(g_dave.webSocket, DAVE_MLS_INVALID_COMMIT,
                         S8Lit("transition_id"), transition_id);
    } else {
        DebugMsg("ProcessCommit ignored\n");
    }
    if (result) {
        daveCommitResultDestroy(result);
    }
}

static void HandleDaveWelcome(u8* data, size_t len) {
    DAVE_LOCK();
    if (!g_dave.session || (len) < 2) {
        DAVE_UNLOCK();
        return;
    }
    i32    transition_id         = ((data)[0] << 8) | (data)[1];
    u8*    welcome_data          = (data) + 2;
    size_t welcome_len           = (len) -2;
    g_dave.pending_transition_id = transition_id;

    char        uid_bufs[DAVE_MAX_USERS][32];
    const char* user_ptrs[DAVE_MAX_USERS];
    u32         user_count = DaveBuildUserPtrs(user_ptrs, uid_bufs);

    DAVEWelcomeResultHandle result = daveSessionProcessWelcome(g_dave.session, welcome_data, welcome_len,
                                                               user_ptrs, user_count);
    DAVE_UNLOCK();

    if (result) {
        DebugMsg("ProcessWelcome succeeded: transition_id=%d\n", transition_id);
        DaveTransitionReady(transition_id);
        daveWelcomeResultDestroy(result);
    } else {
        DebugMsg("ProcessWelcome failed\n");
    }
}

static void HandleDaveBinaryMsg(QByteArray* data) {
    u8* raw = (u8*) QByteArrayConstData(data);
    i32 len = QByteArraySize(data);
    if (len < (i32) sizeof(DaveBinaryHeader)) {
        DebugMsg("DaveBinaryMsg too short: %d bytes\n", len);
        return;
    }

    DaveBinaryHeader* hdr          = (DaveBinaryHeader*) raw;
    u8*               payload      = raw + sizeof(DaveBinaryHeader);
    size_t            payload_size = (size_t) (len - (i32) sizeof(DaveBinaryHeader));

    DAVE_LOCK();
    g_dave.last_seq = ((i32) raw[0] << 8) | (i32) raw[1];
    DAVE_UNLOCK();

    switch (hdr->opcode) {
        case DAVE_MLS_EXTERNAL_SENDER: {
            HandleDaveExternalSender(payload, payload_size);
        } break;

        case DAVE_MLS_PROPOSALS: {
            HandleDaveProposals(payload, payload_size);
        } break;

        case DAVE_MLS_ANNOUNCE_COMMIT: {
            HandleDaveAnnounceCommit(payload, payload_size);
        } break;

        case DAVE_MLS_WELCOME: {
            HandleDaveWelcome(payload, payload_size);
        } break;

        default: {
            DebugMsg("Unhandled binary opcode %d\n", hdr->opcode);
        } break;
    }
}

static void DaveBinarySlotImpl(i32 which, void* this, void* receiver, void** args, u8* ret) {
    Unreferenced(receiver);
    switch (which) {
        case 0: {  // NOTE(geni): Destroy
            free(this);
        } break;

        case 1: {  // NOTE(geni): Call
            QByteArray* data = (QByteArray*) args[1];
            HandleDaveBinaryMsg(data);
        } break;

        case 2: {  // NOTE(geni): Compare
            if (ret) {
                *ret = 0;
            }
        } break;
    }
}

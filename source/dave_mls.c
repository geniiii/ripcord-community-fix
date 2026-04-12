static void HandleDaveExternalSender(const u8* data, size_t len) {
    if (!g_dave.session) {
        return;
    }
    daveSessionSetExternalSender(g_dave.session, data, len);
}

static void HandleDaveProposals(const u8* data, size_t len) {
    if (!g_dave.session) {
        return;
    }

    char        uid_bufs[DAVE_MAX_USERS][32];
    const char* user_ptrs[DAVE_MAX_USERS];
    u32         user_count = DaveBuildUserPtrs(user_ptrs, uid_bufs);

    u8*    resp      = NULL;
    size_t resp_size = 0;
    daveSessionProcessProposals(g_dave.session, data, len,
                                user_ptrs, user_count, &resp, &resp_size);

    if (resp && resp_size > 0) {
        DaveSendBinary(g_dave.webSocket, DAVE_MLS_COMMIT_WELCOME, resp, resp_size);
        daveFree(resp);
    }
}

static void HandleDaveAnnounceCommit(const u8* data, size_t len) {
    if (!g_dave.session || len < 2) {
        return;
    }

    i32       transition_id = (data[0] << 8) | data[1];
    const u8* commit_data   = data + 2;
    size_t    commit_len    = len - 2;

    g_dave.pending_transition_id = transition_id;

    DAVECommitResultHandle result = daveSessionProcessCommit(g_dave.session, commit_data, commit_len);
    if (result && !daveCommitResultIsFailed(result) && !daveCommitResultIsIgnored(result)) {
        DebugMsg("ProcessCommit succeeded: transition_id=%d\n", transition_id);
        g_dave.pending_transition_ready = 1;
        DaveSendJson1Int(g_dave.webSocket, VOICE_OP_READY_FOR_TRANSITION,
                         S8Lit("transition_id"), transition_id);
        if (transition_id == 0) {
            DaveCompleteTransition();
        }
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

static void HandleDaveWelcome(const u8* data, size_t len) {
    if (!g_dave.session || len < 2) {
        return;
    }

    i32       transition_id = (data[0] << 8) | data[1];
    const u8* welcome_data  = data + 2;
    size_t    welcome_len   = len - 2;

    g_dave.pending_transition_id = transition_id;

    char        uid_bufs[DAVE_MAX_USERS][32];
    const char* user_ptrs[DAVE_MAX_USERS];
    u32         user_count = DaveBuildUserPtrs(user_ptrs, uid_bufs);

    DAVEWelcomeResultHandle result = daveSessionProcessWelcome(g_dave.session, welcome_data, welcome_len,
                                                               user_ptrs, user_count);

    if (result) {
        DebugMsg("ProcessWelcome succeeded: transition_id=%d\n", transition_id);
        g_dave.pending_transition_ready = 1;
        DaveSendJson1Int(g_dave.webSocket, VOICE_OP_READY_FOR_TRANSITION,
                         S8Lit("transition_id"), transition_id);
        if (transition_id == 0) {
            DaveCompleteTransition();
        }
        daveWelcomeResultDestroy(result);
    } else {
        DebugMsg("ProcessWelcome failed\n");
    }
}

static void HandleDaveBinaryMsg(DisVLWorker* vw, const QByteArray* qba) {
    Unreferenced(vw);
    const u8* raw = (const u8*) QByteArrayConstData(qba);
    i32       len = QByteArraySize(qba);
    if (len < (i32) sizeof(DaveBinaryHeader)) {
        return;
    }

    const DaveBinaryHeader* hdr     = (const DaveBinaryHeader*) raw;
    const u8*               payload = raw + sizeof(DaveBinaryHeader);
    size_t                  plen    = (size_t) (len - (i32) sizeof(DaveBinaryHeader));

    switch (hdr->opcode) {
        case DAVE_MLS_EXTERNAL_SENDER: HandleDaveExternalSender(payload, plen); break;
        case DAVE_MLS_PROPOSALS: HandleDaveProposals(payload, plen); break;
        case DAVE_MLS_ANNOUNCE_COMMIT: HandleDaveAnnounceCommit(payload, plen); break;
        case DAVE_MLS_WELCOME: HandleDaveWelcome(payload, plen); break;
        default: DebugMsg("Unhandled binary opcode %d\n", hdr->opcode); break;
    }
}

static void DaveBinarySlotImpl(i32 which, void* this_, void* receiver, void** args, u8* ret) {
    Unreferenced(receiver);
    switch (which) {
        case 1: {  // NOTE(geni): Call
            DaveBinarySlotObject* slot = (DaveBinarySlotObject*) this_;
            const QByteArray*     qba  = (const QByteArray*) args[1];
            HandleDaveBinaryMsg((DisVLWorker*) slot->user_data, qba);
        } break;
        case 0: {  // NOTE(geni): Destroy
            free(this_);
        } break;
        case 2: {  // NOTE(geni): Compare
            if (ret) {
                *ret = 0;
            }
        } break;
    }
}

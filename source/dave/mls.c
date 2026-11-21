static void DaveRejectTransition(i32 transition_id) {
    DaveSendTransitionOp(DAVE_MLS_INVALID_COMMIT, transition_id);
    DaveInit(daveSessionGetProtocolVersion(g_dave.session));
}

static void HandleDaveProposals(u8* data, size_t len) {
    DaveRecognizedUsers recognized;
    DaveBuildRecognizedUsers(&recognized);

    u8*    resp      = NULL;
    size_t resp_size = 0;
    daveSessionProcessProposals(g_dave.session, data, len, recognized.ptrs, recognized.count, &resp, &resp_size);
    if (resp && resp_size > 0) {
        DaveSendBinary(DAVE_MLS_COMMIT_WELCOME, resp, resp_size);
        daveFree(resp);
    }
}

static void HandleDaveAnnounceCommit(u8* data, size_t len) {
    if (len < 2) {
        return;
    }
    i32    transition_id = ReadU16BE(data);
    u8*    commit_data   = data + 2;
    size_t commit_len    = len - 2;

    DAVECommitResultHandle result = daveSessionProcessCommit(g_dave.session, commit_data, commit_len);
    if (!result) {
        DebugMsg("ProcessCommit ignored\n");
        return;
    }

    if (daveCommitResultIsFailed(result)) {
        DebugMsg("ProcessCommit failed\n");
        DaveRejectTransition(transition_id);
    } else if (daveCommitResultIsIgnored(result)) {
        DebugMsg("ProcessCommit ignored\n");
    } else {
        DebugMsg("ProcessCommit succeeded: transition_id=%d\n", transition_id);
        DavePrepareTransition((u16) transition_id, daveSessionGetProtocolVersion(g_dave.session));
    }
    daveCommitResultDestroy(result);
}

static void HandleDaveWelcome(u8* data, size_t len) {
    if (len < 2) {
        return;
    }
    i32    transition_id = ReadU16BE(data);
    u8*    welcome_data  = data + 2;
    size_t welcome_len   = len - 2;

    DaveRecognizedUsers recognized;
    DaveBuildRecognizedUsers(&recognized);

    DAVEWelcomeResultHandle result = daveSessionProcessWelcome(g_dave.session, welcome_data, welcome_len,
                                                               recognized.ptrs, recognized.count);
    if (!result) {
        DebugMsg("ProcessWelcome failed\n");
        DaveRejectTransition(transition_id);
        return;
    }

    DebugMsg("ProcessWelcome succeeded: transition_id=%d\n", transition_id);
    DavePrepareTransition((u16) transition_id, daveSessionGetProtocolVersion(g_dave.session));
    daveWelcomeResultDestroy(result);
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
    size_t            payload_size = (size_t) len - sizeof(DaveBinaryHeader);

    g_dave.last_seq = ReadU16BE(hdr->seq);

    switch (hdr->opcode) {
        case DAVE_MLS_EXTERNAL_SENDER: {
            daveSessionSetExternalSender(g_dave.session, payload, payload_size);
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
            HandleDaveBinaryMsg((QByteArray*) args[1]);
        } break;

        case 2: {  // NOTE(geni): Compare
            if (ret) {
                *ret = 0;
            }
        } break;
    }
}

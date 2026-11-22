static void Dave_RejectTransition(i32 transition_id) {
    Dave_SendTransitionOp(DAVE_MLS_INVALID_COMMIT, transition_id);
    Dave_Init(daveSessionGetProtocolVersion(g_dave.session));
}

static void Dave_HandleProposals(u8* data, size_t len) {
    DaveRecognizedUsers recognized;
    Dave_BuildRecognizedUsers(&recognized);

    u8*    resp      = NULL;
    size_t resp_size = 0;
    daveSessionProcessProposals(g_dave.session, data, len, recognized.ptrs, recognized.count, &resp, &resp_size);
    if (resp && resp_size > 0) {
        Dave_SendBinary(DAVE_MLS_COMMIT_WELCOME, resp, resp_size);
        daveFree(resp);
    }
}

static void Dave_HandleAnnounceCommit(u8* data, size_t len) {
    if (len < 2) {
        return;
    }
    i32    transition_id = ReadU16BE(data);
    u8*    commit_data   = data + 2;
    size_t commit_len    = len - 2;

    DAVECommitResultHandle result = daveSessionProcessCommit(g_dave.session, commit_data, commit_len);
    if (!result) {
        Log_Debug("ProcessCommit ignored");
        return;
    }

    if (daveCommitResultIsFailed(result)) {
        Log_Debug("ProcessCommit failed");
        Dave_RejectTransition(transition_id);
    } else if (daveCommitResultIsIgnored(result)) {
        Log_Debug("ProcessCommit ignored");
    } else {
        Log_Debug("ProcessCommit succeeded: transition_id=%d", transition_id);
        Dave_PrepareTransition((u16) transition_id, daveSessionGetProtocolVersion(g_dave.session));
    }
    daveCommitResultDestroy(result);
}

static void Dave_HandleWelcome(u8* data, size_t len) {
    if (len < 2) {
        return;
    }
    i32    transition_id = ReadU16BE(data);
    u8*    welcome_data  = data + 2;
    size_t welcome_len   = len - 2;

    DaveRecognizedUsers recognized;
    Dave_BuildRecognizedUsers(&recognized);

    DAVEWelcomeResultHandle result = daveSessionProcessWelcome(g_dave.session, welcome_data, welcome_len,
                                                               recognized.ptrs, recognized.count);
    if (!result) {
        Log_Debug("ProcessWelcome failed");
        Dave_RejectTransition(transition_id);
        return;
    }

    Log_Debug("ProcessWelcome succeeded: transition_id=%d", transition_id);
    Dave_PrepareTransition((u16) transition_id, daveSessionGetProtocolVersion(g_dave.session));
    daveWelcomeResultDestroy(result);
}

static void Dave_HandleBinaryMessage(QByteArray* data) {
    u8* raw = (u8*) QByteArray_ConstData(data);
    i32 len = QByteArray_Size(data);
    if (len < (i32) sizeof(DaveBinaryHeader)) {
        Log_Debug("DaveBinaryMsg too short: %d bytes", len);
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
            Dave_HandleProposals(payload, payload_size);
        } break;

        case DAVE_MLS_ANNOUNCE_COMMIT: {
            Dave_HandleAnnounceCommit(payload, payload_size);
        } break;

        case DAVE_MLS_WELCOME: {
            Dave_HandleWelcome(payload, payload_size);
        } break;

        default: {
            Log_Debug("Unhandled binary opcode %d", hdr->opcode);
        } break;
    }
}

static void Dave_BinarySlotImpl(i32 which, void* this, void* receiver, void** args, u8* ret) {
    Unreferenced(receiver);
    switch (which) {
        case 0: {  // NOTE(geni): Destroy
            free(this);
        } break;

        case 1: {  // NOTE(geni): Call
            Dave_HandleBinaryMessage((QByteArray*) args[1]);
        } break;

        case 2: {  // NOTE(geni): Compare
            if (ret) {
                *ret = 0;
            }
        } break;
    }
}

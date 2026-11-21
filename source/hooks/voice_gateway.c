// NOTE(geni): Not really necessary at the moment, but we have to prepare for future voice protocol updates
static SEND_SPEAKING_STATE(SendSpeakingStateHook) {
    QJsonObject d;
    qjsonobject_constructor(&d);
    QJsonInsertInt(&d, S8Lit("speaking"), isSpeaking);
    QJsonInsertInt(&d, S8Lit("delay"), 0);
    QJsonInsertInt(&d, S8Lit("ssrc"), this->priv->vlWorker->ssrc);
    SendVoiceOp(this->priv->vlWorker->webSocket, 5, &d);
}

static void SendTextSync(void* webSocket, String8 text) {
    QString msg;
    msg.d = qstring_from_ascii_helper(text.cstr, (i64) text.size);
    qwebsocket_sendtextmessage(webSocket, &msg);
    qstring_destructor(&msg);
}

static void SendVoiceIdentify(DisVLWorker* vc) {
    void* webSocket = vc->webSocket;

    u64 guildId   = vc->connGuildId;
    u64 channelId = vc->connChannelId;
    u64 userId    = vc->connUserId;
    u64 serverId  = (guildId == (u64) -1) ? channelId : guildId;

    QByteArray sid;
    QByteArray tok;
    qstring_toutf8(&vc->connSessionId, &sid);
    qstring_toutf8(&vc->connToken, &tok);

    // NOTE(geni): imma be real I don't care enough to use QJson for this
    char json[1024];
    i32  len = snprintf(json, sizeof json,
                        "{\"op\":0,\"d\":{\"server_id\":\"%llu\",\"user_id\":\"%llu\","
                         "\"session_id\":\"%.*s\",\"token\":\"%.*s\",\"video\":true,"
                         "\"max_dave_protocol_version\":1}}",
                        serverId, userId,
                        QByteArraySize(&sid), QByteArrayConstData(&sid),
                        QByteArraySize(&tok), QByteArrayConstData(&tok));

    qbytearray_destructor(&sid);
    qbytearray_destructor(&tok);

    String8 msg = {
        .cstr = json,
        .size = (u64) len,
    };
    SendTextSync(webSocket, msg);
}

static VOICE_CONN_WS_CONNECTED(VoiceConnWSConnectedHook) {
    DaveReset();
    g_dave.user_id    = vc->connUserId;
    g_dave.channel_id = vc->connChannelId;
    g_dave.webSocket  = vc->webSocket;
    SendVoiceIdentify(vc);
}

typedef struct {
    Pad(16);
    DisVLWorker* vlWorker;
} HeartbeatLambdaCapture;

typedef void (*HeartbeatLambdaImplType)(i32 which, void* this_, void* r, void** a);
static HeartbeatLambdaImplType heartbeat_lambda_impl;

static void HeartbeatLambdaImplHook(i32 which, void* this_, void* r, void** a) {
    if (which != 1) {
        heartbeat_lambda_impl(which, this_, r, a);
        return;
    }

    HeartbeatLambdaCapture* capture = (HeartbeatLambdaCapture*) this_;
    DisVLWorker*            vw      = capture->vlWorker;
    if (!vw->webSocket) {
        return;
    }

    u64 now = qdatetime_currentmsecsinceepoch();

    QJsonObject d;
    QJsonValue  value;
    qjsonobject_constructor(&d);
    QJsonInsert(&d, S8Lit("t"), qjsonvalue_constructor_double(&value, (double) now));
    QJsonInsertInt(&d, S8Lit("seq_ack"), g_dave.last_seq);
    SendVoiceOp(vw->webSocket, 3, &d);
}

// NOTE(geni): Binary DAVE ops (25-31) go through HandleDaveBinaryMsg instead
//             Join flow:
//               4      SESSION_DESCRIPTION          -> DaveInit, send our MLS_KEY_PACKAGE
//               25     MLS_EXTERNAL_SENDER          -> libdave creates a pending group
//               11     CLIENTS_CONNECT              -> add to recognized users
//               27     MLS_PROPOSALS                -> commit the member adds/removes, send MLS_COMMIT_WELCOME
//               29/30  MLS_ANNOUNCE_COMMIT/WELCOME  -> DavePrepareTransition: decryptors switch, send READY_FOR_TRANSITION
//               22     EXECUTE_TRANSITION           -> DaveExecuteTransition: encryptor switches to new key
static VOICE_CONN_TEXT_MSG_RECEIVED(VoiceConnTextMsgReceivedHook) {
    QByteArray text_utf8;
    qstring_toutf8(text, &text_utf8);
    String8 src = {
        .cstr = (char*) QByteArrayConstData(&text_utf8),
        .size = (u64) QByteArraySize(&text_utf8),
    };

    jsmntok_t tokens[256];
    Json      j = JsonParse(src, tokens, ArrayCount(tokens));
    if (j.count < 1 || tokens[0].type != JSMN_OBJECT) {
        voice_conn_text_msg_received(vw, text);
        goto cleanup;
    }

    i32 op  = JsonI32(&j, 0, S8Lit("op"), -1);
    i32 seq = JsonI32(&j, 0, S8Lit("seq"), -1);
    i32 d   = JsonGet(&j, 0, S8Lit("d"));

    // NOTE(geni): Echoed back as seq_ack in heartbeats
    if (seq >= 0) {
        g_dave.last_seq = seq;
    }

    if (d < 0) {
        voice_conn_text_msg_received(vw, text);
        goto cleanup;
    }

    switch (op) {
        // NOTE(geni): Original runs first where we need vw->ssrc
        case VOICE_OP_READY: {
            voice_conn_text_msg_received(vw, text);
            daveEncryptorAssignSsrcToCodec(g_dave.encryptor, vw->ssrc, DAVE_CODEC_OPUS);
        } break;

        case VOICE_OP_SESSION_DESCRIPTION: {
            voice_conn_text_msg_received(vw, text);
            i32 dave_ver = JsonI32(&j, d, S8Lit("dave_protocol_version"), 0);
            if (dave_ver > 0) {
                DaveInit((u16) dave_ver);
            }
        } break;

        case VOICE_OP_SPEAKING: {
            voice_conn_text_msg_received(vw, text);
            // NOTE(geni): Fill out SSRC map
            u64 uid  = JsonU64(&j, d, S8Lit("user_id"), 0);
            u32 ssrc = JsonU32(&j, d, S8Lit("ssrc"), 0);
            if (uid != 0 && ssrc != 0) {
                DaveSetSsrcUser(ssrc, uid);
            }
        } break;

        case VOICE_OP_PREPARE_TRANSITION: {
            // NOTE(geni): This is only used for disabling or resetting DAVE
            i32 proto_ver     = JsonI32(&j, d, S8Lit("protocol_version"), 0);
            i32 transition_id = JsonI32(&j, d, S8Lit("transition_id"), 0);
            DavePrepareTransition((u16) transition_id, (u16) proto_ver);
        } break;

        case VOICE_OP_EXECUTE_TRANSITION: {
            i32 transition_id = JsonI32(&j, d, S8Lit("transition_id"), 0);
            if (transition_id != 0 && transition_id == g_dave.pending_transition_id) {
                DaveExecuteTransition();
            }
        } break;

        case VOICE_OP_PREPARE_EPOCH: {
            // NOTE(geni): Any other epoch means the group is kept as is
            if (JsonI32(&j, d, S8Lit("epoch"), 0) == 1) {
                DaveInit((u16) JsonI32(&j, d, S8Lit("protocol_version"), 0));
            }
        } break;

        case VOICE_OP_CLIENTS_CONNECT: {
            u64 uids[DAVE_MAX_USERS];
            u32 count = JsonU64Array(&j, d, S8Lit("user_ids"), uids, ArrayCount(uids));
            for (u32 i = 0; i < count; ++i) {
                DaveAddRecognizedUser(uids[i]);
            }
            voice_conn_text_msg_received(vw, text);
        } break;

        case VOICE_OP_CLIENT_DISCONNECT: {
            voice_conn_text_msg_received(vw, text);
            u64 uid = JsonU64(&j, d, S8Lit("user_id"), 0);
            if (uid != 0) {
                DaveRemoveRecognizedUser(uid);
                DaveRemoveUserSsrcs(uid);
            }
        } break;

        default: {
            voice_conn_text_msg_received(vw, text);
        } break;
    }
cleanup:
    qbytearray_destructor(&text_utf8);
}

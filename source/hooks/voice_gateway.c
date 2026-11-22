// NOTE(geni): Not really necessary at the moment, but we have to prepare for future voice protocol updates
static DISVOICELINE_SENDSPEAKINGSTATE(DisVoiceLine_SendSpeakingStateHook) {
    QJsonObject d;
    QJsonObject_Constructor(&d);
    QJson_InsertInt(&d, S8Lit("speaking"), isSpeaking);
    QJson_InsertInt(&d, S8Lit("delay"), 0);
    QJson_InsertInt(&d, S8Lit("ssrc"), this->priv->vlWorker->ssrc);
    Op_SendVoice(this->priv->vlWorker->webSocket, 5, &d);
}

static void Voice_SendIdentify(DisVLWorker* vc) {
    void* webSocket = vc->webSocket;

    u64 guildId   = vc->connGuildId;
    u64 channelId = vc->connChannelId;
    u64 userId    = vc->connUserId;
    u64 serverId  = (guildId == (u64) -1) ? channelId : guildId;

    QByteArray sid;
    QByteArray tok;
    QString_ToUtf8(&vc->connSessionId, &sid);
    QString_ToUtf8(&vc->connToken, &tok);

    // NOTE(geni): imma be real I don't care enough to use QJson for this
    char json[1024];
    i32  len = snprintf(json, sizeof json,
                        "{\"op\":0,\"d\":{\"server_id\":\"%llu\",\"user_id\":\"%llu\","
                         "\"session_id\":\"%.*s\",\"token\":\"%.*s\",\"video\":true,"
                         "\"max_dave_protocol_version\":1}}",
                        serverId, userId,
                        QByteArray_Size(&sid), QByteArray_ConstData(&sid),
                        QByteArray_Size(&tok), QByteArray_ConstData(&tok));

    QByteArray_Destructor(&sid);
    QByteArray_Destructor(&tok);

    String8 msg = {
        .cstr = json,
        .size = (u64) len,
    };
    Op_SendText(webSocket, msg);
}

static DISCLIENTIMPL_VOICECONNWEBSOCKETCONNECTED(DisClientImpl_VoiceConnWebSocketConnectedHook) {
    Dave_Reset();
    g_dave.user_id    = vc->connUserId;
    g_dave.channel_id = vc->connChannelId;
    g_dave.webSocket  = vc->webSocket;
    Voice_SendIdentify(vc);
}

typedef struct {
    Pad(16);
    DisVLWorker* vlWorker;
} HeartbeatLambdaCapture;

typedef void (*DisClientImpl_HeartbeatLambdaImplType)(i32 which, void* this_, void* r, void** a);
static DisClientImpl_HeartbeatLambdaImplType DisClientImpl_HeartbeatLambdaImpl;

static void DisClientImpl_HeartbeatLambdaImplHook(i32 which, void* this_, void* r, void** a) {
    if (which != 1) {
        DisClientImpl_HeartbeatLambdaImpl(which, this_, r, a);
        return;
    }

    HeartbeatLambdaCapture* capture = (HeartbeatLambdaCapture*) this_;
    DisVLWorker*            vw      = capture->vlWorker;
    if (!vw->webSocket) {
        return;
    }

    u64 now = QDateTime_CurrentMSecsSinceEpoch();

    QJsonObject d;
    QJsonValue  value;
    QJsonObject_Constructor(&d);
    QJson_Insert(&d, S8Lit("t"), QJsonValue_ConstructorDouble(&value, (double) now));
    QJson_InsertInt(&d, S8Lit("seq_ack"), g_dave.last_seq);
    Op_SendVoice(vw->webSocket, 3, &d);
}

// NOTE(geni): Binary DAVE ops (25-31) go through Dave_HandleBinaryMessage instead
//             Join flow:
//               4      SESSION_DESCRIPTION          -> Dave_Init, send our MLS_KEY_PACKAGE
//               25     MLS_EXTERNAL_SENDER          -> libdave creates a pending group
//               11     CLIENTS_CONNECT              -> add to recognized users
//               27     MLS_PROPOSALS                -> commit the member adds/removes, send MLS_COMMIT_WELCOME
//               29/30  MLS_ANNOUNCE_COMMIT/WELCOME  -> Dave_PrepareTransition: decryptors switch, send READY_FOR_TRANSITION
//               22     EXECUTE_TRANSITION           -> Dave_ExecuteTransition: encryptor switches to new key
static DISCLIENTIMPL_VOICECONNTEXTMESSAGERECEIVED(DisClientImpl_VoiceConnTextMessageReceivedHook) {
    QByteArray text_utf8;
    QString_ToUtf8(text, &text_utf8);
    String8 src = {
        .cstr = (char*) QByteArray_ConstData(&text_utf8),
        .size = (u64) QByteArray_Size(&text_utf8),
    };

    jsmntok_t tokens[256];
    Json      j = Json_Parse(src, tokens, ArrayCount(tokens));
    if (j.count < 1 || tokens[0].type != JSMN_OBJECT) {
        DisClientImpl_VoiceConnTextMessageReceived(vw, text);
        goto cleanup;
    }

    i32 op  = Json_GetI32(&j, 0, S8Lit("op"), -1);
    i32 seq = Json_GetI32(&j, 0, S8Lit("seq"), -1);
    i32 d   = Json_Find(&j, 0, S8Lit("d"));

    // NOTE(geni): Echoed back as seq_ack in heartbeats
    if (seq >= 0) {
        g_dave.last_seq = seq;
    }

    if (d < 0) {
        DisClientImpl_VoiceConnTextMessageReceived(vw, text);
        goto cleanup;
    }

    switch (op) {
        // NOTE(geni): Original runs first where we need vw->ssrc
        case VOICE_OP_READY: {
            DisClientImpl_VoiceConnTextMessageReceived(vw, text);
            daveEncryptorAssignSsrcToCodec(g_dave.encryptor, vw->ssrc, DAVE_CODEC_OPUS);
        } break;

        case VOICE_OP_SESSION_DESCRIPTION: {
            DisClientImpl_VoiceConnTextMessageReceived(vw, text);
            i32 dave_ver = Json_GetI32(&j, d, S8Lit("dave_protocol_version"), 0);
            if (dave_ver > 0) {
                Dave_Init((u16) dave_ver);
            }
        } break;

        case VOICE_OP_SPEAKING: {
            DisClientImpl_VoiceConnTextMessageReceived(vw, text);
            // NOTE(geni): Fill out SSRC map
            u64 uid  = Json_GetU64(&j, d, S8Lit("user_id"), 0);
            u32 ssrc = Json_GetU32(&j, d, S8Lit("ssrc"), 0);
            if (uid != 0 && ssrc != 0) {
                Dave_SetSsrcUser(ssrc, uid);
            }
        } break;

        case VOICE_OP_PREPARE_TRANSITION: {
            // NOTE(geni): This is only used for disabling or resetting DAVE
            i32 proto_ver     = Json_GetI32(&j, d, S8Lit("protocol_version"), 0);
            i32 transition_id = Json_GetI32(&j, d, S8Lit("transition_id"), 0);
            Dave_PrepareTransition((u16) transition_id, (u16) proto_ver);
        } break;

        case VOICE_OP_EXECUTE_TRANSITION: {
            i32 transition_id = Json_GetI32(&j, d, S8Lit("transition_id"), 0);
            if (transition_id != 0 && transition_id == g_dave.pending_transition_id) {
                Dave_ExecuteTransition();
            }
        } break;

        case VOICE_OP_PREPARE_EPOCH: {
            // NOTE(geni): Any other epoch means the group is kept as is
            if (Json_GetI32(&j, d, S8Lit("epoch"), 0) == 1) {
                Dave_Init((u16) Json_GetI32(&j, d, S8Lit("protocol_version"), 0));
            }
        } break;

        case VOICE_OP_CLIENTS_CONNECT: {
            u64 uids[DAVE_MAX_USERS];
            u32 count = Json_GetU64Array(&j, d, S8Lit("user_ids"), uids, ArrayCount(uids));
            for (u32 i = 0; i < count; ++i) {
                Dave_AddRecognizedUser(uids[i]);
            }
            DisClientImpl_VoiceConnTextMessageReceived(vw, text);
        } break;

        case VOICE_OP_CLIENT_DISCONNECT: {
            DisClientImpl_VoiceConnTextMessageReceived(vw, text);
            u64 uid = Json_GetU64(&j, d, S8Lit("user_id"), 0);
            if (uid != 0) {
                Dave_RemoveRecognizedUser(uid);
                Dave_RemoveUserSsrcs(uid);
            }
        } break;

        default: {
            DisClientImpl_VoiceConnTextMessageReceived(vw, text);
        } break;
    }
cleanup:
    QByteArray_Destructor(&text_utf8);
}

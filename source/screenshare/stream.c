static u8 stream_ws_send(WINHTTP_WEB_SOCKET_BUFFER_TYPE type, const void* data, u32 length) {
    stream_conn* c = &g_stream;
    if (!c->h_ws) {
        return 0;
    }
    EnterCriticalSection(&g_stream_ws_lock);
    DWORD error = WinHttpWebSocketSend(c->h_ws, type, (PVOID) data, length);
    LeaveCriticalSection(&g_stream_ws_lock);
    return error == NO_ERROR;
}

static u8 stream_send_json(const char* text) {
    return stream_ws_send(WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, text, (u32) strlen(text));
}

// Client to server binary frames are the opcode followed by the payload
static u8 stream_send_binary(u8 opcode, const u8* payload, size_t length) {
    u8* buffer = (u8*) malloc(1 + length);
    if (!buffer) {
        return 0;
    }
    buffer[0] = opcode;
    if (length && payload) {
        memcpy(buffer + 1, payload, length);
    }
    u8 ok = stream_ws_send(WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE, buffer, (u32) (1 + length));
    free(buffer);
    return ok;
}

static u8 stream_ws_connect(void) {
    stream_conn* c = &g_stream;

    wchar_t host[160];
    MultiByteToWideChar(CP_UTF8, 0, c->host, -1, host, ArrayCount(host));

    c->h_session = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!c->h_session) {
        return 0;
    }
    // Resolve, connect, send, and (importantly for an idle socket) receive. Zero means no timeout
    WinHttpSetTimeouts(c->h_session, 10000, 10000, 10000, 0);

    c->h_connect = WinHttpConnect(c->h_session, host, c->port, 0);
    if (!c->h_connect) {
        return 0;
    }
    HINTERNET request = WinHttpOpenRequest(c->h_connect, L"GET", L"/?v=8", NULL, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, c->secure ? WINHTTP_FLAG_SECURE : 0);
    if (!request) {
        return 0;
    }
    if (!WinHttpSetOption(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0) ||
        !WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, NULL)) {
        WinHttpCloseHandle(request);
        return 0;
    }
    c->h_ws = WinHttpWebSocketCompleteUpgrade(request, 0);
    WinHttpCloseHandle(request);
    return c->h_ws != NULL;
}

static void stream_add_user(const char* user_id) {
    stream_conn* c = &g_stream;
    for (u32 i = 0; i < c->user_count; ++i) {
        if (strcmp(c->users[i], user_id) == 0) {
            return;
        }
    }
    if (c->user_count < stream_max_users && strlen(user_id) < sizeof c->users[0]) {
        strcpy(c->users[c->user_count++], user_id);
    }
}

static void stream_remove_user(const char* user_id) {
    stream_conn* c = &g_stream;
    for (u32 i = 0; i < c->user_count; ++i) {
        if (strcmp(c->users[i], user_id) == 0) {
            memmove(c->users[i], c->users[i + 1], (c->user_count - i - 1) * sizeof c->users[0]);
            --c->user_count;
            return;
        }
    }
}

static u32 stream_user_ptrs(const char** pointers) {
    stream_conn* c = &g_stream;
    for (u32 i = 0; i < c->user_count; ++i) {
        pointers[i] = c->users[i];
    }
    return c->user_count;
}

static void stream_mark_ready(void) {
    stream_conn* c = &g_stream;
    if (InterlockedExchange(&c->ready, 1) == 0) {
        stream_set_status(stream_state_live, L"Live");
        Log_Debug("Go Live: connection ready");
        SetEvent(c->ready_event);
        ss_request_key();
        audio_start();
    }
}

static void stream_send_key_package(void) {
    stream_conn* c       = &g_stream;
    u8*          package = NULL;
    size_t       length  = 0;
    daveSessionGetMarshalledKeyPackage(c->session, &package, &length);
    if (package) {
        stream_send_binary(DAVE_MLS_KEY_PACKAGE, package, length);
        daveFree(package);
    }
}

static void stream_dave_init(void) {
    stream_conn* c        = &g_stream;
    u64          group_id = c->server_id_num - 1;
    daveSessionInit(c->session, c->dave_version, group_id, c->user_id);
    stream_send_key_package();
}

static void stream_dave_reset(void) {
    stream_conn* c = &g_stream;
    EnterCriticalSection(&g_stream_dave_lock);
    daveSessionReset(c->session);
    LeaveCriticalSection(&g_stream_dave_lock);
    stream_dave_init();
}

// Processing a commit or welcome has already advanced the MLS epoch, so asking the session for our ratchet now
// returns the key of the new epoch
static void stream_apply_keys(void) {
    stream_conn* c = &g_stream;
    if (!c->use_dave || !c->session) {
        return;
    }
    EnterCriticalSection(&g_stream_dave_lock);
    DAVEKeyRatchetHandle mine = daveSessionGetKeyRatchet(c->session, c->user_id);
    if (mine) {
        daveEncryptorSetKeyRatchet(c->encryptor, mine);
        if (c->ratchet) {
            daveKeyRatchetDestroy(c->ratchet);
        }
        c->ratchet = mine;
    }
    LeaveCriticalSection(&g_stream_dave_lock);
    if (mine) {
        stream_mark_ready();
    }
    ss_request_key();
}

static void stream_transition_ready(u16 transition_id) {
    char json[96];
    snprintf(json, sizeof json, "{\"op\":23,\"d\":{\"transition_id\":%u}}", transition_id);
    stream_send_json(json);
}

static void stream_invalid_commit(u16 transition_id) {
    char json[96];
    snprintf(json, sizeof json, "{\"op\":31,\"d\":{\"transition_id\":%u}}", transition_id);
    stream_send_json(json);
    InterlockedExchange(&g_stream.ready, 0);
    stream_dave_reset();
}

static void stream_on_binary(const u8* data, u32 size) {
    stream_conn* c = &g_stream;
    // Server to client: a 16-bit sequence number, the opcode, then the payload
    if (size < 3) {
        return;
    }
    i32 seq = (data[0] << 8) | data[1];
    if (seq > c->last_seq) {
        InterlockedExchange(&c->last_seq, seq);
    }
    if (!c->use_dave || !c->session) {
        return;
    }
    u8        opcode  = data[2];
    const u8* payload = data + 3;
    u32       length  = size - 3;

    switch (opcode) {
        case DAVE_MLS_EXTERNAL_SENDER: {
            EnterCriticalSection(&g_stream_dave_lock);
            daveSessionSetExternalSender(c->session, payload, length);
            LeaveCriticalSection(&g_stream_dave_lock);
        } break;

        case DAVE_MLS_PROPOSALS: {
            const char* users[stream_max_users];
            u32         user_count = stream_user_ptrs(users);
            u8*         commit     = NULL;
            size_t      commit_len = 0;
            EnterCriticalSection(&g_stream_dave_lock);
            daveSessionProcessProposals(c->session, payload, length, users, user_count, &commit, &commit_len);
            LeaveCriticalSection(&g_stream_dave_lock);
            if (commit) {
                stream_send_binary(DAVE_MLS_COMMIT_WELCOME, commit, commit_len);
                daveFree(commit);
            }
            ss_request_key();
        } break;

        case DAVE_MLS_ANNOUNCE_COMMIT: {
            if (length < 2) {
                break;
            }
            u16 transition_id = (u16) ((payload[0] << 8) | payload[1]);
            EnterCriticalSection(&g_stream_dave_lock);
            DAVECommitResultHandle result = daveSessionProcessCommit(c->session, payload + 2, length - 2);
            LeaveCriticalSection(&g_stream_dave_lock);
            if (!result || daveCommitResultIsFailed(result)) {
                stream_invalid_commit(transition_id);
            } else {
                if (!daveCommitResultIsIgnored(result)) {
                    stream_apply_keys();
                }
                stream_transition_ready(transition_id);
            }
            if (result) {
                daveCommitResultDestroy(result);
            }
        } break;

        case DAVE_MLS_WELCOME: {
            if (length < 2) {
                break;
            }
            u16         transition_id = (u16) ((payload[0] << 8) | payload[1]);
            const char* users[stream_max_users];
            u32         user_count = stream_user_ptrs(users);
            EnterCriticalSection(&g_stream_dave_lock);
            DAVEWelcomeResultHandle result = daveSessionProcessWelcome(c->session, payload + 2, length - 2, users, user_count);
            LeaveCriticalSection(&g_stream_dave_lock);
            if (result) {
                stream_apply_keys();
                stream_transition_ready(transition_id);
                daveWelcomeResultDestroy(result);
            } else {
                stream_invalid_commit(transition_id);
            }
        } break;
    }
}

static void stream_send_identify(void) {
    stream_conn* c = &g_stream;
    char         json[1024];
    snprintf(json, sizeof json,
             "{\"op\":0,\"d\":{\"server_id\":\"%s\",\"user_id\":\"%s\",\"session_id\":\"%s\",\"token\":\"%s\","
             "\"video\":true,\"streams\":[{\"type\":\"screen\",\"rid\":\"100\",\"quality\":100}],"
             "\"max_dave_protocol_version\":%u}}",
             c->server_id, c->user_id, c->session_id, c->token, (u32) daveMaxSupportedProtocolVersion());
    stream_send_json(json);
}

// Op 12: tells the server which SSRCs carry our video and how big and fast it will be. Without it the server has
// nothing to forward to viewers
static void stream_send_video(void) {
    stream_conn* c = &g_stream;
    char         json[1024];
    snprintf(json, sizeof json,
             "{\"op\":12,\"d\":{\"audio_ssrc\":%u,\"video_ssrc\":%u,\"rtx_ssrc\":%u,\"streams\":[{\"type\":\"screen\","
             "\"rid\":\"%s\",\"ssrc\":%u,\"active\":true,\"quality\":%d,\"rtx_ssrc\":%u,\"max_bitrate\":%u,"
             "\"max_framerate\":%d,\"max_resolution\":{\"type\":\"fixed\",\"width\":%d,\"height\":%d}}]}}",
             c->ssrc, c->video_ssrc, c->rtx_ssrc, c->video_rid, c->video_ssrc, c->video_quality, c->rtx_ssrc, c->bitrate, c->fps,
             c->width, c->height);
    stream_send_json(json);
}

static void stream_send_select(const char* address, u32 port) {
    char json[1536];
    snprintf(json, sizeof json,
             "{\"op\":1,\"d\":{\"protocol\":\"udp\",\"data\":{\"address\":\"%s\",\"port\":%u,\"mode\":\"aead_aes256_gcm_rtpsize\"},"
             "\"codecs\":[{\"name\":\"opus\",\"type\":\"audio\",\"priority\":1000,\"payload_type\":%d},"
             "{\"name\":\"H264\",\"type\":\"video\",\"priority\":1000,\"payload_type\":%d,\"rtx_payload_type\":%d,"
             "\"encode\":true,\"decode\":true}]}}",
             address, port, stream_pt_audio, stream_pt_video, stream_pt_rtx);
    stream_send_json(json);
}

static void stream_send_discovery(void) {
    stream_conn* c          = &g_stream;
    u8           packet[74] = { 0 };
    packet[1]               = 1;
    packet[3]               = 70;
    packet[4]               = (u8) (c->ssrc >> 24);
    packet[5]               = (u8) (c->ssrc >> 16);
    packet[6]               = (u8) (c->ssrc >> 8);
    packet[7]               = (u8) (c->ssrc & 0xFF);
    send(c->sock, (const char*) packet, sizeof packet, 0);
}

static DWORD WINAPI stream_udp(LPVOID param);
static DWORD WINAPI stream_heartbeat(LPVOID param);
static DWORD WINAPI stream_sender(LPVOID param);

static u8 stream_open_udp(const char* ip, u16 port) {
    stream_conn* c = &g_stream;
    WSADATA      wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    struct sockaddr_in address = { 0 };
    address.sin_family         = AF_INET;
    address.sin_port           = htons(port);
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) {
        return 0;
    }
    c->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (c->sock == INVALID_SOCKET) {
        return 0;
    }
    if (connect(c->sock, (struct sockaddr*) &address, sizeof address) != 0) {
        closesocket(c->sock);
        c->sock = INVALID_SOCKET;
        return 0;
    }
    c->udp_thread = CreateThread(NULL, 0, stream_udp, NULL, 0, NULL);
    return c->udp_thread != NULL;
}

static void stream_copy_str(Json* j, i32 obj, String8 key, char* out, u32 size) {
    i32 idx = Json_Find(j, obj, key);
    if (idx < 0) {
        return;
    }
    String8 s = Json_TokenStr(j, idx);
    if (s.size >= size) {
        return;
    }
    memcpy(out, s.data, s.size);
    out[s.size] = 0;
}

static void stream_on_ready(Json* j, i32 d) {
    stream_conn* c = &g_stream;
    c->ssrc        = Json_GetU32(j, d, S8Lit("ssrc"), 0);
    c->media_port  = (u16) Json_GetU32(j, d, S8Lit("port"), 0);
    stream_copy_str(j, d, S8Lit("ip"), c->media_ip, sizeof c->media_ip);

    // NOTE(Xelph): I fall back to audio ssrc + 1 and + 2 like Discord's clients do when the streams array has none
    c->video_ssrc = c->ssrc + 1;
    c->rtx_ssrc   = c->ssrc + 2;
    strcpy(c->video_rid, "100");
    c->video_quality = 100;

    i32 streams = Json_FindOfType(j, d, S8Lit("streams"), JSMN_ARRAY);
    i32 stream  = streams + 1;
    for (i32 i = 0; streams >= 0 && i < j->tok[streams].size; ++i, stream = Json_SkipValue(j, stream)) {
        char type[24] = { 0 };
        stream_copy_str(j, stream, S8Lit("type"), type, sizeof type);
        if (strcmp(type, "screen") != 0 && strcmp(type, "video") != 0) {
            continue;
        }
        c->video_ssrc    = Json_GetU32(j, stream, S8Lit("ssrc"), c->video_ssrc);
        c->rtx_ssrc      = Json_GetU32(j, stream, S8Lit("rtx_ssrc"), c->rtx_ssrc);
        c->video_quality = Json_GetI32(j, stream, S8Lit("quality"), 100);
        stream_copy_str(j, stream, S8Lit("rid"), c->video_rid, sizeof c->video_rid);
        break;
    }

    Log_Debug("Go Live: ready, media %s:%u, ssrc=%u video=%u rtx=%u", c->media_ip, c->media_port, c->ssrc, c->video_ssrc, c->rtx_ssrc);
    if (!stream_open_udp(c->media_ip, c->media_port)) {
        stream_fail(L"Couldn't open the media connection.");
        return;
    }
    stream_send_discovery();
}

static void stream_on_session(Json* j, i32 d) {
    stream_conn* c = &g_stream;

    i32 key = Json_FindOfType(j, d, S8Lit("secret_key"), JSMN_ARRAY);
    if (key < 0 || j->tok[key].size != sizeof c->key) {
        stream_fail(L"The server sent no encryption key.");
        return;
    }
    i32 elem = key + 1;
    for (u32 i = 0; i < sizeof c->key; ++i, elem = Json_SkipValue(j, elem)) {
        i32 byte = 0;
        S8_ParseI32(Json_TokenStr(j, elem), &byte);
        c->key[i] = (u8) byte;
    }
    if (!stream_crypto_init()) {
        stream_fail(L"Couldn't set up encryption.");
        return;
    }

    // NOTE(Xelph): Stage channels answer 0, so I only have the AES-GCM layer as encryption there
    i32 version     = Json_GetI32(j, d, S8Lit("dave_protocol_version"), 0);
    c->use_dave     = version > 0;
    c->dave_version = (u16) version;

    stream_send_video();
    if (!c->use_dave) {
        stream_mark_ready();
        return;
    }

    EnterCriticalSection(&g_stream_dave_lock);
    c->session   = daveSessionCreate(NULL, NULL, NULL, NULL);
    c->encryptor = daveEncryptorCreate();
    daveEncryptorAssignSsrcToCodec(c->encryptor, c->ssrc, DAVE_CODEC_OPUS);
    daveEncryptorAssignSsrcToCodec(c->encryptor, c->video_ssrc, DAVE_CODEC_H264);
    LeaveCriticalSection(&g_stream_dave_lock);
    stream_dave_init();
}

static void stream_on_text(const char* text, u32 length) {
    stream_conn* c = &g_stream;

    jsmntok_t tokens[256];
    Json      j = Json_Parse((String8){ .cstr = (char*) text, .size = length }, tokens, ArrayCount(tokens));
    if (j.count < 1 || tokens[0].type != JSMN_OBJECT) {
        return;
    }

    i32 op  = Json_GetI32(&j, 0, S8Lit("op"), -1);
    i32 seq = Json_GetI32(&j, 0, S8Lit("seq"), -1);
    i32 d   = Json_Find(&j, 0, S8Lit("d"));
    if (seq > c->last_seq) {
        InterlockedExchange(&c->last_seq, seq);
    }

    switch (op) {
        case VOICE_OP_HELLO: {
            c->heartbeat_ms = Json_GetI32(&j, d, S8Lit("heartbeat_interval"), 41250);
            if (c->heartbeat_ms < 1000 || c->heartbeat_ms > 120000) {
                c->heartbeat_ms = 41250;
            }
            c->heartbeat_thread = CreateThread(NULL, 0, stream_heartbeat, NULL, 0, NULL);
            stream_send_identify();
        } break;

        case VOICE_OP_READY: {
            stream_on_ready(&j, d);
        } break;

        case VOICE_OP_SESSION_DESCRIPTION: {
            stream_on_session(&j, d);
        } break;

        case VOICE_OP_SPEAKING: {
            char user[40] = { 0 };
            stream_copy_str(&j, d, S8Lit("user_id"), user, sizeof user);
            if (user[0]) {
                stream_add_user(user);
            }
        } break;

        case VOICE_OP_CLIENTS_CONNECT: {
            i32 ids  = Json_FindOfType(&j, d, S8Lit("user_ids"), JSMN_ARRAY);
            i32 elem = ids + 1;
            for (i32 i = 0; ids >= 0 && i < j.tok[ids].size; ++i, elem = Json_SkipValue(&j, elem)) {
                String8 user = Json_TokenStr(&j, elem);
                if (user.size < sizeof c->users[0]) {
                    char buf[24] = { 0 };
                    memcpy(buf, user.data, user.size);
                    stream_add_user(buf);
                }
            }
        } break;

        case VOICE_OP_CLIENT_DISCONNECT: {
            char user[40] = { 0 };
            stream_copy_str(&j, d, S8Lit("user_id"), user, sizeof user);
            if (user[0]) {
                stream_remove_user(user);
            }
        } break;

        case VOICE_OP_PREPARE_TRANSITION: {
            if (!c->use_dave || d < 0) {
                break;
            }
            i32 transition_id = Json_GetI32(&j, d, S8Lit("transition_id"), -1);
            i32 version       = Json_GetI32(&j, d, S8Lit("protocol_version"), -1);
            if (transition_id == 0) {
                stream_apply_keys();
            } else if (transition_id > 0) {
                if (version == 0) {
                    c->pending_downgrade_tid = transition_id;
                }
                stream_transition_ready((u16) transition_id);
            }
        } break;

        case VOICE_OP_EXECUTE_TRANSITION: {
            if (!c->use_dave || d < 0) {
                break;
            }
            i32 transition_id = Json_GetI32(&j, d, S8Lit("transition_id"), -1);
            if (transition_id >= 0 && transition_id == c->pending_downgrade_tid) {
                EnterCriticalSection(&g_stream_dave_lock);
                daveEncryptorSetPassthroughMode(c->encryptor, true);
                LeaveCriticalSection(&g_stream_dave_lock);
                c->pending_downgrade_tid = -1;
            } else {
                stream_apply_keys();
            }
        } break;

        case VOICE_OP_PREPARE_EPOCH: {
            if (!c->use_dave || d < 0) {
                break;
            }
            // NOTE(Xelph): I treat epoch 1 as the gateway creating the MLS group again and keep the group for any other epoch
            if (Json_GetI32(&j, d, S8Lit("epoch"), -1) == 1) {
                i32 version     = Json_GetI32(&j, d, S8Lit("protocol_version"), 1);
                c->dave_version = (u16) (version > 0 ? version : 1);
                InterlockedExchange(&c->ready, 0);
                stream_dave_reset();
            }
        } break;
    }
}

static DWORD WINAPI stream_heartbeat(LPVOID param) {
    Unreferenced(param);
    stream_conn* c = &g_stream;
    while (WaitForSingleObject(c->stop_event, (DWORD) c->heartbeat_ms) == WAIT_TIMEOUT) {
        char json[128];
        snprintf(json, sizeof json, "{\"op\":3,\"d\":{\"t\":%llu,\"seq_ack\":%ld}}", (u64) GetTickCount64(), c->last_seq);
        stream_send_json(json);
    }
    return 0;
}

static DWORD WINAPI stream_sender(LPVOID param) {
    Unreferenced(param);
    stream_conn* c = &g_stream;
    while (WaitForSingleObject(c->stop_event, 2) == WAIT_TIMEOUT) {
        EnterCriticalSection(&g_stream_send_lock);
        stream_pump();
        LeaveCriticalSection(&g_stream_send_lock);
    }
    return 0;
}

static void stream_on_udp(u8* data, u32 size) {
    stream_conn* c = &g_stream;

    if (size == 74 && data[0] == 0 && data[1] == 2) {
        data[71]         = 0;
        const char* ip   = (const char*) data + 8;
        u32         port = (u32) ((data[72] << 8) | data[73]);
        stream_send_select(ip, port);
        return;
    }
    if (!InterlockedCompareExchange(&c->ready, 0, 0) || size < 8) {
        return;
    }
    // Feedback from the server: a NACK asks for packets again, a picture-loss or full-intra request asks for a
    // keyframe. Forging one can at worst cost us a keyframe
    if (data[1] >= 200 && data[1] <= 207) {
        if (size >= 12 && data[1] == 205 && (data[0] & 0x1F) == 1) {
            stream_on_nack(data, size);
        } else if (data[1] == 206) {
            u32 format = data[0] & 0x1F;
            if (format == 1 || format == 4) {
                ss_request_key();
            }
        }
    }
}

static DWORD WINAPI stream_udp(LPVOID param) {
    Unreferenced(param);
    stream_conn* c = &g_stream;
    u8           buffer[stream_packet_max];
    while (!c->stop) {
        int size = recv(c->sock, (char*) buffer, sizeof buffer, 0);
        if (size <= 0) {
            if (c->stop || size == 0) {
                break;
            }
            int error = WSAGetLastError();
            // A connected UDP socket reports an earlier ICMP "port unreachable" as a reset: not fatal
            if (error == WSAECONNRESET) {
                continue;
            }
            break;
        }
        stream_on_udp(buffer, (u32) size);
    }
    return 0;
}

static DWORD WINAPI stream_run(LPVOID param) {
    Unreferenced(param);
    stream_conn* c = &g_stream;

    if (!stream_ws_connect()) {
        if (!c->stop) {
            stream_fail(L"Couldn't connect to the stream server.");
        }
        return 0;
    }
    Log_Debug("Go Live: voice WebSocket connected to %s:%u", c->host, c->port);

    u32 capacity = 64 * 1024;
    u8* message  = (u8*) malloc(capacity);
    u32 used     = 0;
    for (; message;) {
        if (used + 4096 > capacity) {
            capacity *= 2;
            u8* bigger = (u8*) realloc(message, capacity);
            if (!bigger) {
                break;
            }
            message = bigger;
        }
        DWORD                          read  = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type  = WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE;
        DWORD                          error = WinHttpWebSocketReceive(c->h_ws, message + used, capacity - used - 1, &read, &type);
        if (error != NO_ERROR || type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            break;
        }
        used += read;
        if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) {
            message[used] = 0;
            if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
                stream_on_text((const char*) message, used);
            } else {
                stream_on_binary(message, used);
            }
            used = 0;
        }
    }
    free(message);

    if (!c->stop) {
        InterlockedExchange(&c->ready, 0);
        stream_fail(L"The stream connection closed.");
    }
    return 0;
}

static void stream_disconnect(void) {
    stream_conn* c = &g_stream;
    if (!g_stream_used) {
        return;
    }
    audio_stop();
    InterlockedExchange(&c->stop, 1);
    InterlockedExchange(&c->ready, 0);
    if (c->stop_event) {
        SetEvent(c->stop_event);
    }

    // Closing the handles wakes the threads blocked in receive
    if (c->h_ws) {
        WinHttpWebSocketClose(c->h_ws, 1000, NULL, 0);
        WinHttpCloseHandle(c->h_ws);
        c->h_ws = NULL;
    }
    if (c->sock != INVALID_SOCKET) {
        closesocket(c->sock);
    }

    HANDLE threads[4] = { c->connect_thread, c->udp_thread, c->heartbeat_thread, c->sender_thread };
    for (u32 i = 0; i < 4; ++i) {
        if (threads[i]) {
            WaitForSingleObject(threads[i], 3000);
            CloseHandle(threads[i]);
        }
    }
    c->connect_thread = c->udp_thread = c->heartbeat_thread = c->sender_thread = NULL;
    c->sock                                                                    = INVALID_SOCKET;

    if (c->h_connect) {
        WinHttpCloseHandle(c->h_connect);
        c->h_connect = NULL;
    }
    if (c->h_session) {
        WinHttpCloseHandle(c->h_session);
        c->h_session = NULL;
    }
    if (c->bkey) {
        BCryptDestroyKey(c->bkey);
        c->bkey = NULL;
    }
    if (c->alg) {
        BCryptCloseAlgorithmProvider(c->alg, 0);
        c->alg = NULL;
    }
    if (c->session) {
        daveSessionDestroy(c->session);
        c->session = NULL;
    }
    if (c->encryptor) {
        daveEncryptorDestroy(c->encryptor);
        c->encryptor = NULL;
    }
    if (c->ratchet) {
        daveKeyRatchetDestroy(c->ratchet);
        c->ratchet = NULL;
    }
    stream_queue_flush();
    for (u32 i = 0; i < stream_history; ++i) {
        free(c->history[i].payload);
        c->history[i].payload = NULL;
    }
    ss_bytes_free(&c->dave_out);
    if (c->stop_event) {
        CloseHandle(c->stop_event);
        c->stop_event = NULL;
    }
    if (c->ready_event) {
        CloseHandle(c->ready_event);
        c->ready_event = NULL;
    }
}

static u8 stream_connect(const stream_connect_info* info) {
    stream_conn* c = &g_stream;
    if (!g_stream_locks_ready) {
        InitializeCriticalSection(&g_stream_ws_lock);
        InitializeCriticalSection(&g_stream_send_lock);
        InitializeCriticalSection(&g_stream_dave_lock);
        g_stream_locks_ready = 1;
    }
    if (g_stream_used) {
        stream_disconnect();
    }
    g_stream_used = 1;

    memset(c, 0, sizeof *c);
    c->sock                  = INVALID_SOCKET;
    c->last_seq              = -1;
    c->pending_downgrade_tid = -1;

    snprintf(c->host, sizeof c->host, "%s", info->host);
    c->port   = info->port;
    c->secure = info->secure;
    snprintf(c->server_id, sizeof c->server_id, "%s", info->server_id);
    snprintf(c->user_id, sizeof c->user_id, "%s", info->user_id);
    snprintf(c->session_id, sizeof c->session_id, "%s", info->session_id);
    snprintf(c->token, sizeof c->token, "%s", info->token);
    c->server_id_num = strtoull(info->server_id, NULL, 10);
    c->width         = info->width;
    c->height        = info->height;
    c->fps           = info->fps;
    c->bitrate       = info->bitrate;
    stream_add_user(c->user_id);

    c->stop_event  = CreateEventW(NULL, TRUE, FALSE, NULL);
    c->ready_event = CreateEventW(NULL, TRUE, FALSE, NULL);

    stream_set_status(stream_state_connecting, L"Connecting...");
    c->sender_thread  = CreateThread(NULL, 0, stream_sender, NULL, 0, NULL);
    c->connect_thread = CreateThread(NULL, 0, stream_run, NULL, 0, NULL);
    return c->connect_thread != NULL;
}

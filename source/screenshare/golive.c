// NOTE(Xelph): I keep the owner of the account's voice line here (the QObject parent of the DisVoiceLine). Ripcord deletes
//              the voice line when the call ends but the owner lives as long as the account, so I hold on to the owner.
//              My start_worker hook sets it
static void* g_voice_owner;

static struct {
    char stream_key[160];
    char server_id[40];
    char token[320];
    char endpoint[200];
    char user_id[40];
    char session_id[96];
    u8   have_create;
    u8   have_server;
    u8   connecting;
    i32  width;
    i32  height;
    i32  fps;
    u32  bitrate;
    u64  started_ms;
} g_golive;

static u8 go_live_readable(const void* ptr, size_t size) {
    if (!ptr || ((uptr) ptr & 7)) {
        return 0;
    }
    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(ptr, &info, sizeof info) || info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
        return 0;
    }
    return (u8*) ptr + size <= (u8*) info.BaseAddress + info.RegionSize;
}

// NOTE(Xelph): I found the voice line at owner + 160, the same slot Ripcord's join/leave functions fill and clear
static DisVoiceLine* go_live_voice_line(void) {
    if (!go_live_readable(g_voice_owner, 0x100)) {
        return NULL;
    }
    DisVoiceLine* line = *(DisVoiceLine**) ((u8*) g_voice_owner + 160);
    if (!go_live_readable(line, sizeof *line) || !go_live_readable(line->priv, sizeof *line->priv)) {
        return NULL;
    }
    return line;
}

// NOTE(Xelph): I read the gateway from owner->priv + 0x28, the same place Ripcord reads it for its own voice state messages
static void* go_live_gateway(void) {
    if (!go_live_readable(g_voice_owner, 0x100)) {
        return NULL;
    }
    u8* priv = *(u8**) ((u8*) g_voice_owner + 0x10);
    if (!go_live_readable(priv, 0x30)) {
        return NULL;
    }
    void* gateway = *(void**) (priv + 0x28);
    if (!go_live_readable(gateway, 0x18) || !go_live_readable(*(void**) gateway, 8)) {
        return NULL;
    }
    return gateway;
}

static u8 go_live_in_voice(void) {
    DisVoiceLine* line = go_live_voice_line();
    return line && line->priv->vlWorker;
}

static u8 go_live_send(const char* json) {
    void* gateway = go_live_gateway();
    if (!gateway) {
        return 0;
    }

    QByteArray    json_ba;
    QJsonDocument document;
    QJsonObject   payload;
    QJsonValue    value;
    QByteArray_Constructor(&json_ba, json, (i32) strlen(json));
    QJsonDocument_FromJson(&document, &json_ba, 0);
    QJsonDocument_Object(&document, &payload);
    WebSocketHelpers_SendJsonAsEtf(gateway, QJsonValue_ConstructorQJsonObject(&value, &payload));

    QJsonObject_Destructor(&payload);
    QJsonDocument_Destructor(&document);
    QByteArray_Destructor(&json_ba);
    return 1;
}

static void go_live_copy(char* out, u32 size, ErfStr s) {
    out[0] = 0;
    if (s.length > 0 && (u32) s.length < size) {
        memcpy(out, s.data, (u32) s.length);
        out[s.length] = 0;
    }
}

static DWORD WINAPI go_live_connect(LPVOID param) {
    Unreferenced(param);

    char host[160];
    snprintf(host, sizeof host, "%s", g_golive.endpoint);
    u16   port  = 443;
    char* colon = strrchr(host, ':');
    if (colon) {
        port   = (u16) atoi(colon + 1);
        *colon = 0;
    }

    stream_connect_info info = {
        .host       = host,
        .port       = port,
        .secure     = 1,
        .server_id  = g_golive.server_id,
        .user_id    = g_golive.user_id,
        .session_id = g_golive.session_id,
        .token      = g_golive.token,
        .width      = g_golive.width,
        .height     = g_golive.height,
        .fps        = g_golive.fps,
        .bitrate    = g_golive.bitrate,
    };
    stream_connect(&info);
    return 0;
}

static void go_live_maybe_connect(void) {
    if (!g_golive.have_create || !g_golive.have_server || g_golive.connecting) {
        return;
    }
    g_golive.connecting = 1;
    stream_set_status(stream_state_connecting, L"Connecting...");
    HANDLE thread = CreateThread(NULL, 0, go_live_connect, NULL, 0, NULL);
    if (thread) {
        CloseHandle(thread);
    }
}

// NOTE(Xelph): Ripcord doesn't know these events, so I read them myself after it has handled the message
static void go_live_on_event(ErfMap* root_map) {
    if (g_stream_state != stream_state_requesting && g_stream_state != stream_state_connecting && g_stream_state != stream_state_live) {
        return;
    }

    ErfMapAny t, d;
    if (!Erf_GetOfType(root_map, S8Lit("t"), ErfTag_Str, &t) || !Erf_GetOfType(root_map, S8Lit("d"), ErfTag_Map, &d)) {
        return;
    }
    String8 event = {
        .cstr = (char*) t.str.data,
        .size = (u64) t.str.length,
    };
    u32 create = S8_Equals(event, S8Lit("STREAM_CREATE"));
    u32 server = S8_Equals(event, S8Lit("STREAM_SERVER_UPDATE"));
    u32 remove = S8_Equals(event, S8Lit("STREAM_DELETE"));
    if (!create && !server && !remove) {
        return;
    }

    char key[160];
    go_live_copy(key, sizeof key, Erf_GetStr(&d.map, S8Lit("stream_key")));
    size_t key_length  = strlen(key);
    size_t user_length = strlen(g_golive.user_id);
    if (key_length < user_length || strcmp(key + key_length - user_length, g_golive.user_id) != 0) {
        return;
    }

    if (create) {
        strcpy(g_golive.stream_key, key);
        snprintf(g_golive.server_id, sizeof g_golive.server_id, "%llu", Erf_GetFlake(&d.map, S8Lit("rtc_server_id"), 0));
        g_golive.have_create = 1;
        Log_Debug("Go Live: STREAM_CREATE %s, rtc server %s", g_golive.stream_key, g_golive.server_id);
    } else if (server) {
        go_live_copy(g_golive.token, sizeof g_golive.token, Erf_GetStr(&d.map, S8Lit("token")));
        go_live_copy(g_golive.endpoint, sizeof g_golive.endpoint, Erf_GetStr(&d.map, S8Lit("endpoint")));
        g_golive.have_server = g_golive.token[0] && g_golive.endpoint[0];
        Log_Debug("Go Live: STREAM_SERVER_UPDATE endpoint %s", g_golive.endpoint);
    } else {
        stream_fail(L"The stream was ended by Discord.");
        return;
    }
    go_live_maybe_connect();
}

static u8 go_live_begin(i32 width, i32 height, i32 fps, u32 bitrate) {
    DisVoiceLine*     line = go_live_voice_line();
    DisVoiceLinePriv* priv = line ? line->priv : NULL;
    if (!priv || !priv->vlWorker) {
        ss_fail(L"Join a voice channel first, then start sharing.");
        return 0;
    }
    if (!go_live_gateway()) {
        ss_fail(L"Couldn't reach Discord's gateway.");
        return 0;
    }

    memset(&g_golive, 0, sizeof g_golive);
    snprintf(g_golive.user_id, sizeof g_golive.user_id, "%llu", priv->userId);
    QByteArray session;
    QString_ToUtf8(&priv->sessionId, &session);
    snprintf(g_golive.session_id, sizeof g_golive.session_id, "%.*s", QByteArray_Size(&session), QByteArray_ConstData(&session));
    QByteArray_Destructor(&session);
    g_golive.width      = width;
    g_golive.height     = height;
    g_golive.fps        = fps;
    g_golive.bitrate    = bitrate;
    g_golive.started_ms = GetTickCount64();

    char json[320];
    if (priv->guildId == (u64) -1) {
        snprintf(json, sizeof json, "{\"op\":18,\"d\":{\"type\":\"call\",\"guild_id\":null,\"channel_id\":\"%llu\",\"preferred_region\":null}}", priv->channelId);
    } else {
        snprintf(json, sizeof json, "{\"op\":18,\"d\":{\"type\":\"guild\",\"guild_id\":\"%llu\",\"channel_id\":\"%llu\",\"preferred_region\":null}}", priv->guildId, priv->channelId);
    }
    stream_set_status(stream_state_requesting, L"Asking Discord for a stream...");
    if (!go_live_send(json)) {
        ss_fail(L"Couldn't send the request to Discord.");
        stream_set_status(stream_state_idle, L"");
        return 0;
    }
    Log_Debug("Go Live: requested a stream for channel %llu", priv->channelId);
    return 1;
}

static void go_live_end(void) {
    if (g_golive.stream_key[0]) {
        char json[260];
        snprintf(json, sizeof json, "{\"op\":19,\"d\":{\"stream_key\":\"%s\"}}", g_golive.stream_key);
        go_live_send(json);
    }
    stream_disconnect();
    memset(&g_golive, 0, sizeof g_golive);
    stream_set_status(stream_state_idle, L"");
}

static void go_live_tick(void) {
    if ((g_stream_state == stream_state_requesting || g_stream_state == stream_state_connecting) && GetTickCount64() - g_golive.started_ms > 25000) {
        stream_fail(L"Discord didn't start the stream in time.");
    }
}

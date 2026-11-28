typedef void  start_worker_fn(DisVoiceLine* this);
typedef void* qobject_parent_fn(const void* object);
typedef void  qobject_delete_later_fn(void* object);
static u32    Hook_Create(u8* base, u64 ptr, void* hook, void** orig);
static void   voice_line_start_worker_hook(DisVoiceLine* this);
typedef struct qt_object_api {
    qobject_parent_fn*       parent;
    qobject_delete_later_fn* delete_later;
} qt_object_api;
static u8 qt_object_api_load(qt_object_api* self) {
    HMODULE qt5core    = GetModuleHandleA("Qt5Core.dll");
    self->parent       = (qobject_parent_fn*) GetProcAddress(qt5core, "?parent@QObject@@QEBAPEAV1@XZ");
    self->delete_later = (qobject_delete_later_fn*) GetProcAddress(qt5core, "?deleteLater@QObject@@QEAAXXZ");
    return self->parent && self->delete_later;
}
typedef struct voice_monitor {
    qt_object_api    qt;
    start_worker_fn* start_worker;
    u8               server_update;
} voice_monitor;
static voice_monitor g_voice_monitor;
static u8            voice_monitor_string_equal(const QString* a, const QString* b) {
    i32 size = a->d->size;
    return size == b->d->size && memcmp(QTypedArrayData_Data(a->d), QTypedArrayData_Data(b->d), (u64) size * 2) == 0;
}
static u8 voice_monitor_has_connect_info(const voice_monitor* self, const DisVoiceLinePriv* priv) {
    Unreferenced(self);
    return priv->sessionId.d->size && priv->token.d->size && priv->endpoint.d->size;
}
static void voice_monitor_note_event(voice_monitor* self, ErfMap* root_map) {
    ErfStr t = Erf_GetStr(root_map, S8Lit("t"));
    if (t.length == sizeof "VOICE_SERVER_UPDATE" - 1 && memcmp(t.data, "VOICE_SERVER_UPDATE", t.length) == 0) {
        self->server_update = 1;
    }
}
static u8 voice_monitor_take_update(voice_monitor* self) {
    u8 seen             = self->server_update;
    self->server_update = 0;
    return seen;
}
static u8 voice_monitor_server_changed(const voice_monitor* self, const DisVoiceLinePriv* priv, const DisVLWorker* old) {
    return old && priv->stateType != 0 && voice_monitor_has_connect_info(self, priv) &&
           (!voice_monitor_string_equal(&priv->endpoint, &old->connEndpoint) || !voice_monitor_string_equal(&priv->token, &old->connToken));
}
static void voice_monitor_reopen_closed_line(const voice_monitor* self, DisVoiceLinePriv* priv, u8 server_update) {
    if (!priv->vlWorker && priv->stateType == 4 && server_update && voice_monitor_has_connect_info(self, priv)) {
        priv->stateType = 0;
    }
}
static void voice_monitor_retire_worker(voice_monitor* self, DisVoiceLinePriv* priv, DisVLWorker* old) {
    Log_Debug("Voice server changed, restarting the voice worker");
    // NOTE(Xelph): The old worker's "disconnected" slot posts a completion event to its parent voice line, which deletes
    //              whatever priv->vlWorker is by then, and that would be my new worker. I zero the parent pointer so the
    //              slot does nothing.
    *(u64*) (old->parentVoiceLine + 8) = 0;
    self->qt.delete_later(old);
    priv->vlWorker  = NULL;
    priv->stateType = 0;
}
// NOTE(Xelph): Ripcord ignores VOICE_SERVER_UPDATE while it has a voice worker, so a region change never reconnects.
//              Its handler stores the new endpoint and token in the voice line and calls this, which returns early when
//              stateType != 0 and a worker exists. If either changed, I retire the old worker and let the original start
//              a new one.
static void voice_monitor_start_worker(voice_monitor* self, DisVoiceLine* line) {
    g_voice_owner = self->qt.parent(line);

    DisVoiceLinePriv* priv          = line->priv;
    u8                server_update = voice_monitor_take_update(self);

    if (priv) {
        // NOTE(Xelph): Ripcord may already have torn the old connection down (state 4, no worker) before the new server
        //              arrived, and the original would return early. I reopen the line for the new server.
        voice_monitor_reopen_closed_line(self, priv, server_update);

        DisVLWorker* old = priv->vlWorker;
        if (voice_monitor_server_changed(self, priv, old)) {
            voice_monitor_retire_worker(self, priv, old);
        }
    }

    self->start_worker(line);
}
static void voice_monitor_install(voice_monitor* self) {
    if (!qt_object_api_load(&self->qt)) {
        return;
    }
    Hook_Create((u8*) GetModuleHandleA("Ripcord.exe"), 0xD1140, (void*) &voice_line_start_worker_hook, (void**) &self->start_worker);
}
static void voice_line_start_worker_hook(DisVoiceLine* this) {
    voice_monitor_start_worker(&g_voice_monitor, this);
}
static void voice_line_note_gateway_event(ErfMap* root_map) {
    voice_monitor_note_event(&g_voice_monitor, root_map);
}
static void voice_line_init(void) {
    voice_monitor_install(&g_voice_monitor);
}

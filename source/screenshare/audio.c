// stream audio constants
#define audio_rate             48000
#define audio_channels         2
#define audio_frame_size       960
#define audio_ring_frames      9600
#define audio_bitrate          96000
#define audio_frame_bytes      (audio_bitrate / 8 / 50)
#define audio_packet_max       1500
#define audio_gap_us           200000
#define opus_application_audio 2049
#define opus_set_bitrate       4002

static const GUID audio_iid_unknown = {
    0x00000000,
    0x0000,
    0x0000,
    { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};
static const GUID audio_iid_agile = {
    0x94EA2B94,
    0xE9CC,
    0x49E0,
    { 0xC0, 0xFF, 0xEE, 0x64, 0xCA, 0x8F, 0x5B, 0x90 }
};
static const GUID audio_iid_handler = {
    0x41D949AB,
    0x9862,
    0x444A,
    { 0x80, 0xF6, 0xC2, 0x61, 0x33, 0x4D, 0xA5, 0xEB }
};
static const GUID audio_iid_client = {
    0x1CB9AD4C,
    0xDBFA,
    0x4C32,
    { 0xB1, 0x78, 0xC2, 0xF5, 0x68, 0xA7, 0x03, 0xB2 }
};
static const GUID audio_iid_capture = {
    0xC8ADBD64,
    0xE71E,
    0x48A0,
    { 0xA4, 0xDE, 0x18, 0x5C, 0x39, 0x5C, 0xD3, 0x17 }
};

typedef HRESULT(WINAPI* audio_activate_fn)(LPCWSTR path, REFIID iid, PROPVARIANT* params, IActivateAudioInterfaceCompletionHandler* handler, IActivateAudioInterfaceAsyncOperation** operation);

typedef void* opus_create_fn(i32 rate, i32 channels, i32 application, i32* error);
typedef i32   opus_encode_fn(void* encoder, const i16* pcm, i32 frame_size, u8* data, i32 max_bytes);
typedef i32   opus_ctl_fn(void* encoder, i32 request, ...);
typedef void  opus_destroy_fn(void* encoder);

typedef struct {
    opus_create_fn*  create;
    opus_encode_fn*  encode;
    opus_ctl_fn*     ctl;
    opus_destroy_fn* destroy;
    void*            handle;
} audio_opus;

typedef struct {
    IActivateAudioInterfaceCompletionHandler iface;
    HANDLE                                   done;
} audio_handler;

typedef struct {
    IAudioClient*        client;
    IAudioCaptureClient* capture;
    HANDLE               event;
} audio_source;

typedef struct {
    HANDLE        thread;
    volatile LONG stop;
    volatile LONG muted;
    u16           sequence;
    u32           timestamp;
} audio_state;

static audio_state g_audio;

static HRESULT STDMETHODCALLTYPE audio_handler_query(IActivateAudioInterfaceCompletionHandler* self, REFIID iid, void** out) {
    if (IsEqualGUID(iid, &audio_iid_unknown) || IsEqualGUID(iid, &audio_iid_handler) || IsEqualGUID(iid, &audio_iid_agile)) {
        *out = self;
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE audio_handler_ref(IActivateAudioInterfaceCompletionHandler* self) {
    Unreferenced(self);
    return 1;
}

static HRESULT STDMETHODCALLTYPE audio_handler_done(IActivateAudioInterfaceCompletionHandler* self, IActivateAudioInterfaceAsyncOperation* op) {
    Unreferenced(op);
    SetEvent(((audio_handler*) self)->done);
    return S_OK;
}

static IActivateAudioInterfaceCompletionHandlerVtbl g_audio_handler_vtbl = {
    audio_handler_query,
    audio_handler_ref,
    audio_handler_ref,
    audio_handler_done,
};

static u8 audio_opus_load(audio_opus* opus) {
    HMODULE module = GetModuleHandleA("opus.dll");
    if (!module) {
        module = LoadLibraryA("opus.dll");
    }
    if (!module) {
        return 0;
    }
    opus->create  = (opus_create_fn*) GetProcAddress(module, "opus_encoder_create");
    opus->encode  = (opus_encode_fn*) GetProcAddress(module, "opus_encode");
    opus->ctl     = (opus_ctl_fn*) GetProcAddress(module, "opus_encoder_ctl");
    opus->destroy = (opus_destroy_fn*) GetProcAddress(module, "opus_encoder_destroy");
    if (!opus->create || !opus->encode || !opus->ctl || !opus->destroy) {
        return 0;
    }
    i32 error    = 0;
    opus->handle = opus->create(audio_rate, audio_channels, opus_application_audio, &error);
    if (!opus->handle || error != 0) {
        return 0;
    }
    // NOTE(Xelph): Ripcord's opus.dll is a CELT-only build that ignores the bitrate setting and fills every frame to the
    //              size I pass, so the frame size cap is what actually sets the bitrate. The ctl is for ordinary libopus builds
    opus->ctl(opus->handle, opus_set_bitrate, (i32) audio_bitrate);
    return 1;
}

static void audio_opus_close(audio_opus* opus) {
    if (opus->handle) {
        opus->destroy(opus->handle);
        opus->handle = NULL;
    }
}

// NOTE(Xelph): I capture with a process loopback client. Including a process tree gives only that app's sound (Chrome plays
//              from a child process, hence the tree), and excluding Ripcord's own tree gives everything else on the PC
//              without feeding the call back into the stream
static u8 audio_source_open(audio_source* source, DWORD pid, u8 include) {
    memset(source, 0, sizeof *source);

    HMODULE           module   = LoadLibraryW(L"Mmdevapi.dll");
    audio_activate_fn activate = module ? (audio_activate_fn) GetProcAddress(module, "ActivateAudioInterfaceAsync") : NULL;
    if (!activate) {
        return 0;
    }

    AUDIOCLIENT_ACTIVATION_PARAMS params         = { 0 };
    params.ActivationType                        = AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK;
    params.ProcessLoopbackParams.TargetProcessId = pid;
    params.ProcessLoopbackParams.ProcessLoopbackMode =
        include ? PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE : PROCESS_LOOPBACK_MODE_EXCLUDE_TARGET_PROCESS_TREE;

    PROPVARIANT variant    = { 0 };
    variant.vt             = VT_BLOB;
    variant.blob.cbSize    = sizeof params;
    variant.blob.pBlobData = (BYTE*) &params;

    audio_handler                          handler   = { .iface.lpVtbl = &g_audio_handler_vtbl, .done = CreateEventW(NULL, FALSE, FALSE, NULL) };
    IActivateAudioInterfaceAsyncOperation* operation = NULL;
    HRESULT                                hr        = activate(L"VAD\\Process_Loopback", &audio_iid_client, &variant, &handler.iface, &operation);
    u8                                     ok        = 0;
    if (SUCCEEDED(hr) && WaitForSingleObject(handler.done, 5000) == WAIT_OBJECT_0) {
        HRESULT   result  = E_FAIL;
        IUnknown* unknown = NULL;
        IActivateAudioInterfaceAsyncOperation_GetActivateResult(operation, &result, &unknown);
        if (SUCCEEDED(result) && unknown) {
            unknown->lpVtbl->QueryInterface(unknown, &audio_iid_client, (void**) &source->client);
            unknown->lpVtbl->Release(unknown);
        }
    }
    if (operation) {
        operation->lpVtbl->Release(operation);
    }
    CloseHandle(handler.done);
    if (!source->client) {
        return 0;
    }

    WAVEFORMATEX format = { WAVE_FORMAT_PCM, audio_channels, audio_rate, audio_rate * audio_channels * 2, audio_channels * 2, 16, 0 };
    DWORD        flags  = AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM |
                          AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
    source->event       = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok                  = SUCCEEDED(IAudioClient_Initialize(source->client, AUDCLNT_SHAREMODE_SHARED, flags, 200000, 0, &format, NULL)) &&
                          SUCCEEDED(IAudioClient_SetEventHandle(source->client, source->event)) &&
                          SUCCEEDED(IAudioClient_GetService(source->client, &audio_iid_capture, (void**) &source->capture)) &&
                          SUCCEEDED(IAudioClient_Start(source->client));
    return ok;
}

static void audio_source_close(audio_source* source) {
    if (source->client) {
        IAudioClient_Stop(source->client);
    }
    ss_release(source->capture);
    ss_release(source->client);
    if (source->event) {
        CloseHandle(source->event);
        source->event = NULL;
    }
}

// Appends everything the device has buffered to `ring`. Silent packets are written as zeros. If the ring would overflow
// the old audio is dropped, which only happens if the encoder thread stalls
static void audio_source_drain(audio_source* source, i16* ring, u32* count) {
    for (;;) {
        UINT32 packet = 0;
        if (FAILED(IAudioCaptureClient_GetNextPacketSize(source->capture, &packet)) || packet == 0) {
            return;
        }
        BYTE*  data   = NULL;
        UINT32 frames = 0;
        DWORD  flags  = 0;
        if (FAILED(IAudioCaptureClient_GetBuffer(source->capture, &data, &frames, &flags, NULL, NULL))) {
            return;
        }
        if (*count + frames > audio_ring_frames) {
            *count = 0;
        }
        if (frames > audio_ring_frames) {
            frames = audio_ring_frames;
        }
        if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
            memset(ring + *count * audio_channels, 0, frames * audio_channels * sizeof(i16));
        } else {
            memcpy(ring + *count * audio_channels, data, frames * audio_channels * sizeof(i16));
        }
        *count += frames;
        IAudioCaptureClient_ReleaseBuffer(source->capture, frames);
    }
}

static void audio_send_speaking(u8 speaking) {
    char json[128];
    snprintf(json, sizeof json, "{\"op\":5,\"d\":{\"speaking\":%d,\"delay\":0,\"ssrc\":%u}}", speaking ? 2 : 0, g_stream.ssrc);
    stream_send_json(json);
}

// One Opus frame as one RTP packet on the audio SSRC. It goes straight to the socket instead of through the video queue,
// because that queue drops its backlog when the link is slow and audio shouldn't be part of that
static void audio_send_packet(const u8* opus, u32 size, u32 timestamp) {
    stream_conn* c = &g_stream;
    if (!InterlockedCompareExchange(&c->ready, 0, 0) || c->sock == INVALID_SOCKET) {
        return;
    }

    u8        encrypted[audio_packet_max];
    const u8* payload = opus;
    u32       length  = size;
    if (c->use_dave) {
        EnterCriticalSection(&g_stream_dave_lock);
        if (!c->encryptor || !daveEncryptorHasKeyRatchet(c->encryptor)) {
            LeaveCriticalSection(&g_stream_dave_lock);
            return;
        }
        size_t                  written = 0;
        DAVEEncryptorResultCode result  = DAVE_ENCRYPTOR_RESULT_CODE_ENCRYPTION_FAILURE;
        if (daveEncryptorGetMaxCiphertextByteSize(c->encryptor, DAVE_MEDIA_TYPE_AUDIO, size) <= sizeof encrypted) {
            result = daveEncryptorEncrypt(c->encryptor, DAVE_MEDIA_TYPE_AUDIO, c->ssrc, opus, size, encrypted, sizeof encrypted, &written);
        }
        LeaveCriticalSection(&g_stream_dave_lock);
        if (result != DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS || written == 0) {
            return;
        }
        payload = encrypted;
        length  = (u32) written;
    }

    u8  packet[stream_packet_max];
    u32 header = stream_rtp_header(packet, 0, stream_pt_audio, g_audio.sequence++, timestamp, c->ssrc);
    u32 total  = stream_seal(packet, header, payload, length);
    if (total) {
        send(c->sock, (const char*) packet, (int) total, 0);
    }
}

static DWORD WINAPI audio_thread(LPVOID param) {
    Unreferenced(param);
    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    DWORD pid     = GetCurrentProcessId();
    u8    include = 0;
    if (g_engine.config.kind == ss_kind_application && g_engine.config.window) {
        DWORD window_pid = 0;
        GetWindowThreadProcessId(g_engine.config.window, &window_pid);
        if (window_pid == pid) {
            Log_Debug("Go Live: sharing Ripcord itself, no audio");
            CoUninitialize();
            return 0;
        }
        pid     = window_pid;
        include = 1;
    }

    audio_opus   opus   = { 0 };
    audio_source source = { 0 };
    i16*         ring   = (i16*) malloc(audio_ring_frames * audio_channels * sizeof(i16));
    if (!ring || !audio_opus_load(&opus)) {
        Log_Debug("Go Live: no Opus encoder, sharing without audio");
    } else if (!audio_source_open(&source, pid, include)) {
        Log_Debug("Go Live: couldn't capture audio (needs Windows 10 2004 or later), sharing without audio");
    } else {
        Log_Debug("Go Live: audio %s pid %lu", include ? "from" : "from everything except Ripcord, excluded", (unsigned long) pid);
        audio_send_speaking(1);
        u8 was_muted = 0;

        u32 count   = 0;
        i64 last_us = 0;
        while (!InterlockedCompareExchange(&g_audio.stop, 0, 0)) {
            WaitForSingleObject(source.event, 10);
            audio_source_drain(&source, ring, &count);
            u8 muted = InterlockedCompareExchange(&g_audio.muted, 0, 0) != 0;
            if (muted != was_muted) {
                audio_send_speaking(!muted);
                was_muted = muted;
            }
            if (muted) {
                count = 0;
                continue;
            }
            while (count >= audio_frame_size) {
                u8  out[audio_packet_max];
                i32 size = opus.encode(opus.handle, ring, audio_frame_size, out, audio_frame_bytes);
                count -= audio_frame_size;
                memmove(ring, ring + audio_frame_size * audio_channels, count * audio_channels * sizeof(i16));
                if (size <= 0) {
                    continue;
                }
                i64 now = stream_now_us();
                if (last_us && now - last_us > audio_gap_us) {
                    g_audio.timestamp += (u32) ((now - last_us) * audio_rate / 1000000);
                }
                last_us = now;
                audio_send_packet(out, (u32) size, g_audio.timestamp);
                g_audio.timestamp += audio_frame_size;
            }
        }
        audio_send_speaking(0);
    }

    audio_source_close(&source);
    audio_opus_close(&opus);
    free(ring);
    CoUninitialize();
    return 0;
}

static void audio_start(void) {
    if (g_audio.thread) {
        return;
    }
    g_audio.stop   = 0;
    g_audio.muted  = 0;
    g_audio.thread = CreateThread(NULL, 0, audio_thread, NULL, 0, NULL);
}

static void audio_stop(void) {
    if (!g_audio.thread) {
        return;
    }
    InterlockedExchange(&g_audio.stop, 1);
    WaitForSingleObject(g_audio.thread, 5000);
    CloseHandle(g_audio.thread);
    g_audio.thread = NULL;
}

static u8 audio_is_muted(void) {
    return InterlockedCompareExchange(&g_audio.muted, 0, 0) != 0;
}

static void audio_toggle_mute(void) {
    InterlockedExchange(&g_audio.muted, !audio_is_muted());
}

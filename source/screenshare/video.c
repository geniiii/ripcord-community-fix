#define ss_max_width      2560
#define ss_min_size       16
#define ss_gop_seconds    2
#define ss_clock_hz       90000
#define ss_min_fps        5
#define ss_start_wait     10000
#define ss_stop_wait      5000
#define ss_dxgi_wait      100
#define ss_drain_attempts 4

static const GUID ss_clsid_video_processor = {
    0x88753B26,
    0x5B24,
    0x49BD,
    { 0xB2, 0xE7, 0x0C, 0x44, 0x5C, 0x78, 0xC9, 0x82 }
};

typedef struct {
    ss_config config;
    i32       src_w, src_h;
    i32       enc_w, enc_h;
    i32       fps;
    u32       bitrate;
    RECT      rect;

    HANDLE        thread;
    HANDLE        ready;
    volatile LONG stop;
    volatile LONG need_key;
    u8            started;

    HMONITOR                monitor;
    ID3D11Device*           device;
    ID3D11DeviceContext*    context;
    IDXGIOutputDuplication* duplication;
    ID3D11Texture2D*        staging;

    HDC     clean_dc, shown_dc;
    HBITMAP clean_bmp, shown_bmp;
    u8*     clean_bits;
    u8*     shown_bits;
    HCURSOR cursor;
    POINT   cursor_hot;

    IMFTransform* convert;
    IMFTransform* encoder;
    IMFSample*    convert_in;
    IMFSample*    convert_out;
    IMFSample*    coded;
    u8            sps_pps[256];
    u32           sps_pps_size;

    i64 start_us;
    u32 last_timestamp;
    u32 tick;

    u32 frames;
    u64 bytes;
    i64 stats_us;
} ss_engine;

static ss_engine g_engine;
static ss_config g_ss_current;
static ss_stats  g_ss_stats;
static wchar_t   g_ss_error[160];
static u8        g_ss_active;

#define ss_release(p)                                            \
    do {                                                         \
        if (p) {                                                 \
            ((IUnknown*) (p))->lpVtbl->Release((IUnknown*) (p)); \
            (p) = NULL;                                          \
        }                                                        \
    } while (0)

static void ss_fail(const wchar_t* message) {
    wcsncpy(g_ss_error, message, ArrayCount(g_ss_error) - 1);
    g_ss_error[ArrayCount(g_ss_error) - 1] = 0;
}

static u64 ss_pack(u32 high, u32 low) {
    return ((u64) high << 32) | low;
}

static void ss_request_key(void) {
    InterlockedExchange(&g_engine.need_key, 1);
}

// NOTE(Xelph): The output is the configured height with the width from the source's aspect ratio, kept even and under what
//              Discord's servers carry. A screen is never upscaled
static void ss_output_size(const ss_config* config, i32 src_w, i32 src_h) {
    ss_engine* e      = &g_engine;
    i32        height = (i32) config->height;
    if (config->kind == ss_kind_screen && height > src_h) {
        height = src_h;
    }
    i32 width = (i32) ((i64) src_w * height / src_h);
    if (width > ss_max_width) {
        height = (i32) ((i64) height * ss_max_width / width);
        width  = ss_max_width;
    }
    e->enc_w = (width & ~1) < ss_min_size ? ss_min_size : width & ~1;
    e->enc_h = (height & ~1) < ss_min_size ? ss_min_size : height & ~1;
}

static u32 ss_bitrate(void) {
    static const double bits_per_pixel[] = { 0.04, 0.07, 0.10 };
    static const double minimum[]        = { 1500000.0, 2000000.0, 3000000.0 };
    static const double maximum[]        = { 4000000.0, 8000000.0, 10000000.0 };

    ss_engine* e       = &g_engine;
    u32        level   = e->config.quality > 2 ? 2 : e->config.quality;
    double     bitrate = (double) e->enc_w * e->enc_h * e->fps * bits_per_pixel[level];
    return (u32) (bitrate < minimum[level] ? minimum[level] : bitrate > maximum[level] ? maximum[level]
                                                                                       : bitrate);
}

//~ Capture

static HBITMAP ss_create_dib(HDC* dc, i32 width, i32 height, u8** bits) {
    BITMAPINFO info              = { 0 };
    info.bmiHeader.biSize        = sizeof info.bmiHeader;
    info.bmiHeader.biWidth       = width;
    info.bmiHeader.biHeight      = -height;
    info.bmiHeader.biPlanes      = 1;
    info.bmiHeader.biBitCount    = 32;
    info.bmiHeader.biCompression = BI_RGB;
    HBITMAP bitmap               = CreateDIBSection(NULL, &info, DIB_RGB_COLORS, (void**) bits, NULL, 0);
    if (bitmap) {
        if (!*dc) {
            *dc = CreateCompatibleDC(NULL);
        }
        DeleteObject(SelectObject(*dc, bitmap));
    }
    return bitmap;
}

static void ss_free_surfaces(void) {
    ss_engine* e = &g_engine;
    DeleteDC(e->clean_dc);
    DeleteDC(e->shown_dc);
    DeleteObject(e->clean_bmp);
    DeleteObject(e->shown_bmp);
    e->clean_dc = e->shown_dc = NULL;
    e->clean_bmp = e->shown_bmp = NULL;
}

static u8 ss_init_duplication(void) {
    ss_engine* e = &g_engine;
    ss_release(e->duplication);
    ss_release(e->context);
    ss_release(e->device);

    // NOTE(Xelph): The monitor can hang off any adapter (laptops with two GPUs) and duplication has to use the device that owns it
    IDXGIFactory1* factory = NULL;
    if (FAILED(CreateDXGIFactory1(&IID_IDXGIFactory1, (void**) &factory))) {
        return 0;
    }
    IDXGIAdapter1* adapter = NULL;
    IDXGIOutput*   output  = NULL;
    for (UINT a = 0; !output && IDXGIFactory1_EnumAdapters1(factory, a, &adapter) == S_OK; ++a) {
        for (UINT o = 0; !output && IDXGIAdapter1_EnumOutputs(adapter, o, &output) == S_OK; ++o) {
            DXGI_OUTPUT_DESC desc;
            IDXGIOutput_GetDesc(output, &desc);
            if (desc.Monitor != e->monitor) {
                ss_release(output);
            }
        }
        if (!output) {
            ss_release(adapter);
        }
    }
    ss_release(factory);
    if (!output) {
        return 0;
    }

    D3D_FEATURE_LEVEL level;
    HRESULT           hr = D3D11CreateDevice((IDXGIAdapter*) adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                                             D3D11_SDK_VERSION, &e->device, &level, &e->context);
    ss_release(adapter);
    IDXGIOutput1* output1 = NULL;
    if (SUCCEEDED(hr) && SUCCEEDED(IDXGIOutput_QueryInterface(output, &IID_IDXGIOutput1, (void**) &output1))) {
        hr = IDXGIOutput1_DuplicateOutput(output1, (IUnknown*) e->device, &e->duplication);
    }
    ss_release(output1);
    ss_release(output);
    return e->duplication != NULL;
}

static u8 ss_grab_screen(UINT wait_ms) {
    ss_engine*              e        = &g_engine;
    DXGI_OUTDUPL_FRAME_INFO info     = { 0 };
    IDXGIResource*          resource = NULL;
    HRESULT                 hr       = IDXGIOutputDuplication_AcquireNextFrame(e->duplication, wait_ms, &info, &resource);
    if (hr == DXGI_ERROR_ACCESS_LOST) {
        // NOTE(Xelph): A mode change, the UAC prompt or the lock screen invalidates the duplication
        ss_init_duplication();
        return 0;
    }
    if (FAILED(hr)) {
        return 0;
    }

    ID3D11Texture2D* texture = NULL;
    IDXGIResource_QueryInterface(resource, &IID_ID3D11Texture2D, (void**) &texture);
    ss_release(resource);
    u8 copied = 0;
    if (texture) {
        D3D11_TEXTURE2D_DESC desc;
        ID3D11Texture2D_GetDesc(texture, &desc);
        if (!e->staging) {
            desc.Usage          = D3D11_USAGE_STAGING;
            desc.BindFlags      = 0;
            desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
            desc.MiscFlags      = 0;
            ID3D11Device_CreateTexture2D(e->device, &desc, NULL, &e->staging);
        }
        D3D11_MAPPED_SUBRESOURCE mapped;
        if (e->staging) {
            ID3D11DeviceContext_CopyResource(e->context, (ID3D11Resource*) e->staging, (ID3D11Resource*) texture);
            if (SUCCEEDED(ID3D11DeviceContext_Map(e->context, (ID3D11Resource*) e->staging, 0, D3D11_MAP_READ, 0, &mapped))) {
                for (i32 y = 0; y < e->src_h; ++y) {
                    memcpy(e->clean_bits + (u64) y * e->src_w * 4, (const u8*) mapped.pData + (u64) y * mapped.RowPitch, (u64) e->src_w * 4);
                }
                ID3D11DeviceContext_Unmap(e->context, (ID3D11Resource*) e->staging, 0);
                copied = 1;
            }
        }
        ss_release(texture);
    }
    IDXGIOutputDuplication_ReleaseFrame(e->duplication);
    return copied;
}

static u8 ss_grab_window(void) {
    ss_engine* e = &g_engine;
    RECT       rect;
    if (!GetWindowRect(e->config.window, &rect) || IsIconic(e->config.window)) {
        return 0;
    }
    e->rect = rect;

    // NOTE(Xelph): PW_RENDERFULLCONTENT (2) so windows drawn by the GPU aren't black
    return PrintWindow(e->config.window, e->clean_dc, 2) != 0;
}

// NOTE(Xelph): Neither capture path includes the pointer, so I draw it on a copy of the frame
static void ss_draw_cursor(void) {
    ss_engine* e = &g_engine;
    memcpy(e->shown_bits, e->clean_bits, (u64) e->src_w * e->src_h * 4);

    CURSORINFO cursor = { sizeof cursor };
    if (!GetCursorInfo(&cursor) || !(cursor.flags & CURSOR_SHOWING)) {
        return;
    }
    if (cursor.hCursor != e->cursor) {
        ICONINFO info;
        if (!GetIconInfo(cursor.hCursor, &info)) {
            return;
        }
        e->cursor     = cursor.hCursor;
        e->cursor_hot = (POINT){ (LONG) info.xHotspot, (LONG) info.yHotspot };
        DeleteObject(info.hbmColor);
        DeleteObject(info.hbmMask);
    }
    DrawIconEx(e->shown_dc, cursor.ptScreenPos.x - e->rect.left - e->cursor_hot.x, cursor.ptScreenPos.y - e->rect.top - e->cursor_hot.y,
               cursor.hCursor, 0, 0, 0, NULL, DI_NORMAL);
}

//~ Convert and encode

static IMFMediaType* ss_video_type(const GUID* subtype, i32 width, i32 height) {
    ss_engine*    e    = &g_engine;
    IMFMediaType* type = NULL;
    MFCreateMediaType(&type);
    IMFMediaType_SetGUID(type, &MF_MT_MAJOR_TYPE, &MFMediaType_Video);
    IMFMediaType_SetGUID(type, &MF_MT_SUBTYPE, subtype);
    IMFMediaType_SetUINT64(type, &MF_MT_FRAME_SIZE, ss_pack((u32) width, (u32) height));
    IMFMediaType_SetUINT64(type, &MF_MT_FRAME_RATE, ss_pack((u32) e->fps, 1));
    IMFMediaType_SetUINT64(type, &MF_MT_PIXEL_ASPECT_RATIO, ss_pack(1, 1));
    IMFMediaType_SetUINT32(type, &MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    return type;
}

static IMFSample* ss_make_sample(u32 size) {
    IMFSample*      sample = NULL;
    IMFMediaBuffer* buffer = NULL;
    MFCreateSample(&sample);
    MFCreateMemoryBuffer(size, &buffer);
    IMFSample_AddBuffer(sample, buffer);
    IMFMediaBuffer_Release(buffer);
    return sample;
}

// NOTE(Xelph): The Video Processor MFT does the colour conversion, the scale and the letterboxing, so there's no pixel code of
//              my own here. It is Windows' own, vectorised, and as fast in a debug build as in a release one
static u8 ss_init_convert(void) {
    ss_engine* e = &g_engine;
    if (FAILED(CoCreateInstance(&ss_clsid_video_processor, NULL, CLSCTX_INPROC_SERVER, &IID_IMFTransform, (void**) &e->convert))) {
        return 0;
    }

    IMFMediaType* in = ss_video_type(&MFVideoFormat_RGB32, e->src_w, e->src_h);
    IMFMediaType_SetUINT32(in, &MF_MT_DEFAULT_STRIDE, (UINT32) (e->src_w * 4));
    IMFMediaType* out = ss_video_type(&MFVideoFormat_NV12, e->enc_w, e->enc_h);
    u8            ok  = SUCCEEDED(IMFTransform_SetInputType(e->convert, 0, in, 0)) && SUCCEEDED(IMFTransform_SetOutputType(e->convert, 0, out, 0));
    IMFMediaType_Release(in);
    IMFMediaType_Release(out);
    if (!ok) {
        return 0;
    }

    i32 fit_w = e->enc_w, fit_h = (i32) ((i64) e->src_h * e->enc_w / e->src_w);
    if (fit_h > e->enc_h) {
        fit_h = e->enc_h;
        fit_w = (i32) ((i64) e->src_w * e->enc_h / e->src_h);
    }
    IMFVideoProcessorControl* control = NULL;
    if (SUCCEEDED(IMFTransform_QueryInterface(e->convert, &IID_IMFVideoProcessorControl, (void**) &control))) {
        RECT fit = { (e->enc_w - fit_w) / 2, (e->enc_h - fit_h) / 2, (e->enc_w + fit_w) / 2, (e->enc_h + fit_h) / 2 };
        IMFVideoProcessorControl_SetDestinationRectangle(control, &fit);
        IMFVideoProcessorControl_Release(control);
    }

    e->convert_in  = ss_make_sample((u32) e->src_w * e->src_h * 4);
    e->convert_out = ss_make_sample((u32) e->enc_w * e->enc_h * 3 / 2);
    return e->convert_in && e->convert_out;
}

static u8 ss_init_encoder(void) {
    ss_engine* e = &g_engine;
    if (FAILED(CoCreateInstance(&CLSID_CMSH264EncoderMFT, NULL, CLSCTX_INPROC_SERVER, &IID_IMFTransform, (void**) &e->encoder))) {
        return 0;
    }

    // NOTE(Xelph): Baseline has no B-frames and no reordering, so decode order is display order and the capture timestamps stay valid
    IMFMediaType* out = ss_video_type(&MFVideoFormat_H264, e->enc_w, e->enc_h);
    IMFMediaType_SetUINT32(out, &MF_MT_AVG_BITRATE, e->bitrate);
    IMFMediaType_SetUINT32(out, &MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base);
    IMFMediaType* in = ss_video_type(&MFVideoFormat_NV12, e->enc_w, e->enc_h);
    u8            ok = SUCCEEDED(IMFTransform_SetOutputType(e->encoder, 0, out, 0)) && SUCCEEDED(IMFTransform_SetInputType(e->encoder, 0, in, 0));
    IMFMediaType_Release(in);
    IMFMediaType_Release(out);
    if (!ok) {
        return 0;
    }

    ICodecAPI* codec = NULL;
    if (SUCCEEDED(IMFTransform_QueryInterface(e->encoder, &IID_ICodecAPI, (void**) &codec))) {
        struct {
            const GUID* key;
            VARTYPE     type;
            u32         value;
        } settings[] = {
            {      &CODECAPI_AVEncCommonLowLatency, VT_BOOL,              (u32) VARIANT_TRUE },
            { &CODECAPI_AVEncCommonRateControlMode,  VT_UI4, eAVEncCommonRateControlMode_CBR },
            {     &CODECAPI_AVEncCommonMeanBitRate,  VT_UI4,                      e->bitrate },
            {            &CODECAPI_AVEncMPVGOPSize,  VT_UI4,   (u32) e->fps * ss_gop_seconds },
        };
        for (u32 i = 0; i < ArrayCount(settings); ++i) {
            VARIANT v;
            VariantInit(&v);
            V_VT(&v)  = settings[i].type;
            V_UI4(&v) = settings[i].value;
            ICodecAPI_SetValue(codec, settings[i].key, &v);
        }
        ICodecAPI_Release(codec);
    }
    MFT_OUTPUT_STREAM_INFO info = { 0 };
    IMFTransform_GetOutputStreamInfo(e->encoder, 0, &info);
    e->coded = ss_make_sample(info.cbSize);
    IMFTransform_ProcessMessage(e->encoder, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    IMFTransform_ProcessMessage(e->encoder, MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);

    // NOTE(Xelph): The encoder only puts SPS and PPS in its first frame, so I keep them from the sequence header and put them
    //              back in front of every keyframe, which is what lets a viewer join mid-stream
    IMFMediaType* current = NULL;
    UINT32        size    = 0;
    if (SUCCEEDED(IMFTransform_GetOutputCurrentType(e->encoder, 0, &current))) {
        IMFMediaType_GetBlob(current, &MF_MT_MPEG_SEQUENCE_HEADER, e->sps_pps, sizeof e->sps_pps, &size);
        e->sps_pps_size = size;
        IMFMediaType_Release(current);
    }
    return 1;
}

// NOTE(Xelph): Whether the Annex B data holds a NAL of the given type (5 is an IDR slice)
static u8 ss_has_nal(const u8* data, u32 size, u32 type) {
    for (u32 i = 0; i + 4 < size; ++i) {
        if (data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 && (u32) (data[i + 3] & 0x1F) == type) {
            return 1;
        }
    }
    return 0;
}

static u8 ss_convert(void) {
    ss_engine* e = &g_engine;
    if (FAILED(IMFTransform_ProcessInput(e->convert, 0, e->convert_in, 0))) {
        return 0;
    }

    // NOTE(Xelph): The converter marks its output incomplete and refuses the next frame until it has been asked again
    u8 got = 0;
    for (i32 attempt = 0; attempt < ss_drain_attempts; ++attempt) {
        MFT_OUTPUT_DATA_BUFFER data = { .pSample = e->convert_out };
        DWORD                  status;
        if (FAILED(IMFTransform_ProcessOutput(e->convert, 0, 1, &data, &status))) {
            break;
        }
        got = 1;
    }
    return got;
}

static void ss_emit(const u8* data, u32 size, u32 timestamp) {
    ss_engine* e = &g_engine;
    stream_send_frame(data, size, timestamp);
    ++e->frames;
    e->bytes += size;
}

static void ss_encode(u32 timestamp, u8 key_frame) {
    ss_engine* e = &g_engine;

    IMFMediaBuffer* buffer = NULL;
    BYTE*           bytes  = NULL;
    IMFSample_GetBufferByIndex(e->convert_in, 0, &buffer);
    IMFMediaBuffer_Lock(buffer, &bytes, NULL, NULL);
    memcpy(bytes, e->shown_bits, (u64) e->src_w * e->src_h * 4);
    IMFMediaBuffer_Unlock(buffer);
    IMFMediaBuffer_SetCurrentLength(buffer, (DWORD) e->src_w * e->src_h * 4);
    IMFMediaBuffer_Release(buffer);

    LONGLONG duration = 10000000LL / e->fps;
    LONGLONG time     = (LONGLONG) e->tick * duration;
    IMFSample_SetSampleTime(e->convert_in, time);
    IMFSample_SetSampleDuration(e->convert_in, duration);
    if (!ss_convert()) {
        return;
    }
    IMFSample_SetSampleTime(e->convert_out, time);
    IMFSample_SetSampleDuration(e->convert_out, duration);

    if (key_frame) {
        ICodecAPI* codec = NULL;
        if (SUCCEEDED(IMFTransform_QueryInterface(e->encoder, &IID_ICodecAPI, (void**) &codec))) {
            VARIANT v;
            VariantInit(&v);
            V_VT(&v)  = VT_UI4;
            V_UI4(&v) = 1;
            ICodecAPI_SetValue(codec, &CODECAPI_AVEncVideoForceKeyFrame, &v);
            ICodecAPI_Release(codec);
        }
    }

    if (FAILED(IMFTransform_ProcessInput(e->encoder, 0, e->convert_out, 0))) {
        return;
    }
    for (i32 attempt = 0; attempt < ss_drain_attempts; ++attempt) {
        MFT_OUTPUT_DATA_BUFFER out = { .pSample = e->coded };
        DWORD                  status;
        HRESULT                hr = IMFTransform_ProcessOutput(e->encoder, 0, 1, &out, &status);
        if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
            IMFMediaType* type = NULL;
            if (SUCCEEDED(IMFTransform_GetOutputAvailableType(e->encoder, 0, 0, &type))) {
                IMFTransform_SetOutputType(e->encoder, 0, type, 0);
                IMFMediaType_Release(type);
            }
            continue;
        }
        if (FAILED(hr)) {
            break;
        }

        IMFMediaBuffer* contiguous = NULL;
        BYTE*           data       = NULL;
        DWORD           length     = 0;
        IMFSample_ConvertToContiguousBuffer(e->coded, &contiguous);
        IMFMediaBuffer_Lock(contiguous, &data, NULL, &length);
        u8* frame = (u8*) ss_scratch_push(e->sps_pps_size + length);
        if (frame && length) {
            u32 prefix = ss_has_nal(data, length, 5) && !ss_has_nal(data, length, 7) ? e->sps_pps_size : 0;
            memcpy(frame, e->sps_pps, prefix);
            memcpy(frame + prefix, data, length);
            ss_emit(frame, prefix + length, timestamp);
        }
        IMFMediaBuffer_Unlock(contiguous);
        IMFMediaBuffer_Release(contiguous);
    }
}

static void ss_tick(void) {
    ss_engine* e = &g_engine;

    u8 grabbed = e->config.kind == ss_kind_screen ? ss_grab_screen(e->tick ? 0 : ss_dxgi_wait) : ss_grab_window();
    if (!grabbed && e->tick == 0) {
        return;
    }

    ss_draw_cursor();

    u32 timestamp = (u32) ((ss_now_us() - e->start_us) * ss_clock_hz / 1000000);
    if (e->last_timestamp && timestamp <= e->last_timestamp) {
        timestamp = e->last_timestamp + 1;
    }
    e->last_timestamp = timestamp;

    u8 key_frame = InterlockedExchange(&e->need_key, 0) != 0 || e->tick % (u32) (e->fps * ss_gop_seconds) == 0;
    ss_encode(timestamp, key_frame);
    ++e->tick;

    i64 now = ss_now_us();
    if (now - e->stats_us >= 1000000) {
        double seconds  = (double) (now - e->stats_us) / 1000000.0;
        g_ss_stats.fps  = e->frames / seconds;
        g_ss_stats.kbps = (double) e->bytes * 8.0 / seconds / 1000.0;
        e->frames       = 0;
        e->bytes        = 0;
        e->stats_us     = now;
    }
}

//~ Lifetime

static u8 ss_setup(void) {
    ss_engine* e = &g_engine;

    if (e->config.kind == ss_kind_screen) {
        e->rect    = e->config.screen;
        e->monitor = MonitorFromRect(&e->rect, MONITOR_DEFAULTTONULL);
    } else if (!IsWindow(e->config.window) || !GetWindowRect(e->config.window, &e->rect)) {
        ss_fail(L"That window is no longer available.");
        return 0;
    } else if (IsIconic(e->config.window)) {
        ss_fail(L"That window is minimized. Restore it and try again.");
        return 0;
    }
    e->src_w = e->rect.right - e->rect.left;
    e->src_h = e->rect.bottom - e->rect.top;
    if (e->src_w <= 0 || e->src_h <= 0) {
        ss_fail(L"Couldn't read the size of that source.");
        return 0;
    }
    if (e->config.kind == ss_kind_screen && (!e->monitor || !ss_init_duplication())) {
        ss_fail(L"Couldn't capture that screen.");
        return 0;
    }

    e->fps = (i32) (e->config.fps < ss_min_fps ? ss_min_fps : e->config.fps);
    ss_output_size(&e->config, e->src_w, e->src_h);
    e->bitrate = ss_bitrate();

    e->clean_bmp = ss_create_dib(&e->clean_dc, e->src_w, e->src_h, &e->clean_bits);
    e->shown_bmp = ss_create_dib(&e->shown_dc, e->src_w, e->src_h, &e->shown_bits);
    if (!e->clean_bmp || !e->shown_bmp || !ss_init_convert() || !ss_init_encoder()) {
        ss_fail(L"Couldn't start the video encoder.");
        return 0;
    }

    e->start_us = e->stats_us = ss_now_us();
    e->need_key               = 1;
    return 1;
}

static void ss_teardown(void) {
    ss_engine* e = &g_engine;
    ss_release(e->encoder);
    ss_release(e->convert);
    ss_release(e->convert_in);
    ss_release(e->convert_out);
    ss_release(e->coded);
    ss_release(e->duplication);
    ss_release(e->staging);
    ss_release(e->context);
    ss_release(e->device);
    ss_free_surfaces();
    ss_scratch_free();
}

static DWORD WINAPI ss_thread(LPVOID param) {
    Unreferenced(param);
    ss_engine* e = &g_engine;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    MFStartup(MF_VERSION, MFSTARTUP_FULL);
    timeBeginPeriod(1);

    e->started = ss_setup();
    SetEvent(e->ready);

    i64 next = ss_now_us();
    while (e->started && !e->stop) {
        ss_scratch_reset();
        ss_tick();
        next += 1000000 / e->fps;
        i64 wait = next - ss_now_us();
        if (wait > 0) {
            Sleep((DWORD) (wait / 1000));
        } else if (wait < -2000000 / e->fps) {
            next = ss_now_us();
        }
    }

    ss_teardown();
    timeEndPeriod(1);
    MFShutdown();
    CoUninitialize();
    return 0;
}

static void ss_end(void) {
    if (g_engine.thread) {
        Log_Debug("Screenshare stop");
        InterlockedExchange(&g_engine.stop, 1);
        WaitForSingleObject(g_engine.thread, ss_stop_wait);
        CloseHandle(g_engine.thread);
        CloseHandle(g_engine.ready);
        g_engine.thread = NULL;
        g_engine.ready  = NULL;
    }
    g_ss_active = 0;
    go_live_end();
}

static u8 ss_begin(const ss_config* config) {
    if (g_ss_active || g_engine.thread) {
        ss_end();
    }
    g_ss_error[0] = 0;

    memset(&g_engine, 0, sizeof g_engine);
    memset(&g_ss_stats, 0, sizeof g_ss_stats);
    g_engine.config = *config;
    g_engine.ready  = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_engine.thread = CreateThread(NULL, 0, ss_thread, NULL, 0, NULL);
    if (!g_engine.thread || !g_engine.ready) {
        ss_fail(L"Couldn't start the capture thread.");
        return 0;
    }
    WaitForSingleObject(g_engine.ready, ss_start_wait);

    u8 ok = g_engine.started && go_live_begin(g_engine.enc_w, g_engine.enc_h, g_engine.fps, g_engine.bitrate);
    if (!ok) {
        wchar_t message[ArrayCount(g_ss_error)];
        wcscpy(message, g_ss_error);
        ss_end();
        wcscpy(g_ss_error, message[0] ? message : L"Couldn't start sharing.");
        return 0;
    }

    g_ss_current = *config;
    g_ss_active  = 1;
    Log_Debug("Screenshare start: %dx%d %d fps, %u kbit/s", g_engine.enc_w, g_engine.enc_h, g_engine.fps, g_engine.bitrate / 1000);
    return 1;
}

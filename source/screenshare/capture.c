static void ss_cap_ensure(i32 w, i32 h) {
    ss_engine* e = &g_engine;
    if (e->cap_bmp && e->cap_w == w && e->cap_h == h) {
        return;
    }
    if (e->cap_bmp) {
        SelectObject(e->cap_dc, e->cap_old);
        DeleteObject(e->cap_bmp);
        e->cap_bmp = NULL;
    }
    e->cap_bmp = ss_create_dib(w, h, &e->cap_bits);
    if (e->cap_bmp) {
        e->cap_old = SelectObject(e->cap_dc, e->cap_bmp);
        e->cap_w   = w;
        e->cap_h   = h;
    } else {
        e->cap_w = e->cap_h = 0;
    }
}
static void ss_free_surfaces(void) {
    ss_engine* e = &g_engine;
    if (e->cap_bmp) {
        SelectObject(e->cap_dc, e->cap_old);
        DeleteObject(e->cap_bmp);
        e->cap_bmp = NULL;
    }
    if (e->out_bmp) {
        SelectObject(e->out_dc, e->out_old);
        DeleteObject(e->out_bmp);
        e->out_bmp = NULL;
    }
    if (e->backup_bmp) {
        SelectObject(e->backup_dc, e->backup_old);
        DeleteObject(e->backup_bmp);
        e->backup_bmp = NULL;
    }
    if (e->cap_dc) {
        DeleteDC(e->cap_dc);
        e->cap_dc = NULL;
    }
    if (e->out_dc) {
        DeleteDC(e->out_dc);
        e->out_dc = NULL;
    }
    if (e->backup_dc) {
        DeleteDC(e->backup_dc);
        e->backup_dc = NULL;
    }
    if (e->screen_dc) {
        DeleteDC(e->screen_dc);
        e->screen_dc = NULL;
    }
    e->cap_w = e->cap_h = 0;
}

static u8 ss_init_gdi(void) {
    ss_engine* e = &g_engine;
    if (e->config.kind == ss_kind_screen) {
        e->screen_dc = CreateDCW(L"DISPLAY", NULL, NULL, NULL);
        if (!e->screen_dc) {
            return 0;
        }
        ss_cap_ensure(e->capture_rect.right - e->capture_rect.left, e->capture_rect.bottom - e->capture_rect.top);
    } else {
        if (!GetWindowRect(e->config.window, &e->capture_rect)) {
            return 0;
        }
        ss_cap_ensure(e->capture_rect.right - e->capture_rect.left, e->capture_rect.bottom - e->capture_rect.top);
    }
    return e->cap_bmp != NULL;
}

static u8 ss_capture_gdi(void) {
    ss_engine* e = &g_engine;
    if (e->config.kind == ss_kind_application) {
        RECT rect;
        if (!GetWindowRect(e->config.window, &rect) || IsIconic(e->config.window)) {
            return 0;
        }
        e->capture_rect = rect;
        ss_cap_ensure(rect.right - rect.left, rect.bottom - rect.top);
        if (!e->cap_bmp) {
            return 0;
        }
        // PW_RENDERFULLCONTENT, so GPU-drawn windows aren't black
        return PrintWindow(e->config.window, e->cap_dc, 2) != 0;
    }
    if (!e->screen_dc || !e->cap_bmp) {
        return 0;
    }
    return BitBlt(e->cap_dc, 0, 0, e->cap_w, e->cap_h, e->screen_dc, e->capture_rect.left, e->capture_rect.top,
                  SRCCOPY | CAPTUREBLT) != 0;
}

static void ss_free_dxgi(void) {
    ss_engine* e = &g_engine;
    ss_release(e->duplication);
    ss_release(e->staging);
    ss_release(e->d3d_context);
    ss_release(e->d3d_device);
    e->staging_w = e->staging_h = 0;
    e->use_dxgi                 = 0;
}

static u8 ss_init_dxgi(void) {
    ss_engine* e = &g_engine;
    ss_free_dxgi();

    // The monitor can hang off any adapter (laptops with an integrated and a discrete GPU), and
    // duplication has to use the device that owns the output
    IDXGIFactory1* factory = NULL;
    if (FAILED(CreateDXGIFactory1(&IID_IDXGIFactory1, (void**) &factory))) {
        return 0;
    }

    IDXGIAdapter1* adapter = NULL;
    IDXGIOutput*   output  = NULL;
    for (UINT a = 0; !output && IDXGIFactory1_EnumAdapters1(factory, a, &adapter) != DXGI_ERROR_NOT_FOUND; ++a) {
        IDXGIOutput* candidate = NULL;
        for (UINT o = 0; IDXGIAdapter1_EnumOutputs(adapter, o, &candidate) != DXGI_ERROR_NOT_FOUND; ++o) {
            DXGI_OUTPUT_DESC desc;
            IDXGIOutput_GetDesc(candidate, &desc);
            if (desc.Monitor == e->monitor) {
                output = candidate;
                break;
            }
            ss_release(candidate);
        }
        if (!output) {
            ss_release(adapter);
        }
    }
    ss_release(factory);
    if (!output || !adapter) {
        ss_release(output);
        ss_release(adapter);
        return 0;
    }

    D3D_FEATURE_LEVEL level;
    HRESULT           hr = D3D11CreateDevice((IDXGIAdapter*) adapter, D3D_DRIVER_TYPE_UNKNOWN, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                                             NULL, 0, D3D11_SDK_VERSION, &e->d3d_device, &level, &e->d3d_context);
    ss_release(adapter);
    if (FAILED(hr)) {
        ss_release(output);
        ss_free_dxgi();
        return 0;
    }

    IDXGIOutput1* output1 = NULL;
    hr                    = IDXGIOutput_QueryInterface(output, &IID_IDXGIOutput1, (void**) &output1);
    ss_release(output);
    if (FAILED(hr)) {
        ss_free_dxgi();
        return 0;
    }
    hr = IDXGIOutput1_DuplicateOutput(output1, (IUnknown*) e->d3d_device, &e->duplication);
    ss_release(output1);
    if (FAILED(hr)) {
        ss_free_dxgi();
        return 0;
    }
    return 1;
}

static u8 ss_capture_dxgi(UINT timeout_ms) {
    ss_engine*              e        = &g_engine;
    DXGI_OUTDUPL_FRAME_INFO info     = { 0 };
    IDXGIResource*          resource = NULL;
    HRESULT                 hr       = IDXGIOutputDuplication_AcquireNextFrame(e->duplication, timeout_ms, &info, &resource);
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
        return 0;
    }
    if (hr == DXGI_ERROR_ACCESS_LOST) {
        // A mode change, the secure desktop (UAC) or the lock screen invalidates the duplication. Rebuild it,
        // and carry on with plain GDI capture if that isn't possible right now
        if (ss_init_dxgi()) {
            e->use_dxgi = 1;
        } else if (ss_init_gdi()) {
            e->use_gdi = 1;
        }
        return 0;
    }
    if (FAILED(hr)) {
        return 0;
    }

    ID3D11Texture2D* texture = NULL;
    hr                       = IDXGIResource_QueryInterface(resource, &IID_ID3D11Texture2D, (void**) &texture);
    ss_release(resource);
    if (FAILED(hr)) {
        IDXGIOutputDuplication_ReleaseFrame(e->duplication);
        return 0;
    }

    D3D11_TEXTURE2D_DESC desc;
    ID3D11Texture2D_GetDesc(texture, &desc);
    if (!e->staging || e->staging_w != desc.Width || e->staging_h != desc.Height) {
        D3D11_TEXTURE2D_DESC staging_desc = desc;
        staging_desc.Usage                = D3D11_USAGE_STAGING;
        staging_desc.BindFlags            = 0;
        staging_desc.CPUAccessFlags       = D3D11_CPU_ACCESS_READ;
        staging_desc.MiscFlags            = 0;
        ss_release(e->staging);
        if (FAILED(ID3D11Device_CreateTexture2D(e->d3d_device, &staging_desc, NULL, &e->staging))) {
            ss_release(texture);
            IDXGIOutputDuplication_ReleaseFrame(e->duplication);
            return 0;
        }
        e->staging_w = desc.Width;
        e->staging_h = desc.Height;
    }

    ID3D11DeviceContext_CopyResource(e->d3d_context, (ID3D11Resource*) e->staging, (ID3D11Resource*) texture);
    ss_release(texture);
    IDXGIOutputDuplication_ReleaseFrame(e->duplication);

    D3D11_MAPPED_SUBRESOURCE mapped;
    if (FAILED(ID3D11DeviceContext_Map(e->d3d_context, (ID3D11Resource*) e->staging, 0, D3D11_MAP_READ, 0, &mapped))) {
        return 0;
    }
    ss_cap_ensure((i32) desc.Width, (i32) desc.Height);
    if (e->cap_bmp) {
        for (UINT y = 0; y < desc.Height; ++y) {
            memcpy(e->cap_bits + (size_t) y * desc.Width * 4, (const u8*) mapped.pData + (size_t) y * mapped.RowPitch,
                   (size_t) desc.Width * 4);
        }
    }
    ID3D11DeviceContext_Unmap(e->d3d_context, (ID3D11Resource*) e->staging, 0);
    return e->cap_bmp != NULL;
}

// Neither capture path includes the mouse pointer, so it is drawn on afterwards. It goes onto the capture surface
// for the scaling step and is taken off again, so a static screen can be reused without a trail of cursors
static void ss_cache_cursor(HCURSOR cursor) {
    ss_engine* e     = &g_engine;
    e->cursor_handle = cursor;
    e->cursor_hot_x = e->cursor_hot_y = 0;
    e->cursor_w = e->cursor_h = 32;

    ICONINFO info = { 0 };
    if (!GetIconInfo(cursor, &info)) {
        return;
    }
    e->cursor_hot_x = (i32) info.xHotspot;
    e->cursor_hot_y = (i32) info.yHotspot;
    BITMAP bm       = { 0 };
    if (info.hbmColor && GetObjectW(info.hbmColor, sizeof bm, &bm) && bm.bmWidth > 0 && bm.bmHeight > 0) {
        e->cursor_w = bm.bmWidth;
        e->cursor_h = bm.bmHeight;
    } else if (info.hbmMask && GetObjectW(info.hbmMask, sizeof bm, &bm) && bm.bmWidth > 0) {
        // Monochrome cursors keep the AND and XOR masks stacked in one bitmap
        e->cursor_w = bm.bmWidth;
        e->cursor_h = bm.bmHeight / 2;
    }
    if (info.hbmColor) {
        DeleteObject(info.hbmColor);
    }
    if (info.hbmMask) {
        DeleteObject(info.hbmMask);
    }
    if (e->cursor_w > 256 || e->cursor_h > 256 || e->cursor_w <= 0 || e->cursor_h <= 0) {
        e->cursor_w = e->cursor_h = 32;
    }
}

static void ss_scale_to_out(void) {
    ss_engine* e = &g_engine;
    if (e->cap_w == e->enc_w && e->cap_h == e->enc_h) {
        BitBlt(e->out_dc, 0, 0, e->enc_w, e->enc_h, e->cap_dc, 0, 0, SRCCOPY);
        return;
    }

    i32 fit_w = e->enc_w;
    i32 fit_h = (i32) ((i64) e->cap_h * e->enc_w / e->cap_w);
    if (fit_h > e->enc_h) {
        fit_h = e->enc_h;
        fit_w = (i32) ((i64) e->cap_w * e->enc_h / e->cap_h);
    }
    if (fit_w < 2) {
        fit_w = 2;
    }
    if (fit_h < 2) {
        fit_h = 2;
    }
    if (fit_w != e->enc_w || fit_h != e->enc_h) {
        PatBlt(e->out_dc, 0, 0, e->enc_w, e->enc_h, BLACKNESS);
    }
    SetStretchBltMode(e->out_dc, HALFTONE);
    SetBrushOrgEx(e->out_dc, 0, 0, NULL);
    StretchBlt(e->out_dc, (e->enc_w - fit_w) / 2, (e->enc_h - fit_h) / 2, fit_w, fit_h, e->cap_dc, 0, 0, e->cap_w, e->cap_h, SRCCOPY);
}

static u32 ss_clock_ticks(void) {
    ss_engine*    e = &g_engine;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (u32) ((u64) (now.QuadPart - e->clock_start.QuadPart) * 90000 / (u64) e->clock_freq.QuadPart);
}

static void ss_emit(void) {
    ss_engine* e = &g_engine;
    for (i32 i = 0; i < e->queue_count; ++i) {
        ss_bytes* frame = &e->queue[i];
        u32       ts    = e->ts_count > 0 ? e->ts_queue[0] : e->last_ts;
        if (e->ts_count > 0) {
            memmove(&e->ts_queue[0], &e->ts_queue[1], (size_t) (e->ts_count - 1) * sizeof e->ts_queue[0]);
            --e->ts_count;
        }
        u8 key = ss_has_nal(frame->data, frame->size, 5);
        if (key) {
            e->key_owed = 0;
        }
        stream_send_frame(frame->data, frame->size, ts);
        ++e->frame_counter;
        ++e->stats_frames;
        e->stats_bytes += frame->size;
        ss_bytes_free(frame);
    }
    e->queue_count = 0;
}

static void ss_tick(void) {
    ss_engine*    e          = &g_engine;
    u64           tick_start = ss_now_ms();
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);

    u8 new_frame = 0;
    if (e->use_dxgi) {
        new_frame = ss_capture_dxgi(e->have_frame ? 0 : 100);
    } else if (e->use_gdi) {
        new_frame = ss_capture_gdi();
    }
    if (new_frame) {
        e->have_frame = 1;
        e->nv12_valid = 0;
    }
    if (!e->have_frame) {
        return;
    }

    CURSORINFO cursor      = { 0 };
    cursor.cbSize          = sizeof cursor;
    u8      cursor_visible = GetCursorInfo(&cursor) && (cursor.flags & CURSOR_SHOWING) && cursor.hCursor;
    i32     cursor_x       = cursor_visible ? cursor.ptScreenPos.x : -1;
    i32     cursor_y       = cursor_visible ? cursor.ptScreenPos.y : -1;
    HCURSOR cursor_handle  = cursor_visible ? cursor.hCursor : NULL;
    u8      cursor_changed = cursor_x != e->last_cursor_x || cursor_y != e->last_cursor_y || cursor_handle != e->last_cursor_handle;

    if (!e->nv12_valid || cursor_changed) {
        u8  drawn    = 0;
        i32 backup_x = 0, backup_y = 0, backup_w = 0, backup_h = 0;
        if (cursor_visible) {
            if (cursor.hCursor != e->cursor_handle) {
                ss_cache_cursor(cursor.hCursor);
            }
            i32 x    = cursor.ptScreenPos.x - e->capture_rect.left - e->cursor_hot_x;
            i32 y    = cursor.ptScreenPos.y - e->capture_rect.top - e->cursor_hot_y;
            backup_x = x < 0 ? 0 : x;
            backup_y = y < 0 ? 0 : y;
            backup_w = x + e->cursor_w > e->cap_w ? e->cap_w - backup_x : x + e->cursor_w - backup_x;
            backup_h = y + e->cursor_h > e->cap_h ? e->cap_h - backup_y : y + e->cursor_h - backup_y;
            if (backup_w > 0 && backup_h > 0 && backup_w <= 256 && backup_h <= 256) {
                BitBlt(e->backup_dc, 0, 0, backup_w, backup_h, e->cap_dc, backup_x, backup_y, SRCCOPY);
                DrawIconEx(e->cap_dc, x, y, cursor.hCursor, e->cursor_w, e->cursor_h, 0, NULL, DI_NORMAL);
                drawn = 1;
            }
        }
        ss_scale_to_out();
        if (drawn) {
            BitBlt(e->cap_dc, backup_x, backup_y, backup_w, backup_h, e->backup_dc, 0, 0, SRCCOPY);
        }
        GdiFlush();
        ss_bgra_to_nv12(e->out_bits, e->enc_w, e->enc_h, e->nv12.data);
        e->nv12.size          = (u32) ((size_t) e->enc_w * e->enc_h * 3 / 2);
        e->nv12_valid         = 1;
        e->last_cursor_x      = cursor_x;
        e->last_cursor_y      = cursor_y;
        e->last_cursor_handle = cursor_handle;
    }

    u32 capture_ts = ss_clock_ticks();
    if (e->last_ts != 0 && capture_ts <= e->last_ts) {
        capture_ts = e->last_ts + 1;
    }
    e->last_ts = capture_ts;
    if (e->ts_count == ss_queue_max) {
        memmove(&e->ts_queue[0], &e->ts_queue[1], (ss_queue_max - 1) * sizeof e->ts_queue[0]);
        --e->ts_count;
    }
    e->ts_queue[e->ts_count++] = capture_ts;

    // A keyframe on request and every two seconds. If one was asked for and hasn't come out yet (encoders hold
    // back their first frames), ask again only after a short wait instead of on every tick
    u32 tick      = e->tick_index++;
    u8  key_frame = InterlockedExchange(&e->need_key, 0) != 0 || tick % (u32) (e->fps * 2) == 0 ||
                    (e->key_owed && tick - e->key_owed_tick > (u32) e->fps / 3);
    if (key_frame) {
        e->key_owed      = 1;
        e->key_owed_tick = tick;
    }
    ss_encode_nv12(&e->nv12, key_frame);

    if (e->queue_count == 0) {
        if (e->hardware && ++e->empty_frames >= e->fps * 3 / 2) {
            if (!ss_fall_back()) {
                e->stop = 1;
            }
        }
    } else {
        e->empty_frames = 0;
        ss_emit();
    }

    QueryPerformanceCounter(&t1);
    e->stats_work_ms += (double) (t1.QuadPart - t0.QuadPart) * 1000.0 / (double) e->clock_freq.QuadPart;
    ++e->stats_ticks;
    if (e->stats_start_ms == 0) {
        e->stats_start_ms = tick_start;
    }
    u64 elapsed = ss_now_ms() - e->stats_start_ms;
    if (elapsed >= 1000) {
        double seconds     = (double) elapsed / 1000.0;
        g_ss_stats.fps     = e->stats_frames / seconds;
        g_ss_stats.kbps    = (double) e->stats_bytes * 8.0 / seconds / 1000.0;
        g_ss_stats.work_ms = e->stats_ticks ? e->stats_work_ms / e->stats_ticks : 0.0;
        e->stats_frames    = 0;
        e->stats_bytes     = 0;
        e->stats_work_ms   = 0.0;
        e->stats_ticks     = 0;
        e->stats_start_ms  = ss_now_ms();
    }
}

static u8 ss_setup(void) {
    ss_engine* e = &g_engine;

    i32 src_w, src_h;
    if (e->config.kind == ss_kind_screen) {
        e->capture_rect = e->config.screen;
        e->monitor      = MonitorFromRect(&e->capture_rect, MONITOR_DEFAULTTONULL);
    } else {
        if (!e->config.window || !IsWindow(e->config.window) || !GetWindowRect(e->config.window, &e->capture_rect)) {
            ss_fail(L"That window is no longer available.");
            return 0;
        }
        if (IsIconic(e->config.window)) {
            ss_fail(L"That window is minimized. Restore it and try again.");
            return 0;
        }
    }
    src_w = e->capture_rect.right - e->capture_rect.left;
    src_h = e->capture_rect.bottom - e->capture_rect.top;
    if (src_w <= 0 || src_h <= 0) {
        ss_fail(L"Couldn't read the size of that source.");
        return 0;
    }

    e->cap_dc    = CreateCompatibleDC(NULL);
    e->out_dc    = CreateCompatibleDC(NULL);
    e->backup_dc = CreateCompatibleDC(NULL);
    if (!e->cap_dc || !e->out_dc || !e->backup_dc) {
        ss_fail(L"Couldn't start capturing that source.");
        return 0;
    }
    e->backup_bmp = ss_create_dib(256, 256, NULL);
    if (!e->backup_bmp) {
        ss_fail(L"Couldn't start capturing that source.");
        return 0;
    }
    e->backup_old = SelectObject(e->backup_dc, e->backup_bmp);

    if (e->config.kind == ss_kind_screen && e->monitor && ss_init_dxgi()) {
        e->use_dxgi = 1;
    } else if (ss_init_gdi()) {
        e->use_gdi = 1;
    } else {
        ss_fail(L"Couldn't start capturing that source.");
        return 0;
    }

    e->fps = (i32) (e->config.fps < 5 ? 5 : e->config.fps);
    ss_output_size(&e->config, src_w, src_h, &e->enc_w, &e->enc_h);
    e->bitrate     = ss_bitrate(e->enc_w, e->enc_h, e->fps, e->config.quality);
    e->interval_ms = 1000 / e->fps;

    e->out_bmp = ss_create_dib(e->enc_w, e->enc_h, &e->out_bits);
    if (!e->out_bmp) {
        ss_fail(L"Couldn't allocate the output frame.");
        return 0;
    }
    e->out_old = SelectObject(e->out_dc, e->out_bmp);
    if (!ss_bytes_reserve(&e->nv12, (u32) ((size_t) e->enc_w * e->enc_h * 3 / 2))) {
        ss_fail(L"Out of memory.");
        return 0;
    }

    if (!ss_init_encoder(e->config.hardware)) {
        ss_fail(L"Couldn't start the H.264 encoder.");
        return 0;
    }

    QueryPerformanceFrequency(&e->clock_freq);
    QueryPerformanceCounter(&e->clock_start);
    e->last_ts       = 0;
    e->ts_count      = 0;
    e->frame_counter = 0;
    e->tick_index    = 0;
    e->key_owed      = 0;
    e->need_key      = 1;
    e->have_frame    = 0;
    e->nv12_valid    = 0;
    e->last_cursor_x = e->last_cursor_y = -1;
    e->last_cursor_handle               = NULL;
    e->cursor_handle                    = NULL;
    e->stats_start_ms                   = 0;
    return 1;
}

static void ss_teardown(void) {
    ss_engine* e = &g_engine;
    ss_free_encoder();
    ss_free_dxgi();
    ss_free_surfaces();
    ss_bytes_free(&e->nv12);
    ss_bytes_free(&e->sps_pps);
}

static DWORD WINAPI ss_thread(LPVOID param) {
    Unreferenced(param);
    ss_engine* e = &g_engine;

    // Media Foundation needs COM on the thread that uses it
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    MFStartup(MF_VERSION, MFSTARTUP_FULL);
    timeBeginPeriod(1);

    e->started = ss_setup();
    SetEvent(e->ready);

    if (e->started) {
        LARGE_INTEGER freq, next, now;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&next);
        i64 interval = freq.QuadPart / e->fps;

        while (!e->stop) {
            ss_tick();
            next.QuadPart += interval;
            QueryPerformanceCounter(&now);
            i64 wait_ms = (next.QuadPart - now.QuadPart) * 1000 / freq.QuadPart;
            if (wait_ms > 0) {
                Sleep((DWORD) wait_ms);
            } else if (wait_ms < -(i64) e->interval_ms * 2) {
                next = now;
            }
        }
    }

    ss_teardown();
    timeEndPeriod(1);
    MFShutdown();
    CoUninitialize();
    return 0;
}

static void ss_request_key(void) {
    InterlockedExchange(&g_engine.need_key, 1);
}

static void ss_end(void) {
    if (g_engine.thread) {
        Log_Debug("Screenshare stop");
        InterlockedExchange(&g_engine.stop, 1);
        WaitForSingleObject(g_engine.thread, 5000);
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

    if (config->kind != ss_kind_application && config->kind != ss_kind_screen) {
        ss_fail(L"Cameras can't be shared yet.");
        return 0;
    }

    memset(&g_engine, 0, sizeof g_engine);
    memset(&g_ss_stats, 0, sizeof g_ss_stats);
    g_engine.config = *config;
    g_engine.ready  = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_engine.thread = CreateThread(NULL, 0, ss_thread, NULL, 0, NULL);
    if (!g_engine.thread || !g_engine.ready) {
        ss_fail(L"Couldn't start the capture thread.");
        return 0;
    }
    WaitForSingleObject(g_engine.ready, 10000);

    if (!g_engine.started) {
        WaitForSingleObject(g_engine.thread, 5000);
        CloseHandle(g_engine.thread);
        CloseHandle(g_engine.ready);
        g_engine.thread = NULL;
        g_engine.ready  = NULL;
        if (!g_ss_error[0]) {
            ss_fail(L"Couldn't start sharing.");
        }
        return 0;
    }

    if (!go_live_begin(g_engine.enc_w, g_engine.enc_h, g_engine.fps, g_engine.bitrate)) {
        wchar_t message[ArrayCount(g_ss_error)];
        wcscpy(message, g_ss_error);
        ss_end();
        wcscpy(g_ss_error, message);
        return 0;
    }

    g_ss_current = *config;
    g_ss_active  = 1;

    // NOTE(Xelph): I log UTF-8 here because %ls stops at the first character the C locale can't convert, like an em dash in a title
    char name[512];
    WideCharToMultiByte(CP_UTF8, 0, config->name, -1, name, sizeof name, NULL, NULL);
    char encoder[256];
    WideCharToMultiByte(CP_UTF8, 0, g_ss_stats.encoder, -1, encoder, sizeof encoder, NULL, NULL);
    Log_Debug("Screenshare start: \"%s\" %dx%d %d fps, %u kbit/s, encoder: %s", name, g_engine.enc_w, g_engine.enc_h, g_engine.fps,
              g_engine.bitrate / 1000, encoder);
    return 1;
}

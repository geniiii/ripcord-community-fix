#define ss_queue_max 16

static ss_settings g_ss_settings = { .height = 720, .fps = 60, .fps_mode = 1, .quality = 1, .hardware = 1 };
static ss_config   g_ss_current;
static u8          g_ss_active;
static wchar_t     g_ss_error[160];
static ss_stats    g_ss_stats;

typedef struct {
    ss_config config;
    HMONITOR  monitor;
    RECT      capture_rect;
    i32       enc_w;
    i32       enc_h;
    i32       fps;
    i32       interval_ms;
    u32       bitrate;

    HANDLE        thread;
    HANDLE        ready;
    volatile LONG stop;
    volatile LONG need_key;
    u8            started;

    u8      use_dxgi;
    u8      use_gdi;
    HDC     screen_dc;
    HDC     cap_dc;
    HDC     out_dc;
    HDC     backup_dc;
    HBITMAP cap_bmp;
    HBITMAP out_bmp;
    HBITMAP backup_bmp;
    HGDIOBJ cap_old;
    HGDIOBJ out_old;
    HGDIOBJ backup_old;
    u8*     cap_bits;
    u8*     out_bits;
    i32     cap_w;
    i32     cap_h;

    ID3D11Device*           d3d_device;
    ID3D11DeviceContext*    d3d_context;
    IDXGIOutputDuplication* duplication;
    ID3D11Texture2D*        staging;
    UINT                    staging_w;
    UINT                    staging_h;

    HCURSOR cursor_handle;
    i32     cursor_hot_x;
    i32     cursor_hot_y;
    i32     cursor_w;
    i32     cursor_h;
    i32     last_cursor_x;
    i32     last_cursor_y;
    HCURSOR last_cursor_handle;

    u8       have_frame;
    ss_bytes nv12;
    u8       nv12_valid;

    IMFTransform*           mf;
    IMFActivate*            activate;
    IMFMediaEventGenerator* events;
    u8                      hardware;
    u8                      async;
    i32                     need_input;
    i32                     empty_frames;
    ss_bytes                sps_pps;
    u64                     mf_timestamp;
    ss_bytes                queue[ss_queue_max];
    i32                     queue_count;

    LARGE_INTEGER clock_start;
    LARGE_INTEGER clock_freq;
    u32           last_ts;
    u32           ts_queue[ss_queue_max];
    i32           ts_count;
    u32           frame_counter;
    u32           tick_index;
    u8            key_owed;
    u32           key_owed_tick;

    u32    stats_frames;
    u64    stats_bytes;
    double stats_work_ms;
    u32    stats_ticks;
    u64    stats_start_ms;
} ss_engine;

static ss_engine g_engine;

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

static u64 ss_now_ms(void) {
    return GetTickCount64();
}

static u64 ss_pack_pair(u32 high, u32 low) {
    return ((u64) high << 32) | low;
}

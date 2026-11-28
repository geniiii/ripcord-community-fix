#define ss_control_class L"RCFScreenshareControl"
#define ss_picker_class  L"RCFScreenSharePicker"
#define wm_ss_loaded     (WM_APP + 10)
#define wm_ss_state      (WM_APP + 11)

#define ss_thumb_w       400
#define ss_thumb_h       225

#ifndef CAPTUREBLT
#define CAPTUREBLT 0x40000000
#endif

enum {
    ss_kind_none,
    ss_kind_application,
    ss_kind_screen,
    ss_kind_device,
};

typedef struct {
    u32     kind;
    HWND    window;
    RECT    screen;
    wchar_t name[160];
    wchar_t device_id[260];
    // Output height in pixels (480, 720, 1080, 1440). The width follows the source's aspect ratio
    u32 height;
    u32 fps;
    // 0 low, 1 balanced, 2 high: scales the bitrate
    u32 quality;
    u8  hardware;
} ss_config;

typedef struct {
    u32 height;
    u32 fps;
    // 0 = 30, 1 = 60, 2 = custom (typed)
    u32 fps_mode;
    u32 quality;
    u8  hardware;
} ss_settings;

typedef struct {
    u32     kind;
    HWND    window;
    RECT    screen;
    wchar_t name[160];
    wchar_t device_id[260];
    HBITMAP thumb;
    HICON   icon;
} ss_source;

typedef struct {
    ss_source* items;
    u32        count;
    u32        capacity;
    u32        kind;
    u32        generation;
} ss_source_list;

typedef struct {
    HWND notify;
    u32  kind;
    u32  generation;
} ss_load_job;

typedef struct {
    double  fps;
    double  kbps;
    double  work_ms;
    u8      hardware;
    wchar_t encoder[128];
} ss_stats;

static void stream_send_frame(const u8* data, u32 size, u32 rtp_timestamp);
static u8   go_live_begin(i32 width, i32 height, i32 fps, u32 bitrate);
static void go_live_end(void);
static void audio_start(void);
static void audio_stop(void);

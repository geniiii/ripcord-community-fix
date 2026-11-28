#define ss_scratch_size (32u << 20)

enum {
    ss_kind_none,
    ss_kind_application,
    ss_kind_screen,
};

typedef struct {
    u32     kind;
    HWND    window;
    RECT    screen;
    wchar_t name[160];
    u32     height;
    u32     fps;

    // NOTE(Xelph): 0 low, 1 balanced, 2 high. Only scales the bitrate
    u32 quality;
} ss_config;

typedef struct {
    double fps;
    double kbps;
} ss_stats;

typedef struct {
    u8* base;
    u64 pos;
} ss_arena;

#define WriteU16BE(a, v) ((a)[0] = (u8) ((v) >> 8), (a)[1] = (u8) (v))
#define WriteU32BE(a, v) ((a)[0] = (u8) ((v) >> 24), (a)[1] = (u8) ((v) >> 16), (a)[2] = (u8) ((v) >> 8), (a)[3] = (u8) (v))

void        ss_ui_init(void);
static u8   go_live_begin(i32 width, i32 height, i32 fps, u32 bitrate);
static void go_live_end(void);
static void stream_send_frame(const u8* data, u32 size, u32 rtp_timestamp);
static void audio_start(void);
static void audio_stop(void);

// NOTE(Xelph): Everything temporary on a thread (an encoded frame, a DAVE ciphertext, a NAL list) goes into that thread's
//              scratch arena, which the capture loop resets once per tick
static __declspec(thread) ss_arena t_scratch;

static void* ss_scratch_push(u64 size) {
    if (!t_scratch.base) {
        t_scratch.base = (u8*) VirtualAlloc(NULL, ss_scratch_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    size = (size + 15) & ~15ull;
    if (!t_scratch.base || t_scratch.pos + size > ss_scratch_size) {
        return NULL;
    }
    void* result = t_scratch.base + t_scratch.pos;
    t_scratch.pos += size;
    return result;
}

static void ss_scratch_reset(void) {
    t_scratch.pos = 0;
}

static void ss_scratch_free(void) {
    if (t_scratch.base) {
        VirtualFree(t_scratch.base, 0, MEM_RELEASE);
    }
    t_scratch = (ss_arena){ 0 };
}

// NOTE(Xelph): One clock for everything: capture timestamps, pacing, retransmit windows, audio gaps and the Go Live timeout.
//              QPC is the only one with sub-millisecond resolution, which pacing needs
static i64 ss_now_us(void) {
    static i64 frequency;
    if (!frequency) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        frequency = f.QuadPart;
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return now.QuadPart / frequency * 1000000 + now.QuadPart % frequency * 1000000 / frequency;
}

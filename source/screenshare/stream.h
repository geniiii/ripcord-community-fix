#define stream_pt_video    101
#define stream_pt_rtx      102
#define stream_pt_audio    120
#define stream_max_payload 1100
#define stream_history     1024
#define stream_queue_max   4096
#define stream_max_users   64
#define stream_packet_max  2048

typedef enum {
    stream_state_idle,
    stream_state_requesting,
    stream_state_connecting,
    stream_state_live,
    stream_state_failed,
} stream_state;

typedef struct {
    u16 sequence;
    u32 timestamp;
    u8  marker;
    u32 size;
    u8* payload;
} stream_history_entry;

typedef struct {
    u32 size;
    u8* data;
} stream_datagram;

typedef struct {
    const char* host;
    u16         port;
    u8          secure;
    const char* server_id;
    const char* user_id;
    const char* session_id;
    const char* token;
    i32         width;
    i32         height;
    i32         fps;
    u32         bitrate;
} stream_connect_info;

typedef struct {
    char host[160];
    u16  port;
    u8   secure;
    char server_id[40];
    char user_id[40];
    char session_id[96];
    char token[320];
    u64  server_id_num;
    i32  width;
    i32  height;
    i32  fps;
    u32  bitrate;

    HINTERNET h_session;
    HINTERNET h_connect;
    HINTERNET h_ws;
    SOCKET    sock;

    HANDLE connect_thread;
    HANDLE udp_thread;
    HANDLE heartbeat_thread;
    HANDLE sender_thread;
    HANDLE stop_event;
    HANDLE ready_event;

    volatile LONG stop;
    volatile LONG ready;
    volatile LONG nonce;
    volatile LONG last_seq;
    i32           heartbeat_ms;

    u32  ssrc;
    u32  video_ssrc;
    u32  rtx_ssrc;
    char media_ip[64];
    u16  media_port;
    char video_rid[16];
    i32  video_quality;

    u8                key[32];
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_KEY_HANDLE bkey;

    u8                   use_dave;
    u16                  dave_version;
    DAVESessionHandle    session;
    DAVEEncryptorHandle  encryptor;
    DAVEKeyRatchetHandle ratchet;
    char                 users[stream_max_users][24];
    u32                  user_count;
    i64                  pending_downgrade_tid;

    u16                  video_sequence;
    u16                  rtx_sequence;
    stream_history_entry history[stream_history];
    stream_datagram      queue[stream_queue_max];
    u32                  queue_head;
    u32                  queue_count;
    u64                  queue_bytes;
    double               tokens;
    i64                  pacing_last_us;
    i64                  rtx_window_start_us;
    u32                  rtx_window_bytes;
    u8                   packet[stream_packet_max];
    ss_bytes             dave_out;
} stream_conn;

static stream_conn g_stream;
static CRITICAL_SECTION g_stream_ws_lock;
static CRITICAL_SECTION g_stream_send_lock;
static CRITICAL_SECTION g_stream_dave_lock;
static u8               g_stream_locks_ready;
static u8               g_stream_used;
static stream_state g_stream_state;
static wchar_t      g_stream_text[120];

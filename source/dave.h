#include "ext/libdave/cpp/includes/dave/dave.h"

#define DAVE_MAX_DECRYPTORS 256
#define DAVE_MAX_SSRC_MAP   256
#define DAVE_MAX_USERS      256
#define DAVE_MAGIC_BYTES    0xFAFA

enum {
    DAVE_MLS_EXTERNAL_SENDER = 25,
    DAVE_MLS_KEY_PACKAGE     = 26,
    DAVE_MLS_PROPOSALS       = 27,
    DAVE_MLS_COMMIT_WELCOME  = 28,
    DAVE_MLS_ANNOUNCE_COMMIT = 29,
    DAVE_MLS_WELCOME         = 30,
    DAVE_MLS_INVALID_COMMIT  = 31,
};

typedef struct {
    void* decryptor;
    u32   ssrc;
    u64   userId;
} DaveDecryptorEntry;

typedef struct {
    u32 ssrc;
    u64 userId;
} DaveSsrcMapEntry;

typedef struct {
    void*              session;
    void*              encryptor;
    DaveDecryptorEntry decryptors[DAVE_MAX_DECRYPTORS];
    u32                decryptor_count;
    DaveSsrcMapEntry   ssrc_map[DAVE_MAX_SSRC_MAP];
    u32                ssrc_map_count;
    u64                connected_user_ids[DAVE_MAX_USERS];
    u32                connected_user_count;
    u16                protocol_version;
    u16                pending_protocol_version;
    i32                pending_transition_id;
    u8                 dave_enabled;
    u8                 dave_downgraded;
    u8                 pending_transition_ready;
    u8                 pending_transition_executed;
    u32                local_ssrc;
    u64                channel_id;
    u64                user_id;
    void*              webSocket;
    i32                last_seq;
} DaveState;

global CRITICAL_SECTION g_dave_lock;
#define DAVE_LOCK()   EnterCriticalSection(&g_dave_lock)
#define DAVE_UNLOCK() LeaveCriticalSection(&g_dave_lock)

#pragma pack(push, 1)
typedef struct {
    u8 flags;
    u8 seq;
    u8 opcode;
} DaveBinaryHeader;
#pragma pack(pop)

typedef struct {
    i32   m_ref;
    i32   _pad;
    void* m_impl;
    void* user_data;
} DaveBinarySlotObject;

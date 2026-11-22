#include "ext/libdave/cpp/includes/dave/dave.h"

#define DAVE_MAX_USERS 256

typedef struct {
    u32                 ssrc;
    u64                 userId;
    DAVEDecryptorHandle decryptor;
} DaveSsrc;

typedef struct {
    DAVESessionHandle   session;
    DAVEEncryptorHandle encryptor;
    DaveSsrc            ssrcs[DAVE_MAX_USERS];
    u32                 ssrc_count;
    u64                 recognized_user_ids[DAVE_MAX_USERS];
    u32                 recognized_user_count;
    u16                 pending_protocol_version;
    u16                 pending_transition_id;
    u8                  dave_enabled;
    u64                 channel_id;
    u64                 user_id;
    void*               webSocket;
    i32                 last_seq;
} DaveState;

typedef struct {
    char        bufs[DAVE_MAX_USERS + 1][32];
    const char* ptrs[DAVE_MAX_USERS + 1];
    u32         count;
} DaveRecognizedUsers;

typedef struct {
    u8 seq[2];
    u8 opcode;
} DaveBinaryHeader;
static_assert(sizeof(DaveBinaryHeader) == 3);

typedef struct {
    i32   m_ref;
    void* m_impl;
} DaveBinarySlotObject;

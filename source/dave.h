#define DAVE_MAX_DECRYPTORS   256
#define DAVE_MAX_SSRC_MAP     256
#define DAVE_MAX_USERS        256
#define DAVE_MEDIA_TYPE_AUDIO 0
#define DAVE_CODEC_OPUS       1

#define DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS 0
#define DAVE_DECRYPTOR_RESULT_CODE_SUCCESS 0

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
    u32                local_ssrc;
    u64                channel_id;
    u64                user_id;
    void*              webSocket;
    i32                last_seq;
} DaveState;

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

typedef void* DAVESessionHandle;
typedef void* DAVECommitResultHandle;
typedef void* DAVEWelcomeResultHandle;
typedef void* DAVEKeyRatchetHandle;
typedef void* DAVEEncryptorHandle;
typedef void* DAVEDecryptorHandle;

typedef void (*DAVEMLSFailureCallback)(const char* source, const char* reason, void* userData);

extern DAVESessionHandle       daveSessionCreate(void* context, const char* authSessionId, DAVEMLSFailureCallback callback, void* userData);
extern void                    daveSessionDestroy(DAVESessionHandle session);
extern void                    daveSessionInit(DAVESessionHandle session, u16 version, u64 groupId, const char* selfUserId);
extern void                    daveSessionReset(DAVESessionHandle session);
extern void                    daveSessionSetExternalSender(DAVESessionHandle session, const u8* data, size_t length);
extern void                    daveSessionProcessProposals(DAVESessionHandle session, const u8* proposals, size_t length, const char** recognizedUserIds, size_t recognizedUserIdsLength, u8** commitWelcomeBytes, size_t* commitWelcomeBytesLength);
extern DAVECommitResultHandle  daveSessionProcessCommit(DAVESessionHandle session, const u8* commit, size_t length);
extern DAVEWelcomeResultHandle daveSessionProcessWelcome(DAVESessionHandle session, const u8* welcome, size_t length, const char** recognizedUserIds, size_t recognizedUserIdsLength);
extern void                    daveSessionGetMarshalledKeyPackage(DAVESessionHandle session, u8** keyPackage, size_t* length);
extern DAVEKeyRatchetHandle    daveSessionGetKeyRatchet(DAVESessionHandle session, const char* userId);

extern u8   daveCommitResultIsFailed(DAVECommitResultHandle handle);
extern u8   daveCommitResultIsIgnored(DAVECommitResultHandle handle);
extern void daveCommitResultDestroy(DAVECommitResultHandle handle);

extern void daveWelcomeResultDestroy(DAVEWelcomeResultHandle handle);

extern void daveKeyRatchetDestroy(DAVEKeyRatchetHandle ratchet);

extern DAVEEncryptorHandle daveEncryptorCreate(void);
extern void                daveEncryptorDestroy(DAVEEncryptorHandle encryptor);
extern void                daveEncryptorSetKeyRatchet(DAVEEncryptorHandle encryptor, DAVEKeyRatchetHandle ratchet);
extern void                daveEncryptorAssignSsrcToCodec(DAVEEncryptorHandle encryptor, u32 ssrc, i32 codecType);
extern i32                 daveEncryptorEncrypt(DAVEEncryptorHandle encryptor, i32 mediaType, u32 ssrc, const u8* frame, size_t frameLength, u8* encryptedFrame, size_t encryptedFrameCapacity, size_t* bytesWritten);

extern DAVEDecryptorHandle daveDecryptorCreate(void);
extern void                daveDecryptorDestroy(DAVEDecryptorHandle decryptor);
extern void                daveDecryptorTransitionToKeyRatchet(DAVEDecryptorHandle decryptor, DAVEKeyRatchetHandle ratchet);
extern i32                 daveDecryptorDecrypt(DAVEDecryptorHandle decryptor, i32 mediaType, const u8* encryptedFrame, size_t encryptedFrameLength, u8* frame, size_t frameCapacity, size_t* bytesWritten);

extern void daveFree(void* ptr);

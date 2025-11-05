typedef enum {
    ErfTag_Nil,
    ErfTag_Bool,
    ErfTag_Int32,
    ErfTag_Int64,
    ErfTag_Uint64,
    ErfTag_Float64,
    ErfTag_Str,
    ErfTag_Arr,
    ErfTag_Map,
} ErfTag;

typedef union {
    u64 u;
    i64 i;
} FlakeId;

typedef enum {
    DisChannelType_Unknown,
    DisChannelType_GuildText,
    DisChannelType_GuildVoice,
    DisChannelType_GuildCategory,
    DisChannelType_PrivatePair,
    DisChannelType_PrivateGroup,

    DisChannelType_GuildVoiceStage = 13,
} DisChannelType;

__declspec(align(8)) typedef struct {
    i32         length;
    const char* data;
} ErfStr;

__declspec(align(8)) typedef struct {
    void* addr;
    i32   count;
} ErfMap;

__declspec(align(8)) typedef struct {
    void* addr;
    i32   count;
} ErfArr;

typedef struct {
    void* sqlite3_stmt;
} RipStmt;

typedef struct {
    ErfTag tag;
    union {
        u8     boolean;
        i32    int32;
        i64    int64;
        u64    uint64;
        f64    float64;
        ErfStr str;
        ErfArr arr;
        ErfMap map;
    };
} ErfMapAny;

typedef struct
{
    int     txCount;
    RipStmt stmt_beginTx;
    RipStmt stmt_endTx;
    RipStmt replaceIntoGuild;
    RipStmt replaceIntoGuildChannel;
    RipStmt replaceIntoGuildVoiceChannel;
    RipStmt replaceIntoGuildChannelCategory;
    RipStmt replaceIntoGuildMember;
    RipStmt replaceIntoGuildMemberRole;
    RipStmt deleteFromGuildMemberRole_UserId_GuildId;
    RipStmt deleteFromGuildMember_UserId_GuildId;
    RipStmt replaceIntoGuildBan_GuildId_UserId;
    RipStmt deleteFromGuildBan_GuildId_UserId;
    RipStmt replaceIntoRole;
    RipStmt deleteFromRole;
    RipStmt deleteGuildChannelPermQ;
    RipStmt replaceIntoGuildChannelPermQ;
    RipStmt replaceIntoMessage;
    RipStmt insertOrIgnoreIntoQuotedMessage;
    RipStmt replaceIntoEmoji;
    RipStmt replaceIntoEmojiRole;
    RipStmt replaceIntoEmojiGuild;
    RipStmt deleteEmojiInGuildQ;
    RipStmt ensureUserExistsQ;
    RipStmt deleteMessageEmbedsQ;
    RipStmt replaceIntoUserChannelReadState;
    RipStmt replaceIntoUserChannelReadStateKeepMentions;
    RipStmt replaceIntoAnyChannelType;
    RipStmt updateUserStatus;
    RipStmt updateUserStatusWithGame;
    RipStmt insertOrReplaceIntoVoiceState;
    RipStmt deleteFromVoiceState_SessionId;
    RipStmt selectUserHashSum;
    RipStmt replaceIntoUser;
    RipStmt updateUser;
    RipStmt replaceIntoGuildMemberForChannel;
    RipStmt updatePrivateChannelLastMessageId;
    RipStmt updateGuildChannelLastMessageId;
    RipStmt addEmojiReactionQ;
    RipStmt addEmojiReactionCountQ;
    RipStmt removeEmojiReactionQ;
    RipStmt removeEmojiReactionCountQ;
    RipStmt deleteFromMessageEmojiReaction;
    RipStmt deleteFromMessageEmojiReactionCount;
    RipStmt replaceIntoChannelPinnedMessage;
    RipStmt deleteFromChannelPinnedMessage;
    RipStmt selectAuthorFromMessage;
    RipStmt replaceIntoPrivateChan_ChanId;
    RipStmt replaceIntoPrivateChanParticipant_ChanId_UserId;
    RipStmt updatePrivChan_Name_OwnerId_Icon_Id;
    RipStmt insertOrReplaceIntoUserRelationship_OwnUserId_OtherUserId_Type;
    RipStmt clearImageAttachsQ;
    RipStmt clearFileAttachsQ;
    RipStmt addImageAttachQ;
    RipStmt addFileAttachQ;
    RipStmt insertImageEmbedQ;
    RipStmt insertRichEmbedQ;
    RipStmt updateMessageSetDeleted_MsgId_ChanId;
    RipStmt replaceIntoFetchMarker;
    RipStmt selectMsgIdFromFetchMarker;
    void*   db;
    void*   jsbuffer;
} DisDbPrepared;
static_assert(sizeof(DisDbPrepared) == 0x1F0);

typedef struct {
    QString plain;
    QString xsalsa20_poly1305;
    QString xsalsa20_poly1305_suffix;
} VoiceEncStrings;
static_assert(sizeof(VoiceEncStrings) == (sizeof(QString) * 3));

typedef enum {
    VoiceEncMode_XChaCha20_Poly1305_RtpSize = 0x2,
    VoiceEncMode_XSalsa20_Poly1305_Suffix   = 0x3,
} VoiceEncMode;

typedef struct
{
    // NOTE(geni): I can't be bothered to define std::vector and VoiceDatagram... just look at the linux branch if you care
    u8 datagrams[24];

    u8* contentsData;
    u64 contentsCap;
    u64 contentsPos;
} VoiceDatasAccum;
static_assert(sizeof(VoiceDatasAccum) == 0x30);

typedef struct {
    u8              _unk[0x10];
    u8              parentVoiceLine[0x10];
    void*           webSocket;
    void*           heartbeatTimer;
    u8              connParams[0x30];
    void*           udpSocket;
    void*           emptyVoicePacketsTimer;
    u16             emptyVoicePacketsSent;
    u8              padding[6];
    u8*             packetBuffer;
    u64             packetBufferSize;
    u8*             sendPacketBuffer;
    u64             sendPacketBufferSize;
    VoiceDatasAccum voiceDatasAccum;
    u32             ssrc;
    u16             serverPort;
    u8              padding1[2];
    QString         serverAddress;
    u8              serverModes[8];
    u32             encMode;

    // NOTE(geni): Stealing padding for nonce :^)
    u32 COMMUNITY_FIX_nonce;

    u8*     secretKey;
    QString discoveredAddress;
    u16     discoveredPort;
    u16     sequence;
    u8      padding3[4];
} DisVLWorker;
static_assert(sizeof(DisVLWorker) == 0x100);

typedef struct {
    void*        networkThread;
    DisVLWorker* vlWorker;
    // NOTE(geni): Don't care about these
    u8      voiceSinksMutex[8];
    u8      voiceSinks[8];
    u32     stateType;
    u8      padding[4];
    u64     userId;
    u64     guildId;
    u64     channelId;
    QString sessionId;
    QString token;
    QString endpoint;
} DisVoiceLinePriv;
static_assert(sizeof(DisVoiceLinePriv) == 0x58);

typedef struct {
    u8                padding[0x10];
    DisVoiceLinePriv* priv;
} DisVoiceLine;
static_assert(sizeof(DisVoiceLine) == 0x18);

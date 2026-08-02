// NOTE(geni): No #pragma pack here, as alignof 1 would make ErfArr unpassable by value under SysV
//             The manual padding makes structs end up with the correct layout anyway

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
static_assert(sizeof(ErfTag) == 4);

typedef union {
    u64 u;
    i64 i;
} FlakeId;
static_assert(sizeof(FlakeId) == 0x8);

typedef enum {
    DisChannelType_Unknown,
    DisChannelType_GuildText,
    DisChannelType_GuildVoice,
    DisChannelType_GuildCategory,
    DisChannelType_PrivatePair,
    DisChannelType_PrivateGroup,

    DisChannelType_GuildVoiceStage = 13,
} DisChannelType;

typedef struct {
    const char* data;
    i32         length;
    Pad(4);
} ErfStr;
static_assert(sizeof(ErfStr) == 0x10);

typedef struct {
    void* addr;
    i32   count;
    Pad(4);
} ErfMap;
static_assert(sizeof(ErfMap) == 0x10);

typedef struct {
    void* addr;
    i32   count;
    Pad(4);
} ErfArr;
static_assert(sizeof(ErfArr) == 0x10);

typedef struct {
    void* sqlite3_stmt;
} RipStmt;
static_assert(sizeof(RipStmt) == 0x8);

typedef struct {
    ErfTag tag;
    Pad(4);
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
static_assert(sizeof(ErfMapAny) == 0x18);

typedef union {
    struct {
        ErfTag t;
    } any;
    struct {
        ErfTag t;
        u8     v;
    } boolean;
    struct {
        ErfTag t;
        i32    v;
    } int32;
    struct {
        ErfTag t;
        Pad(4);
        i64 v;
    } int64;
    struct {
        ErfTag t;
        Pad(4);
        u64 v;
    } uint64;
    struct {
        ErfTag t;
        Pad(4);
        f64 v;
    } float64;
    struct {
        ErfTag      t;
        i32         size;
        const char* data;
    } str;
    struct {
        ErfTag t;
        u32    valsOffset;
        u32    count;
    } arr;
    struct {
        ErfTag t;
        u32    keysOffset;
        u32    count;
    } map;
} ErfCell;
static_assert(sizeof(ErfCell) == 0x10);
static_assert(sizeof(((ErfCell*) 0)->arr) == 0xC);

typedef struct {
    const char* data;
    i32         size;
    Pad(4);
} ErfKey;
static_assert(sizeof(ErfKey) == 0x10);

typedef struct
{
    i32 txCount;
    Pad(4);
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

//~ Voice

typedef struct {
    u8* data;
    u64 dataSize;
} DisVoiceDatagram;
static_assert(sizeof(DisVoiceDatagram) == 0x10);

typedef struct {
    DisVoiceDatagram datagram;
    u32              _unk1;
    u32              _unk2;
    u32              _unk3;
    u16              _unk4;
    u8               _unk5;
    Pad(1);
} SomeVoiceData;
static_assert(sizeof(SomeVoiceData) == 0x20);

typedef struct {
    void*          _unk1;
    SomeVoiceData* some_voice_data_array;
    SomeVoiceData* some_voice_data_array_unk;
    u8*            internal_buf;
    u64            buf_size;
    u64            buf_size_in_dwords;
} VoiceDataAccum;
static_assert(sizeof(VoiceDataAccum) == 0x30);

//~ Ded/ETF

enum {
    // NOTE(geni): 'h' (SMALL_TUPLE_EXT)
    DedETFTerm_SmallTuple = 104,
};

typedef u32 DedEventType;
enum {
    DedEventType_Nil,
    DedEventType_Uint8,
    DedEventType_Int32,
    DedEventType_Int64,
    DedEventType_Uint64,
    DedEventType_Float64,
    DedEventType_Atom,
    DedEventType_Binary,
    DedEventType_ListStart,
    DedEventType_ListEnd,
    DedEventType_MapStart,
    DedEventType_MapEnd,
};
static_assert(sizeof(DedEventType) == 4);

typedef u8 DedResultType;
enum {
    DedResultType_Event,
    DedResultType_Error,
};
static_assert(sizeof(DedResultType) == 1);

typedef u8 DedErrorType;
enum {
    DedErrorType_EndedUnexpectedly,
    DedErrorType_UnknownTermType,
    DedErrorType_ValueOutOfRange,
    DedErrorType_ExceededSizeLimit,
};
static_assert(sizeof(DedErrorType) == 1);

// NOTE(geni): String8 matches with Ripcord's Ded::Bytes lmao
typedef String8 DedBytes;
static_assert(sizeof(DedBytes) == 0x10);

typedef struct {
    DedEventType type;
    Pad(4);
    union {
        u8      uint8;
        i32     int32;
        i64     int64;
        u64     uint64;
        f64     float64;
        String8 atom;
        String8 binary;
        u64     listStart;
        u64     mapStart;
    };
} DedEvent;
static_assert(sizeof(DedEvent) == 0x18);

typedef struct {
    DedErrorType type;
    u8           unknownTerm;
} DedError;
static_assert(sizeof(DedError) == 2);

// NOTE(geni): LSB is type, rest is count
typedef u32 DedFrame;
static_assert(sizeof(DedFrame) == 4);

typedef struct {
    DedResultType type;
    Pad(7);
    union {
        DedEvent event;
        DedError error;
    };
} DedResult;
static_assert(sizeof(DedResult) == 0x20);

typedef struct {
    DedFrame frames[255];
    Pad(4);
    u8* data;
    u64 length;
    u64 index;
} DedState;
static_assert(sizeof(DedState) == 0x418);

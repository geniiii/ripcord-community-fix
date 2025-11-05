#define VOICEDATA_APPEND(name) void name(VoiceDatasAccum* this, u8* voiceData, u64 voiceDataSize, u8 version, u16 sequence, u32 timestamp, u32 ssrc)
typedef VOICEDATA_APPEND(VoiceDataAppendType);

#define ERF_MAP_FIND(name) u8 name(ErfMap* map, const char* key, u64 key_size, ErfMapAny* out)
typedef ERF_MAP_FIND(ErfMapFindType);

#define ERF_ARR_AT(name) ErfMapAny* name(ErfArr* this, ErfMapAny* result, i32 i)
typedef ERF_ARR_AT(ErfArrAtType);

#define UPDATEUSERGUILDPOSITIONS(name) void name(DisDbPrepared* comStmts, FlakeId userId, ErfArr* guildPosList)
typedef UPDATEUSERGUILDPOSITIONS(UpdateUserGuildPositionsType);

#define RIPSTMT_CONSTRUCTOR(name) void name(RipStmt* this, void* db, const char* sql, int* errcode)
typedef RIPSTMT_CONSTRUCTOR(RipStmtConstructorType);

#define RIPSTMT_DESTRUCTOR(name) void name(RipStmt* this)
typedef RIPSTMT_DESTRUCTOR(RipStmtDestructorType);

#define RIPSTMT_BIND_U64(name) void name(RipStmt* this, int index, u64 value)
typedef RIPSTMT_BIND_U64(RipStmtBindU64Type);

#define RIPSTMT_STEP(name) void name(RipStmt* this)
typedef RIPSTMT_STEP(RipStmtStepType);

#define RIPSTMT_RESET(name) void name(RipStmt* this)
typedef RIPSTMT_RESET(RipStmtResetType);

#define DISDBPREPARED_BEGINTX(name) void name(DisDbPrepared* this)
typedef DISDBPREPARED_BEGINTX(DisDbPreparedBegintxType);

#define DISDBPREPARED_ENDTX(name) void name(DisDbPrepared* this)
typedef DISDBPREPARED_ENDTX(DisDbPreparedEndtxType);

#define READVOICEDATAPACKET_WITHENCRYPTIONMODE(name) void name(VoiceDatasAccum* voiceAccum, VoiceEncMode modeSpec, u8* secretKey, u8* data, u64 size)
typedef READVOICEDATAPACKET_WITHENCRYPTIONMODE(ReadVoiceDataPacketType);

#define SETVOICEENCSTRINGS(name) VoiceEncStrings* name(void* this)
typedef SETVOICEENCSTRINGS(SetVoiceEncStringsType);

#define SEND_SPEAKING_STATE(name) void name(DisVoiceLine* this, u8 isSpeaking)
typedef SEND_SPEAKING_STATE(SendSpeakingStateType);

#define SEND_VOICE_DATAGRAM(name) void name(DisVoiceLine* this, u8* data, u64 dataSize, u32 timestamp)
typedef SEND_VOICE_DATAGRAM(SendVoiceDatagramType);

#define DISVLWORKER_CONSTRUCTOR(name) DisVLWorker* name(DisVLWorker* this, void* parent)
typedef DISVLWORKER_CONSTRUCTOR(DisVLWorkerConstructorType);

#define EMPTY_VOICE_PACKET_SEND(name) void name(DisVLWorker** this)
typedef EMPTY_VOICE_PACKET_SEND(EmptyVoicePacketSendType);

static VoiceDataAppendType*          voice_data_append;
static ErfMapFindType*               erf_map_find;
static ErfArrAtType*                 erf_arr_at;
static UpdateUserGuildPositionsType* update_user_guild_positions;
static RipStmtConstructorType*       ripstmt_constructor;
static RipStmtDestructorType*        ripstmt_destructor;
static RipStmtBindU64Type*           ripstmt_bind_u64;
static RipStmtStepType*              ripstmt_step;
static RipStmtResetType*             ripstmt_reset;
static DisDbPreparedBegintxType*     disdbprepared_begintx;
static DisDbPreparedEndtxType*       disdbprepared_endtx;
static SetVoiceEncStringsType*       set_voice_enc_strings;
static ReadVoiceDataPacketType*      read_voice_data_packet;
static SendSpeakingStateType*        send_speaking_state;
static SendVoiceDatagramType*        send_voice_datagram;
static DisVLWorkerConstructorType*   disvlworker_constructor;
static EmptyVoicePacketSendType*      empty_voice_packet_send;

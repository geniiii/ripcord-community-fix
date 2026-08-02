#define WRITE_DATAGRAM(name) i64 name(void* this, u8* data, i64 size, void* addr, u16 port)
typedef WRITE_DATAGRAM(WriteDatagramType);

#define READ_VOICE_DATA_PACKET(name) void name(VoiceDataAccum* accum, u32 a2, const u8* a3, char* a4, u64 a5)
typedef READ_VOICE_DATA_PACKET(ReadVoiceDataPacketType);

#define ERF_MAP_FIND(name) u8 name(ErfMap* map, const char* key, u64 key_size, ErfMapAny* out)
typedef ERF_MAP_FIND(ErfMapFindType);

#define UPDATEUSERGUILDPOSITIONS(name) void name(DisDbPrepared* comStmts, FlakeId userId, ErfArr guildPosList)
typedef UPDATEUSERGUILDPOSITIONS(UpdateUserGuildPositionsType);

#define RIPSTMT_CONSTRUCTOR(name) void name(RipStmt* this, void* db, const char* sql, i32* errcode)
typedef RIPSTMT_CONSTRUCTOR(RipStmtConstructorType);

#define RIPSTMT_DESTRUCTOR(name) void name(RipStmt* this)
typedef RIPSTMT_DESTRUCTOR(RipStmtDestructorType);

#define RIPSTMT_BIND_U64(name) void name(RipStmt* this, i32 index, u64 value)
typedef RIPSTMT_BIND_U64(RipStmtBindU64Type);

#define RIPSTMT_STEP(name) void name(RipStmt* this)
typedef RIPSTMT_STEP(RipStmtStepType);

#define RIPSTMT_RESET(name) void name(RipStmt* this)
typedef RIPSTMT_RESET(RipStmtResetType);

#define DISDBPREPARED_BEGINTX(name) void name(DisDbPrepared* this)
typedef DISDBPREPARED_BEGINTX(DisDbPreparedBegintxType);

#define DISDBPREPARED_ENDTX(name) void name(DisDbPrepared* this)
typedef DISDBPREPARED_ENDTX(DisDbPreparedEndtxType);

#define DED_STEP(name) DedResult* name(DedResult* result, DedState* s)
typedef DED_STEP(DedStepType);

static WriteDatagramType*            write_datagram;
static ReadVoiceDataPacketType*      read_voice_data_packet;
static ErfMapFindType*               erf_map_find;
static UpdateUserGuildPositionsType* update_user_guild_positions;
static RipStmtConstructorType*       ripstmt_constructor;
static RipStmtDestructorType*        ripstmt_destructor;
static RipStmtBindU64Type*           ripstmt_bind_u64;
static RipStmtStepType*              ripstmt_step;
static RipStmtResetType*             ripstmt_reset;
static DisDbPreparedBegintxType*     disdbprepared_begintx;
static DisDbPreparedEndtxType*       disdbprepared_endtx;
static DedStepType*                  ded_step;

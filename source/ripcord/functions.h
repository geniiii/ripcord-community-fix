#define VOICEDATASACCUM_APPEND(name) void name(VoiceDatasAccum* this, u8* voiceData, u64 voiceDataSize, u8 version, u16 sequence, u32 timestamp, u32 ssrc)
typedef VOICEDATASACCUM_APPEND(VoiceDatasAccum_AppendType);

#define ERFMAP_FIND(name) u8 name(ErfMap* map, const char* key, u64 key_size, ErfMapAny* out)
typedef ERFMAP_FIND(ErfMap_FindType);

#define ERFARR_AT(name) ErfMapAny* name(ErfArr* this, ErfMapAny* result, i32 i)
typedef ERFARR_AT(ErfArr_AtType);

#define ERF_CONVERTFLAKE(name) u8 name(const ErfMapAny* any, FlakeId* out)
typedef ERF_CONVERTFLAKE(Erf_ConvertFlakeType);

#define ERF_CONVERTU64(name) u8 name(const ErfMapAny* any, u64* out)
typedef ERF_CONVERTU64(Erf_ConvertU64Type);

#define DISDB_UPDATEUSERGUILDPOSITIONS(name) void name(DisDbPrepared* comStmts, FlakeId userId, ErfArr* guildPosList)
typedef DISDB_UPDATEUSERGUILDPOSITIONS(DisDb_UpdateUserGuildPositionsType);

#define DISDB_UPDATEADDGUILDCHANNELJSON(name) void name(DisDbPrepared* comStmts, ErfMap* chanMap, FlakeId guildId)
typedef DISDB_UPDATEADDGUILDCHANNELJSON(DisDb_UpdateAddGuildChannelJsonType);

#define RIPSTMT_CONSTRUCTOR(name) void name(RipStmt* this, void* db, const char* sql, i32* errcode)
typedef RIPSTMT_CONSTRUCTOR(RipStmt_ConstructorType);

#define RIPSTMT_DESTRUCTOR(name) void name(RipStmt* this)
typedef RIPSTMT_DESTRUCTOR(RipStmt_DestructorType);

#define RIPSTMT_BINDU64(name) void name(RipStmt* this, i32 index, u64 value)
typedef RIPSTMT_BINDU64(RipStmt_BindU64Type);

#define RIPSTMT_STEP(name) u8 name(RipStmt* this)
typedef RIPSTMT_STEP(RipStmt_StepType);

#define RIPSTMT_RESET(name) void name(RipStmt* this)
typedef RIPSTMT_RESET(RipStmt_ResetType);

#define RIPSTMT_COLU64(name) u64 name(RipStmt* this, i32 index)
typedef RIPSTMT_COLU64(RipStmt_ColU64Type);

#define FLAKEID_TOSTRING(name) QString* name(const FlakeId* this, QString* result)
typedef FLAKEID_TOSTRING(FlakeId_ToStringType);

#define DISCLIENTIMPL_EVENTNAMETOENUM(name) GatewayEvent name(const ErfStr* event_name)
typedef DISCLIENTIMPL_EVENTNAMETOENUM(DisClientImpl_EventNameToEnumType);

#define DISCLIENTIMPL_PROCESSGATEWAYMESSAGE(name) void name(DisSessionWorker* w, ErfMap* root_map)
typedef DISCLIENTIMPL_PROCESSGATEWAYMESSAGE(DisClientImpl_ProcessGatewayMessageType);

#define CHGSREF_CONSTRUCTOR(name) ChgsRef* name(ChgsRef* this)
typedef CHGSREF_CONSTRUCTOR(ChgsRef_ConstructorType);

#define DISCHANGE_ADDCHANGE(name) DisChange* name(DisChanges* changes, DisChangeType type)
typedef DISCHANGE_ADDCHANGE(DisChange_AddChangeType);

#define DISCLIENTIMPL_SENDANYCHGS(name) void name(DisSessionWorker* w, ChgsRef* cs)
typedef DISCLIENTIMPL_SENDANYCHGS(DisClientImpl_SendAnyChgsType);

#define DISDBPREPARED_BEGINTX(name) void name(DisDbPrepared* this)
typedef DISDBPREPARED_BEGINTX(DisDbPrepared_BeginTxType);

#define DISDBPREPARED_ENDTX(name) void name(DisDbPrepared* this)
typedef DISDBPREPARED_ENDTX(DisDbPrepared_EndTxType);

#define DISCLIENTIMPL_READVOICEDATAPACKET(name) void name(VoiceDatasAccum* voiceAccum, VoiceEncMode modeSpec, u8* secretKey, u8* data, u64 size)
typedef DISCLIENTIMPL_READVOICEDATAPACKET(DisClientImpl_ReadVoiceDataPacketType);

#define DISCLIENTIMPL_VOICEENCSTRINGS(name) VoiceEncStrings* name(void* this)
typedef DISCLIENTIMPL_VOICEENCSTRINGS(DisClientImpl_VoiceEncStringsType);

#define DISVOICELINE_SENDSPEAKINGSTATE(name) void name(DisVoiceLine* this, u8 isSpeaking)
typedef DISVOICELINE_SENDSPEAKINGSTATE(DisVoiceLine_SendSpeakingStateType);

#define DISVOICELINE_SENDVOICEDATAGRAM(name) void name(DisVoiceLine* this, u8* data, u64 dataSize, u32 timestamp)
typedef DISVOICELINE_SENDVOICEDATAGRAM(DisVoiceLine_SendVoiceDatagramType);

#define DISVLWORKER_CONSTRUCTOR(name) DisVLWorker* name(DisVLWorker* this, void* parent)
typedef DISVLWORKER_CONSTRUCTOR(DisVLWorker_ConstructorType);

#define DISVLWORKER_SENDEMPTYVOICEPACKETS(name) void name(DisVLWorker** this)
typedef DISVLWORKER_SENDEMPTYVOICEPACKETS(DisVLWorker_SendEmptyVoicePacketsType);

#define DISVOICEENCODE_CREATEENCODINGCONTEXT(name) DisVoiceEncode_EncodingContext* name(void* this, u8 forceMusicSignal)
typedef DISVOICEENCODE_CREATEENCODINGCONTEXT(DisVoiceEncode_CreateEncodingContextType);

#define DISCLIENTIMPL_VOICECONNWEBSOCKETCONNECTED(name) void name(DisVLWorker* vc)
typedef DISCLIENTIMPL_VOICECONNWEBSOCKETCONNECTED(DisClientImpl_VoiceConnWebSocketConnectedType);

#define DISCLIENTIMPL_VOICECONNTEXTMESSAGERECEIVED(name) void name(DisVLWorker* vw, const QString* text)
typedef DISCLIENTIMPL_VOICECONNTEXTMESSAGERECEIVED(DisClientImpl_VoiceConnTextMessageReceivedType);

#define DED_STEP(name) DedResult* name(DedResult* result, DedState* s)
typedef DED_STEP(Ded_StepType);

#define WEBSOCKETHELPERS_SENDJSON(name) void name(void* webSocket, QJsonValue* jsonVal)
typedef WEBSOCKETHELPERS_SENDJSON(WebSocketHelpers_SendJsonType);

static VoiceDatasAccum_AppendType*                     VoiceDatasAccum_Append;
static ErfMap_FindType*                                ErfMap_Find;
static ErfArr_AtType*                                  ErfArr_At;
static Erf_ConvertFlakeType*                           Erf_ConvertFlake;
static Erf_ConvertU64Type*                             Erf_ConvertU64;
static DisDb_UpdateUserGuildPositionsType*             DisDb_UpdateUserGuildPositions;
static DisDb_UpdateAddGuildChannelJsonType*            DisDb_UpdateAddGuildChannelJson;
static RipStmt_ConstructorType*                        RipStmt_Constructor;
static RipStmt_DestructorType*                         RipStmt_Destructor;
static RipStmt_BindU64Type*                            RipStmt_BindU64;
static RipStmt_StepType*                               RipStmt_Step;
static RipStmt_ResetType*                              RipStmt_Reset;
static RipStmt_ColU64Type*                             RipStmt_ColU64;
static FlakeId_ToStringType*                           FlakeId_ToString;
static DisClientImpl_EventNameToEnumType*              DisClientImpl_EventNameToEnum;
static DisClientImpl_ProcessGatewayMessageType*        DisClientImpl_ProcessGatewayMessage;
static ChgsRef_ConstructorType*                        ChgsRef_Constructor;
static DisChange_AddChangeType*                        DisChange_AddChange;
static DisClientImpl_SendAnyChgsType*                  DisClientImpl_SendAnyChgs;
static DisDbPrepared_BeginTxType*                      DisDbPrepared_BeginTx;
static DisDbPrepared_EndTxType*                        DisDbPrepared_EndTx;
static DisClientImpl_VoiceEncStringsType*              DisClientImpl_VoiceEncStrings;
static DisClientImpl_ReadVoiceDataPacketType*          DisClientImpl_ReadVoiceDataPacket;
static DisVoiceLine_SendSpeakingStateType*             DisVoiceLine_SendSpeakingState;
static DisVoiceLine_SendVoiceDatagramType*             DisVoiceLine_SendVoiceDatagram;
static DisVLWorker_ConstructorType*                    DisVLWorker_Constructor;
static DisVLWorker_SendEmptyVoicePacketsType*          DisVLWorker_SendEmptyVoicePackets;
static DisVoiceEncode_CreateEncodingContextType*       DisVoiceEncode_CreateEncodingContext;
static DisClientImpl_VoiceConnWebSocketConnectedType*  DisClientImpl_VoiceConnWebSocketConnected;
static DisClientImpl_VoiceConnTextMessageReceivedType* DisClientImpl_VoiceConnTextMessageReceived;
static Ded_StepType*                                   Ded_Step;
static WebSocketHelpers_SendJsonType*                  WebSocketHelpers_SendJson;
static WebSocketHelpers_SendJsonType*                  WebSocketHelpers_SendJsonAsEtf;

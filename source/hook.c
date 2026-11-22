static u32 Hook_Create(u8* base, u64 ptr, void* hook, void** orig) {
    static char buffer[4096];

    MH_STATUS status;
    if ((status = MH_CreateHook(base + ptr, hook, orig)) != MH_OK) {
        snprintf(buffer, sizeof buffer, "Failed to create hook at 0x%llX\nError code: %d", ptr, status);
        Log_Error(buffer);
        return 0;
    }
    if ((status = MH_EnableHook(base + ptr)) != MH_OK) {
        snprintf(buffer, sizeof buffer, "Failed to enable hook at 0x%llX\nError code: %d", ptr, status);
        Log_Error(buffer);
        return 0;
    }

    return 1;
}

static void Hook_PatchByte(u8* base, u64 ptr, u8 new) {
    DWORD old_protect;
    u8*   addr = base + ptr;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old_protect);
    *addr = new;
    VirtualProtect(addr, 1, old_protect, &old_protect);
}

static void Hook_PatchString(u8* base, u64 ptr, String8 new) {
    DWORD old_protect;
    u8*   addr = base + ptr;
    VirtualProtect(addr, new.size, PAGE_EXECUTE_READWRITE, &old_protect);
    CopyMemory(addr, new.data, new.size);
    VirtualProtect(addr, new.size, old_protect, &old_protect);
}

static u32 Hook_Init() {
    if (MH_Initialize() != MH_OK) {
        Log_Error("Failed to initialize MinHook");
        return 0;
    }

    MODULEINFO module_info;
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA("Ripcord.exe"), &module_info, sizeof module_info);
    u8* rip_base = (u8*) module_info.lpBaseOfDll;

    for (u32 i = 0; i < sizeof SUPPORTED_VERSION; ++i) {
        if (rip_base[0x3BAB70 + i] != SUPPORTED_VERSION[i]) {
            Log_Error("Unsupported Ripcord version (expected " SUPPORTED_VERSION ")");
            return 0;
        }
    }

    // NOTE(geni): Patch IP discovery packet sizes
    Hook_PatchByte(rip_base, 0xDE8D8, 74);
    Hook_PatchByte(rip_base, 0xDE8EA, 8);
    Hook_PatchByte(rip_base, 0xDE90C, 8);
    Hook_PatchByte(rip_base, 0xDE936, 72);

    // NOTE(geni): Set voice gateway version to 8
    Hook_PatchByte(rip_base, 0x3CDEB4 + 0x1200, '8');
    // NOTE(geni): Patch "speaking" field check for v4 and later of voice gateway
    // NOTE(geni): Check for double instead of bool for "speaking" field
    Hook_PatchByte(rip_base, 0xE605C + 0xC00, 0x83);
    Hook_PatchByte(rip_base, 0xE605C + 0xC00 + 1, 0xF8);
    Hook_PatchByte(rip_base, 0xE605C + 0xC00 + 2, 0x02);
    // NOTE(geni): Call QJsonValue::toInt() instead of QJsonValue::toBool()
    Hook_PatchByte(rip_base, 0xE6067 + 0xC00 + 2, 0x03);
    Hook_PatchByte(rip_base, 0xE6067 + 0xC00 + 3, 0x76);

    // NOTE(geni): Fixes image previews not loading. Thanks u130b8!
    Hook_PatchString(rip_base, 0x3E63F8, S8Lit("cdn.discordapp.com/\0\0\0"));

    // NOTE(geni): Discard invalid map keys instead of aborting. Thanks @muffinlord on Discord!
    Hook_PatchByte(rip_base, 0xB9BBF, 0xEB);
    Hook_PatchByte(rip_base, 0xB9BC0, 0x80);

    // NOTE(geni): Disable gateway port splitting
    Hook_PatchByte(rip_base, 0xD677E, 0x10);

    HMODULE qt5core       = GetModuleHandleA("Qt5Core.dll");
    HMODULE qt5network    = GetModuleHandleA("Qt5Network.dll");
    HMODULE sodium        = GetModuleHandleA("libsodium.dll");
    HMODULE qt5websockets = GetModuleHandleA("Qt5WebSockets.dll");

    u64 read_datagram_addr  = (u64) GetProcAddress(qt5network, "?readDatagram@QUdpSocket@@QEAA_JPEAD_JPEAVQHostAddress@@PEAG@Z");
    u64 write_datagram_addr = (u64) GetProcAddress(qt5network, "?writeDatagram@QUdpSocket@@QEAA_JPEBD_JAEBVQHostAddress@@G@Z");

    u64 connect_to_host_addr = (u64) GetProcAddress(qt5network, "?connectToHost@QAbstractSocket@@UEAAXAEBVQString@@GV?$QFlags@W4OpenModeFlag@QIODevice@@@@W4NetworkLayerProtocol@1@@Z");

    u32 result = 1;
    result &= Hook_Create(0, connect_to_host_addr, (LPVOID) &QAbstractSocket_ConnectToHostHook, (LPVOID*) &QAbstractSocket_ConnectToHost);
    result &= Hook_Create(rip_base, 0xB9690, (LPVOID) &ErfMap_FindHook, (LPVOID*) &ErfMap_Find);
    result &= Hook_Create(rip_base, 0xF9750, (LPVOID) &DisDb_UpdateUserGuildPositionsHook, (LPVOID*) &DisDb_UpdateUserGuildPositions);
    result &= Hook_Create(rip_base, 0xCA3B0 + 0xC00, (LPVOID) &DisClientImpl_VoiceEncStringsHook, (LPVOID*) &DisClientImpl_VoiceEncStrings);
    result &= Hook_Create(rip_base, 0xDCC50 + 0xC00, (LPVOID) &DisClientImpl_ReadVoiceDataPacketHook, (LPVOID*) &DisClientImpl_ReadVoiceDataPacket);
    result &= Hook_Create(0, write_datagram_addr, (LPVOID) &QUdpSocket_WriteDatagramHook, (LPVOID*) &QUdpSocket_WriteDatagram);
    result &= Hook_Create(rip_base, 0xE1B50 + 0xC00, (LPVOID) &DisVoiceLine_SendVoiceDatagramHook, (LPVOID*) &DisVoiceLine_SendVoiceDatagram);
    result &= Hook_Create(rip_base, 0xC8590 + 0xC00, (LPVOID) &DisVLWorker_ConstructorHook, (LPVOID*) &DisVLWorker_Constructor);
    result &= Hook_Create(0, read_datagram_addr, (LPVOID) &QUdpSocket_ReadDatagramHook, (LPVOID*) &QUdpSocket_ReadDatagram);
    result &= Hook_Create(rip_base, 0xE15B0 + 0xC00, (LPVOID) &DisVoiceLine_SendSpeakingStateHook, (LPVOID*) &DisVoiceLine_SendSpeakingState);
    result &= Hook_Create(rip_base, 0xCA6E0 + 0xC00, (LPVOID) &DisVLWorker_SendEmptyVoicePacketsHook, (LPVOID*) &DisVLWorker_SendEmptyVoicePackets);
    result &= Hook_Create(rip_base, 0x149900 + 0xC00, (LPVOID) &DisVoiceEncode_CreateEncodingContextHook, (LPVOID*) &DisVoiceEncode_CreateEncodingContext);
    result &= Hook_Create(rip_base, 0xE6280 + 0xC00, (LPVOID) &DisClientImpl_VoiceConnWebSocketConnectedHook, (LPVOID*) &DisClientImpl_VoiceConnWebSocketConnected);
    result &= Hook_Create(rip_base, 0xE5160 + 0xC00, (LPVOID) &DisClientImpl_VoiceConnTextMessageReceivedHook, (LPVOID*) &DisClientImpl_VoiceConnTextMessageReceived);
    result &= Hook_Create(rip_base, 0xD4C20 + 0xC00, (LPVOID) &DisClientImpl_HeartbeatLambdaImplHook, (LPVOID*) &DisClientImpl_HeartbeatLambdaImpl);
    result &= Hook_Create(rip_base, 0xB5EF0, (LPVOID) &Ded_StepHook, (LPVOID*) &Ded_Step);

    result &= Hook_Create(rip_base, 0xF88B0, (LPVOID) &DisDb_UpdateAddGuildChannelJsonHook, (LPVOID*) &DisDb_UpdateAddGuildChannelJson);
    result &= Hook_Create(rip_base, 0xD6BC0, (LPVOID) &DisClientImpl_ProcessGatewayMessageHook, (LPVOID*) &DisClientImpl_ProcessGatewayMessage);

    ChgsRef_Constructor       = (ChgsRef_ConstructorType*) (rip_base + 0xC8510);
    DisChange_AddChange       = (DisChange_AddChangeType*) (rip_base + 0xEB4F0);
    DisClientImpl_SendAnyChgs = (DisClientImpl_SendAnyChgsType*) (rip_base + 0xDF0D0);

    VoiceDatasAccum_Append         = (VoiceDatasAccum_AppendType*) (rip_base + 0xD0DF0);
    DisDbPrepared_BeginTx          = (DisDbPrepared_BeginTxType*) (rip_base + 0xF62E0);
    DisDbPrepared_EndTx            = (DisDbPrepared_EndTxType*) (rip_base + 0xF7070);
    RipStmt_Constructor            = (RipStmt_ConstructorType*) (rip_base + 0x2110);
    RipStmt_Destructor             = (RipStmt_DestructorType*) (rip_base + 0x2230);
    RipStmt_BindU64                = (RipStmt_BindU64Type*) (rip_base + 0x25D0);
    RipStmt_Step                   = (RipStmt_StepType*) (rip_base + 0x3440);
    RipStmt_Reset                  = (RipStmt_ResetType*) (rip_base + 0x3420);
    RipStmt_ColU64                 = (RipStmt_ColU64Type*) (rip_base + 0x2720);
    ErfArr_At                      = (ErfArr_AtType*) (rip_base + 0xD0EE0);
    Erf_ConvertFlake               = (Erf_ConvertFlakeType*) (rip_base + 0xB9450);
    Erf_ConvertU64                 = (Erf_ConvertU64Type*) (rip_base + 0xB9530);
    WebSocketHelpers_SendJson      = (WebSocketHelpers_SendJsonType*) (rip_base + 0xE0E80 + 0xC00);
    WebSocketHelpers_SendJsonAsEtf = (WebSocketHelpers_SendJsonType*) (rip_base + 0xE1B30);
    FlakeId_ToString               = (FlakeId_ToStringType*) (rip_base + 0x39A0);
    DisClientImpl_EventNameToEnum  = (DisClientImpl_EventNameToEnumType*) (rip_base + 0xE73E0);

    QString_Destructor      = (QString_DestructorType*) GetProcAddress(qt5core, "??1QString@@QEAA@XZ");
    QString_FromAsciiHelper = (QString_FromAsciiHelperType*) GetProcAddress(qt5core, "?fromAscii_helper@QString@@CAPEAU?$QTypedArrayData@G@@PEBDH@Z");
    QString_ToUtf8          = (QString_ToUtf8Type*) GetProcAddress(qt5core, "?toUtf8@QString@@QEGBA?AVQByteArray@@XZ");

    QString_SetFromQLatin1String    = (QString_SetFromQLatin1StringType*) GetProcAddress(qt5core, "??4QString@@QEAAAEAV0@VQLatin1String@@@Z");
    QHostAddress_ConstructorQString = (QHostAddress_ConstructorQStringType*) GetProcAddress(qt5network, "??0QHostAddress@@QEAA@AEBVQString@@@Z");
    QHostAddress_Destructor         = (QHostAddress_DestructorType*) GetProcAddress(qt5network, "??1QHostAddress@@QEAA@XZ");

    QJsonValue_ConstructorInt         = (QJsonValue_ConstructorIntType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@H@Z");
    QJsonValue_ConstructorDouble      = (QJsonValue_ConstructorDoubleType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@N@Z");
    QJsonValue_ConstructorQJsonObject = (QJsonValue_ConstructorQJsonObjectType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@AEBVQJsonObject@@@Z");
    QJsonValue_Destructor             = (QJsonValue_DestructorType*) GetProcAddress(qt5core, "??1QJsonValue@@QEAA@XZ");
    QJsonValue_ConstructorQString     = (QJsonValue_ConstructorQStringType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@AEBVQString@@@Z");
    QJsonValue_ConstructorQJsonArray  = (QJsonValue_ConstructorQJsonArrayType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@AEBVQJsonArray@@@Z");
    QJsonArray_Constructor            = (QJsonArray_ConstructorType*) GetProcAddress(qt5core, "??0QJsonArray@@QEAA@XZ");
    QJsonArray_Append                 = (QJsonArray_AppendType*) GetProcAddress(qt5core, "?append@QJsonArray@@QEAAXAEBVQJsonValue@@@Z");
    QJsonArray_Destructor             = (QJsonArray_DestructorType*) GetProcAddress(qt5core, "??1QJsonArray@@QEAA@XZ");
    QJsonObject_Insert                = (QJsonObject_InsertType*) GetProcAddress(qt5core, "?insert@QJsonObject@@QEAA?AViterator@1@AEBVQString@@AEBVQJsonValue@@@Z");
    QJsonObject_Constructor           = (QJsonObject_ConstructorType*) GetProcAddress(qt5core, "??0QJsonObject@@QEAA@XZ");
    QJsonObject_Destructor            = (QJsonObject_DestructorType*) GetProcAddress(qt5core, "??1QJsonObject@@QEAA@XZ");
    QTimer_Stop                       = (QTimer_StopType*) GetProcAddress(qt5core, "?stop@QTimer@@QEAAXXZ");
    QDateTime_CurrentMSecsSinceEpoch  = (QDateTime_CurrentMSecsSinceEpochType*) GetProcAddress(qt5core, "?currentMSecsSinceEpoch@QDateTime@@SA_JXZ");

    crypto_aead_xchacha20poly1305_ietf_decrypt = (CryptoAeadXchacha20poly1305IetfDecryptType*) GetProcAddress(sodium, "crypto_aead_xchacha20poly1305_ietf_decrypt");
    crypto_aead_xchacha20poly1305_ietf_encrypt = (CryptoAeadXchacha20poly1305IetfEncryptType*) GetProcAddress(sodium, "crypto_aead_xchacha20poly1305_ietf_encrypt");

    QByteArray_Constructor = (QByteArray_ConstructorType*) GetProcAddress(qt5core, "??0QByteArray@@QEAA@PEBDH@Z");
    QByteArray_Destructor  = (QByteArray_DestructorType*) GetProcAddress(qt5core, "??1QByteArray@@QEAA@XZ");
    QObject_ConnectImpl    = (QObject_ConnectImplType*) GetProcAddress(qt5core,
                                                                       "?connectImpl@QObject@@CA?AVConnection@QMetaObject@@"
                                                                          "PEBV1@PEAPEAX01PEAVQSlotObjectBase@QtPrivate@@"
                                                                          "W4ConnectionType@Qt@@PEBHPEBU3@@Z");

    QWebSocket_SendBinaryMessage = (QWebSocket_SendBinaryMessageType*) GetProcAddress(qt5websockets,
                                                                                      "?sendBinaryMessage@QWebSocket@@QEAA_JAEBVQByteArray@@@Z");
    g_binary_msg_signal_fn       = (void*) GetProcAddress(qt5websockets,
                                                          "?binaryMessageReceived@QWebSocket@@QEAAXAEBVQByteArray@@@Z");
    g_qwebsocket_static_meta     = (void*) GetProcAddress(qt5websockets,
                                                          "?staticMetaObject@QWebSocket@@2UQMetaObject@@B");
    QWebSocket_SendTextMessage   = (QWebSocket_SendTextMessageType*) GetProcAddress(qt5websockets,
                                                                                    "?sendTextMessage@QWebSocket@@QEAA_JAEBVQString@@@Z");

    return result;
}

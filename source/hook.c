static u32 CreateAndEnableHook(u8* base, u64 ptr, void* hook, void** orig) {
    static char buffer[4096];

    MH_STATUS status;
    if ((status = MH_CreateHook(base + ptr, hook, orig)) != MH_OK) {
        snprintf(buffer, sizeof buffer, "Failed to create hook at 0x%llX\nError code: %d", ptr, status);
        ErrorMessage(buffer);
        return 0;
    }
    if ((status = MH_EnableHook(base + ptr)) != MH_OK) {
        snprintf(buffer, sizeof buffer, "Failed to enable hook at 0x%llX\nError code: %d", ptr, status);
        ErrorMessage(buffer);
        return 0;
    }

    return 1;
}

static void PatchByte(u8* base, u64 ptr, u8 new) {
    DWORD old_protect;
    u8*   addr = base + ptr;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old_protect);
    *addr = new;
    VirtualProtect(addr, 1, old_protect, &old_protect);
}

static void PatchString(u8* base, u64 ptr, String8 new) {
    DWORD old_protect;
    u8*   addr = base + ptr;
    VirtualProtect(addr, new.size, PAGE_EXECUTE_READWRITE, &old_protect);
    CopyMemory(addr, new.data, new.size);
    VirtualProtect(addr, new.size, old_protect, &old_protect);
}

static u32 LoadHooks() {
    if (MH_Initialize() != MH_OK) {
        ErrorMessage("Failed to initialize MinHook");
        return 0;
    }

    MODULEINFO module_info;
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA("Ripcord.exe"), &module_info, sizeof module_info);
    u8* rip_base = (u8*) module_info.lpBaseOfDll;

    for (u32 i = 0; i < sizeof SUPPORTED_VERSION; ++i) {
        if (rip_base[0x3BAB70 + i] != SUPPORTED_VERSION[i]) {
            ErrorMessage("Unsupported Ripcord version (expected " SUPPORTED_VERSION ")");
            return 0;
        }
    }

    // NOTE(geni): Patch IP discovery packet sizes
    PatchByte(rip_base, 0xDE8D8, 74);
    PatchByte(rip_base, 0xDE8EA, 8);
    PatchByte(rip_base, 0xDE90C, 8);
    PatchByte(rip_base, 0xDE936, 72);

    // NOTE(geni): Set voice gateway version to 8
    PatchByte(rip_base, 0x3CDEB4 + 0x1200, '8');
    // NOTE(geni): Patch "speaking" field check for v4 and later of voice gateway
    // NOTE(geni): Check for double instead of bool for "speaking" field
    PatchByte(rip_base, 0xE605C + 0xC00, 0x83);
    PatchByte(rip_base, 0xE605C + 0xC00 + 1, 0xF8);
    PatchByte(rip_base, 0xE605C + 0xC00 + 2, 0x02);
    // NOTE(geni): Call QJsonValue::toInt() instead of QJsonValue::toBool()
    PatchByte(rip_base, 0xE6067 + 0xC00 + 2, 0x03);
    PatchByte(rip_base, 0xE6067 + 0xC00 + 3, 0x76);

    // NOTE(geni): Fixes image previews not loading. Thanks u130b8!
    PatchString(rip_base, 0x3E63F8, S8Lit("cdn.discordapp.com/\0\0\0"));

    // NOTE(geni): Discard invalid map keys instead of aborting. Thanks @muffinlord on Discord!
    PatchByte(rip_base, 0xB9BBF, 0xEB);
    PatchByte(rip_base, 0xB9BC0, 0x80);

    // NOTE(geni): Disable gateway port splitting
    PatchByte(rip_base, 0xD677E, 0x10);

    HMODULE qt5core       = GetModuleHandleA("Qt5Core.dll");
    HMODULE qt5network    = GetModuleHandleA("Qt5Network.dll");
    HMODULE sodium        = GetModuleHandleA("libsodium.dll");
    HMODULE qt5websockets = GetModuleHandleA("Qt5WebSockets.dll");

    u64 read_datagram_addr  = (u64) GetProcAddress(qt5network, "?readDatagram@QUdpSocket@@QEAA_JPEAD_JPEAVQHostAddress@@PEAG@Z");
    u64 write_datagram_addr = (u64) GetProcAddress(qt5network, "?writeDatagram@QUdpSocket@@QEAA_JPEBD_JAEBVQHostAddress@@G@Z");

    u64 connect_to_host_addr = (u64) GetProcAddress(qt5network, "?connectToHost@QAbstractSocket@@UEAAXAEBVQString@@GV?$QFlags@W4OpenModeFlag@QIODevice@@@@W4NetworkLayerProtocol@1@@Z");

    u32 result = 1;
    result &= CreateAndEnableHook(0, connect_to_host_addr, (LPVOID) &QAbstractSocketConnectToHostHook, (LPVOID*) &qabstractsocket_connecttohost);
    result &= CreateAndEnableHook(rip_base, 0xB9690, (LPVOID) &ErfMapFindHook, (LPVOID*) &erf_map_find);
    result &= CreateAndEnableHook(rip_base, 0xF9750, (LPVOID) &UpdateUserGuildPositionsHook, (LPVOID*) &update_user_guild_positions);
    result &= CreateAndEnableHook(rip_base, 0xCA3B0 + 0xC00, (LPVOID) &SetVoiceEncStringsHook, (LPVOID*) &set_voice_enc_strings);
    result &= CreateAndEnableHook(rip_base, 0xDCC50 + 0xC00, (LPVOID) &ReadVoiceDataPacketHook, (LPVOID*) &read_voice_data_packet);
    result &= CreateAndEnableHook(0, write_datagram_addr, (LPVOID) &WriteDatagramHook, (LPVOID*) &write_datagram);
    result &= CreateAndEnableHook(rip_base, 0xE1B50 + 0xC00, (LPVOID) &SendVoiceDatagramHook, (LPVOID*) &send_voice_datagram);
    result &= CreateAndEnableHook(rip_base, 0xC8590 + 0xC00, (LPVOID) &DisVLWorkerConstructorHook, (LPVOID*) &disvlworker_constructor);
    result &= CreateAndEnableHook(0, read_datagram_addr, (LPVOID) &ReadDatagramHook, (LPVOID*) &read_datagram);
    result &= CreateAndEnableHook(rip_base, 0xE15B0 + 0xC00, (LPVOID) &SendSpeakingStateHook, (LPVOID*) &send_speaking_state);
    result &= CreateAndEnableHook(rip_base, 0xCA6E0 + 0xC00, (LPVOID) &EmptyVoicePacketSendHook, (LPVOID*) &empty_voice_packet_send);
    result &= CreateAndEnableHook(rip_base, 0x149900 + 0xC00, (LPVOID) &DisVoiceEncodeCreateEncodingContextHook, (LPVOID*) &disvoiceencode_createencodingcontext);
    result &= CreateAndEnableHook(rip_base, 0xE6280 + 0xC00, (LPVOID) &VoiceConnWSConnectedHook, (LPVOID*) &voice_conn_ws_connected);
    result &= CreateAndEnableHook(rip_base, 0xE5160 + 0xC00, (LPVOID) &VoiceConnTextMsgReceivedHook, (LPVOID*) &voice_conn_text_msg_received);
    result &= CreateAndEnableHook(rip_base, 0xD4C20 + 0xC00, (LPVOID) &HeartbeatLambdaImplHook, (LPVOID*) &heartbeat_lambda_impl);
    result &= CreateAndEnableHook(rip_base, 0xB5EF0, (LPVOID) &DedStepHook, (LPVOID*) &ded_step);

    voice_data_append         = (VoiceDataAppendType*) (rip_base + 0xD0DF0);
    disdbprepared_begintx     = (DisDbPreparedBegintxType*) (rip_base + 0xF62E0);
    disdbprepared_endtx       = (DisDbPreparedEndtxType*) (rip_base + 0xF7070);
    ripstmt_constructor       = (RipStmtConstructorType*) (rip_base + 0x2110);
    ripstmt_destructor        = (RipStmtDestructorType*) (rip_base + 0x2230);
    ripstmt_bind_u64          = (RipStmtBindU64Type*) (rip_base + 0x25D0);
    ripstmt_step              = (RipStmtStepType*) (rip_base + 0x3440);
    ripstmt_reset             = (RipStmtResetType*) (rip_base + 0x3420);
    erf_arr_at                = (ErfArrAtType*) (rip_base + 0xD0EE0);
    websockethelpers_sendjson = (WebSocketHelpersSendJsonType*) (rip_base + 0xE0E80 + 0xC00);

    qstring_destructor        = (QStringDestructorType*) GetProcAddress(qt5core, "??1QString@@QEAA@XZ");
    qstring_from_ascii_helper = (QStringFromAsciiHelperType*) GetProcAddress(qt5core, "?fromAscii_helper@QString@@CAPEAU?$QTypedArrayData@G@@PEBDH@Z");
    qstring_toutf8            = (QStringToUtf8Type*) GetProcAddress(qt5core, "?toUtf8@QString@@QEGBA?AVQByteArray@@XZ");

    qstring_set_from_qlatin1string        = (QStringSetFromQLatin1StringType*) GetProcAddress(qt5core, "??4QString@@QEAAAEAV0@VQLatin1String@@@Z");
    qhostaddress_constructor_from_qstring = (QHostAddressConstructorFromQStringType*) GetProcAddress(qt5network, "??0QHostAddress@@QEAA@AEBVQString@@@Z");
    qhostaddress_destructor               = (QHostAddressDestructorType*) GetProcAddress(qt5network, "??1QHostAddress@@QEAA@XZ");

    qjsonvalue_constructor_int         = (QJsonValueConstructorIntType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@H@Z");
    qjsonvalue_constructor_double      = (QJsonValueConstructorDoubleType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@N@Z");
    qjsonvalue_constructor_qjsonobject = (QJsonValueConstructorQJsonObjectType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@AEBVQJsonObject@@@Z");
    qjsonvalue_destructor              = (QJsonValueDestructorType*) GetProcAddress(qt5core, "??1QJsonValue@@QEAA@XZ");
    qjsonobject_insert                 = (QJsonObjectInsertType*) GetProcAddress(qt5core, "?insert@QJsonObject@@QEAA?AViterator@1@AEBVQString@@AEBVQJsonValue@@@Z");
    qjsonobject_constructor            = (QJsonObjectConstructorType*) GetProcAddress(qt5core, "??0QJsonObject@@QEAA@XZ");
    qjsonobject_destructor             = (QJsonObjectDestructorType*) GetProcAddress(qt5core, "??1QJsonObject@@QEAA@XZ");
    qtimer_stop                        = (QTimerStopType*) GetProcAddress(qt5core, "?stop@QTimer@@QEAAXXZ");
    qdatetime_currentmsecsinceepoch    = (QDateTimeCurrentMSecsSinceEpochType*) GetProcAddress(qt5core, "?currentMSecsSinceEpoch@QDateTime@@SA_JXZ");

    crypto_aead_xchacha20poly1305_ietf_decrypt = (CryptoAeadXchacha20poly1305IetfDecryptType*) GetProcAddress(sodium, "crypto_aead_xchacha20poly1305_ietf_decrypt");
    crypto_aead_xchacha20poly1305_ietf_encrypt = (CryptoAeadXchacha20poly1305IetfEncryptType*) GetProcAddress(sodium, "crypto_aead_xchacha20poly1305_ietf_encrypt");

    qbytearray_constructor = (QByteArrayConstructorType*) GetProcAddress(qt5core, "??0QByteArray@@QEAA@PEBDH@Z");
    qbytearray_destructor  = (QByteArrayDestructorType*) GetProcAddress(qt5core, "??1QByteArray@@QEAA@XZ");
    qobject_connectimpl    = (QObjectConnectImplType*) GetProcAddress(qt5core,
                                                                      "?connectImpl@QObject@@CA?AVConnection@QMetaObject@@"
                                                                         "PEBV1@PEAPEAX01PEAVQSlotObjectBase@QtPrivate@@"
                                                                         "W4ConnectionType@Qt@@PEBHPEBU3@@Z");

    qwebsocket_sendbinarymessage = (QWebSocketSendBinaryMessageType*) GetProcAddress(qt5websockets,
                                                                                     "?sendBinaryMessage@QWebSocket@@QEAA_JAEBVQByteArray@@@Z");
    g_binary_msg_signal_fn       = (void*) GetProcAddress(qt5websockets,
                                                          "?binaryMessageReceived@QWebSocket@@QEAAXAEBVQByteArray@@@Z");
    g_qwebsocket_static_meta     = (void*) GetProcAddress(qt5websockets,
                                                          "?staticMetaObject@QWebSocket@@2UQMetaObject@@B");
    qwebsocket_sendtextmessage   = (QWebSocketSendTextMessageType*) GetProcAddress(qt5websockets,
                                                                                   "?sendTextMessage@QWebSocket@@QEAA_JAEBVQString@@@Z");

    return result;
}

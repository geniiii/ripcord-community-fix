static WRITE_DATAGRAM(WriteDatagramHook) {
    // NOTE(geni): Ripcord sends what is likely an old version of this packet
    //             See here: https://discord.com/developers/docs/topics/voice-connections#ip-discovery
    if (size == 70) {
        u32 ssrc         = *((u32*) data);
        data[0]          = 0;
        data[1]          = 1;
        data[2]          = 0;
        data[3]          = 70;
        ((u32*) data)[1] = ssrc;
        return write_datagram(this, data, 74, addr, port);
    }

    return write_datagram(this, data, size, addr, port);
}

static READ_DATAGRAM(ReadDatagramHook) {
    if (size == 74) {
        i64 result = read_datagram(this, data, size, address, port);
        // NOTE(geni): Swap port endianness
        //             I wanted to just put a rol instruction after the movzx that reads it, but there was no space
        if (data[1] == 2 && data[3] == 70) {
            u8 temp  = data[72];
            data[72] = data[73];
            data[73] = temp;
        }
        return result;
    }
    return read_datagram(this, data, size, address, port);
}

enum {
    RTP_PACKET_TYPE_VOICE = 0x78,
};

// NOTE(geni): The current maximum on Discord's side is 200 so we'll be fine
static u64 guilds[512];
static u32 guilds_count;

static UPDATEUSERGUILDPOSITIONS(UpdateUserGuildPositionsHook) {
    Unreferenced(guildPosList);

    RipStmt orderQ;
    RipStmt deleteQ;

    if (comStmts) {
        disdbprepared_begintx(comStmts);
    }
    ripstmt_constructor(&deleteQ, comStmts->db, "\ndelete from user_guild_position\nwhere user_id = ?\n", 0i64);
    ripstmt_bind_u64(&deleteQ, 1, userId.u);
    ripstmt_step(&deleteQ);
    ripstmt_reset(&deleteQ);
    ripstmt_destructor(&deleteQ);
    ripstmt_constructor(
        &orderQ,
        comStmts->db,
        "\nreplace into user_guild_position\n(user_id, guild_id, position)\nvalues (?, ?, ?)\n",
        0i64);
    for (u32 i = 0; i < guilds_count; ++i) {
        ripstmt_bind_u64(&orderQ, 1, userId.u);
        ripstmt_bind_u64(&orderQ, 2, guilds[i]);
        ripstmt_bind_u64(&orderQ, 3, i);
        ripstmt_step(&orderQ);
        ripstmt_reset(&orderQ);
    }
    ripstmt_destructor(&orderQ);
    disdbprepared_endtx(comStmts);
}

static ERF_MAP_FIND(ErfMapFindHook) {
    u8 result = erf_map_find(map, key, key_size, out);

    if (result && key_size == 4 &&
        out->tag == ErfTag_Int32 && memcmp(key, "type", 4) == 0 &&
        out->int32 == DisChannelType_GuildVoiceStage) {
        out->int32 = DisChannelType_GuildVoice;
    } else {
        ErfMapAny new_out = {.tag = ErfTag_Nil};
        // NOTE(geni): We can probably just check return address instead and it would probably be faster
        if (map && key_size == 15 &&
            memcmp(key, "guild_positions", 15) == 0 &&
            erf_map_find(map, "guild_folders", 13, &new_out) &&
            new_out.tag == ErfTag_Arr) {
            ErfArr arr          = new_out.arr;
            ErfMap guild_folder = {0};
            for (i32 i = 0; i < arr.count; ++i) {
                erf_arr_at(&arr, &new_out, i);
                if (new_out.tag != ErfTag_Map) {
                    continue;
                }
                guild_folder = new_out.map;

                if (erf_map_find(&guild_folder, "guild_ids", 9, &new_out) && new_out.tag == ErfTag_Arr) {
                    ErfArr guild_ids = new_out.arr;
                    for (i32 j = 0; j < guild_ids.count; ++j) {
                        erf_arr_at(&guild_ids, &new_out, j);
                        if (new_out.tag == ErfTag_Uint64) {
                            u64 guild_id           = new_out.uint64;
                            guilds[guilds_count++] = guild_id;
                        }
                    }
                }
            }
        }
    }

    return result;
}

// NOTE(geni): Not really necessary at the moment, but we have to prepare for future voice protocol updates
static SEND_SPEAKING_STATE(SendSpeakingStateHook) {
    void* webSocket = this->priv->vlWorker->webSocket;

    QJsonObject root;
    qjsonobject_constructor(&root);

    QJsonValue value;
    QString    key;

    key.d = qstring_from_ascii_helper("op", 2);
    qjsonvalue_constructor_int(&value, 5);

    QJsonObject_iterator it;
    qjsonobject_insert(&root, &it, &key, &value);
    qstring_destructor(&key);
    qjsonvalue_destructor(&value);

    QJsonObject d;
    qjsonobject_constructor(&d);
    qjsonvalue_constructor_int(&value, isSpeaking);
    key.d = qstring_from_ascii_helper("speaking", 8);
    qjsonobject_insert(&d, &it, &key, &value);
    qstring_destructor(&key);

    qjsonvalue_destructor(&value);
    qjsonvalue_constructor_int(&value, 0);
    key.d = qstring_from_ascii_helper("delay", 5);
    qjsonobject_insert(&d, &it, &key, &value);
    qstring_destructor(&key);

    // NOTE(geni): Add SSRC
    qjsonvalue_destructor(&value);
    qjsonvalue_constructor_int(&value, this->priv->vlWorker->ssrc);
    key.d = qstring_from_ascii_helper("ssrc", 4);
    qjsonobject_insert(&d, &it, &key, &value);
    qstring_destructor(&key);

    qjsonvalue_destructor(&value);
    qjsonvalue_constructor_qjsonobject(&value, &d);
    key.d = qstring_from_ascii_helper("d", 1);
    qjsonobject_insert(&root, &it, &key, &value);
    qstring_destructor(&key);

    qjsonvalue_destructor(&value);

    websockethelpers_sendjson(webSocket, qjsonvalue_constructor_qjsonobject(&value, &root));
    qjsonobject_destructor(&d);
    qjsonobject_destructor(&root);
}

static SETVOICEENCSTRINGS(SetVoiceEncStringsHook) {
    // NOTE(geni): Lie about our encryption support to get Ripcord to connect

    // NOTE(geni): From now on, the xsalsa20_poly1305 path is xchacha20_poly1305_rtpsize
    VoiceEncStrings* arr = set_voice_enc_strings(this);
    qstring_set_from_qlatin1string(&arr->xsalsa20_poly1305, QLatin1StringLit("aead_xchacha20_poly1305_rtpsize"));

    // NOTE(geni): I originally added support for this mode but realized it just adds unnecessary complexity
    qstring_set_from_qlatin1string(&arr->xsalsa20_poly1305_suffix, QLatin1StringLit("nope"));
    return arr;
}

void send_voice_data(u32* noncePtr, void* udpSocket, u8* buffer, u32 encMode, u8* secretKey, QString* hostName, u16 port, u32 ssrc, u16* seq, u8* data, u64 dataSize, u32 timestamp) {
    if (!secretKey || !hostName->d->size) {
        return;
    }

    // NOTE(geni): Generate RTP header
    buffer[0] = 0x80;
    buffer[1] = RTP_PACKET_TYPE_VOICE;
    buffer[2] = (*seq) >> 8;
    buffer[3] = (*seq) & 0xFF;
    (*seq)++;

    buffer[4] = (u8) (timestamp >> 24);
    buffer[5] = (u8) (timestamp >> 16);
    buffer[6] = (u8) (timestamp >> 8);
    buffer[7] = timestamp & 0xFF;

    buffer[8]  = (u8) (ssrc >> 24);
    buffer[9]  = (u8) (ssrc >> 16);
    buffer[10] = (u8) (ssrc >> 8);
    buffer[11] = ssrc & 0xFF;

    u64 packet_size;
    switch (encMode) {
        case VoiceEncMode_XChaCha20_Poly1305_RtpSize: {
            u8  nonce[24]   = {0};
            u32 nonce_value = (*noncePtr)++;
            nonce[0]        = (u8) (nonce_value >> 24);
            nonce[1]        = (u8) (nonce_value >> 16);
            nonce[2]        = (u8) (nonce_value >> 8);
            nonce[3]        = nonce_value & 0xFF;

            u64 encrypted_len;
            if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                    buffer + 12, &encrypted_len,
                    data, dataSize,
                    buffer, 12,
                    NULL,
                    nonce, secretKey)) {
                ErrorMessage("Failed to encrypt voice data");
                return;
            }

            packet_size = 12 + encrypted_len + 4;
            memcpy(buffer + 12 + encrypted_len, nonce, 4);
        } break;
        default: {
            ErrorMessage("Unsupported encryption mode");
            return;
        } break;
    }

    QHostAddress addr;
    qhostaddress_constructor_from_qstring(&addr, hostName);
    write_datagram(udpSocket, buffer, packet_size, &addr, port);
    qhostaddress_destructor(&addr);
}

static void EmptyVoicePacketSendHook(DisVLWorker** vlWorkerPtr) {
    DisVLWorker* vlWorker = *vlWorkerPtr;

    // NOTE(geni): Send video op
    if (!vlWorker->emptyVoicePacketsSent) {
        QJsonObject          root;
        QJsonObject          d;
        QJsonObject_iterator iter;
        QJsonValue           value;
        QString              key;

        qjsonobject_constructor(&root);

        qjsonvalue_constructor_int(&value, 12);
        key.d = qstring_from_ascii_helper("op", 2);
        qjsonobject_insert(&root, &iter, &key, &value);
        qstring_destructor(&key);
        qjsonvalue_destructor(&value);

        qjsonobject_constructor(&d);

        qjsonvalue_constructor_int(&value, vlWorker->ssrc);
        key.d = qstring_from_ascii_helper("audio_ssrc", 10);
        qjsonobject_insert(&d, &iter, &key, &value);
        qstring_destructor(&key);
        qjsonvalue_destructor(&value);

        qjsonvalue_constructor_int(&value, 0);
        key.d = qstring_from_ascii_helper("video_ssrc", 10);
        qjsonobject_insert(&d, &iter, &key, &value);
        qstring_destructor(&key);
        qjsonvalue_destructor(&value);

        qjsonvalue_constructor_int(&value, 0);
        key.d = qstring_from_ascii_helper("rtx_ssrc", 8);
        qjsonobject_insert(&d, &iter, &key, &value);
        qstring_destructor(&key);
        qjsonvalue_destructor(&value);

        qjsonvalue_constructor_qjsonobject(&value, &d);
        key.d = qstring_from_ascii_helper("d", 1);
        qjsonobject_insert(&root, &iter, &key, &value);
        qstring_destructor(&key);
        qjsonvalue_destructor(&value);

        websockethelpers_sendjson(vlWorker->webSocket, qjsonvalue_constructor_qjsonobject(&value, &root));
        qjsonobject_destructor(&d);
        qjsonobject_destructor(&root);
    }
    vlWorker->emptyVoicePacketsSent++;

    u8  silence_packet[3] = {0xF8, 0xFF, 0xFE};
    u64 timestamp         = qdatetime_currentmsecsinceepoch();

    send_voice_data(
        &vlWorker->COMMUNITY_FIX_nonce,
        vlWorker->udpSocket,
        vlWorker->sendPacketBuffer,
        vlWorker->encMode,
        vlWorker->secretKey,
        &vlWorker->serverAddress, vlWorker->serverPort,
        vlWorker->ssrc, &vlWorker->sequence,
        silence_packet, 3,
        (u32) timestamp);

    if (vlWorker->emptyVoicePacketsSent >= 6) {
        qtimer_stop(vlWorker->emptyVoicePacketsTimer);
    }
}
static SEND_VOICE_DATAGRAM(SendVoiceDatagramHook) {
    DisVLWorker* vlWorker = this->priv->vlWorker;
    if (!vlWorker || !vlWorker->serverAddress.d->size || !vlWorker->secretKey) {
        return;
    }

    send_voice_data(
        &vlWorker->COMMUNITY_FIX_nonce,
        vlWorker->udpSocket,
        vlWorker->sendPacketBuffer,
        vlWorker->encMode,
        vlWorker->secretKey,
        &vlWorker->serverAddress,
        vlWorker->serverPort,
        vlWorker->ssrc,
        &vlWorker->sequence,
        data,
        dataSize,
        timestamp);
}

static DISVLWORKER_CONSTRUCTOR(DisVLWorkerConstructorHook) {
    disvlworker_constructor(this, parent);
    // NOTE(geni): This takes the space of stolen padding, hence it's usually going to be uninitialized.
    //             The nonce is an incrementing integer, so we have to initialize it
    this->COMMUNITY_FIX_nonce = 0;
    // NOTE(geni): Our implementation doesn't call realloc
    this->sendPacketBuffer     = malloc(2048);
    this->sendPacketBufferSize = 2048;
    return this;
}

static READVOICEDATAPACKET_WITHENCRYPTIONMODE(ReadVoiceDataPacketHook) {
    if (modeSpec == 0 || secretKey == NULL || size <= 0xC) {
        return;
    }
    // NOTE(geni): RTP header bullshit
    u8 has_extension = (data[0] >> 4) & 1;
    u8 csrc_count    = data[0] & 0xF;
    u8 pt            = data[1] & 0x7F;
    if (pt != RTP_PACKET_TYPE_VOICE) {
        ErrorMessage("Invalid RTP packet type");
        return;
    }
    u16 sequence  = data[2] << 8 | data[3];
    u32 timestamp = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    u32 ssrc      = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    // NOTE(geni): Add CSRCs (4 bytes each) + RTP header extension
    u32 rtp_size = 12 + (4 * csrc_count);

    u8  decrypted[4096];
    u64 decrypted_len;
    switch (modeSpec) {
        case VoiceEncMode_XChaCha20_Poly1305_RtpSize: {
            if (size < 36) {
                return;
            }
            // NOTE(geni): Nonce is last 4 bytes
            u8 nonce[24] = {0};
            memcpy(&nonce[0], data + size - 4, 4);

            u32 data_offset = 0;
            if (has_extension) {
                u16 extension_size_in_dwords = (data[rtp_size + 2] << 8) | data[rtp_size + 3];
                data_offset += 4 * extension_size_in_dwords;
                // NOTE(geni): Skip RTP extension header
                rtp_size += 4;
            }

            if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len,
                                                           NULL,
                                                           data + rtp_size, size - rtp_size - 4,
                                                           data, rtp_size,
                                                           nonce, secretKey) != 0) {
                // NOTE(geni): Presumably we actually got xsalsa20_poly1305 somehow... or we messed up
                ErrorMessage("Failed to decrypt voice data");
                return;
            }

            // NOTE(geni): Ripcord expects full first byte instead of just version
            // NOTE(geni): Hardcode "version" to 80 so Ripcord doesn't apply its evil processing to it
            voice_data_append(voiceAccum, decrypted + data_offset, decrypted_len - data_offset, 0x80, sequence, timestamp, ssrc);
        } break;
        default: {
            // NOTE(geni): Just append it as-is for now, since that's what Ripcord originally did lol
            voice_data_append(voiceAccum, data + 12, size - 12, data[0], sequence, timestamp, ssrc);
        } break;
    }
}

static u32 CreateAndEnableHook(u8* base, u64 ptr, void* hook, void** orig) {
    static char buffer[4096];

    MH_STATUS status;
    if ((status = MH_CreateHook(base + ptr, hook, orig)) != MH_OK) {
        sprintf(buffer, "Failed to create hook at 0x%llX\nError code: %d", ptr, status);
        ErrorMessage(buffer);
        return 0;
    }
    if ((status = MH_EnableHook(base + ptr)) != MH_OK) {
        sprintf(buffer, "Failed to enable hook at 0x%llX\nError code: %d", ptr, status);
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

    // NOTE(geni): Fixes image previews not loading. Thanks u130b8!
    PatchString(rip_base, 0x3E63F8, S8Lit("cdn.discordapp.com/\0\0\0"));

    // NOTE(geni): Discard invalid map keys instead of aborting. Thanks @muffinlord on Discord!
    PatchByte(rip_base, 0xB9BBF, 0xEB);
    PatchByte(rip_base, 0xB9BC0, 0x80);

    // NOTE(geni): Disable gateway port splitting
    PatchByte(rip_base, 0xD677E, 0x10);

    HMODULE qt5core    = GetModuleHandleA("Qt5Core.dll");
    HMODULE qt5network = GetModuleHandleA("Qt5Network.dll");
    HMODULE sodium     = GetModuleHandleA("libsodium.dll");

    u64 read_datagram_addr  = (u64) GetProcAddress(qt5network, "?readDatagram@QUdpSocket@@QEAA_JPEAD_JPEAVQHostAddress@@PEAG@Z");
    u64 write_datagram_addr = (u64) GetProcAddress(qt5network, "?writeDatagram@QUdpSocket@@QEAA_JPEBD_JAEBVQHostAddress@@G@Z");

    u32 result = 1;
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

    qstring_set_from_cstring              = (QStringSetFromCStringType*) GetProcAddress(qt5core, "??4QString@@QEAAAEAV0@PEBD@Z");
    qstring_set_from_qlatin1string        = (QStringSetFromQLatin1StringType*) GetProcAddress(qt5core, "??4QString@@QEAAAEAV0@VQLatin1String@@@Z");
    qhostaddress_constructor_from_qstring = (QHostAddressConstructorFromQStringType*) GetProcAddress(qt5network, "??0QHostAddress@@QEAA@AEBVQString@@@Z");
    qhostaddress_destructor               = (QHostAddressDestructorType*) GetProcAddress(qt5network, "??1QHostAddress@@QEAA@XZ");

    qjsonvalue_constructor_bool        = (QJsonValueConstructorBoolType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@_N@Z");
    qjsonvalue_constructor_int         = (QJsonValueConstructorIntType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@H@Z");
    qjsonvalue_constructor_qjsonobject = (QJsonValueConstructorQJsonObjectType*) GetProcAddress(qt5core, "??0QJsonValue@@QEAA@AEBVQJsonObject@@@Z");
    qjsonvalue_destructor              = (QJsonValueDestructorType*) GetProcAddress(qt5core, "??1QJsonValue@@QEAA@XZ");
    qjsonobject_insert                 = (QJsonObjectInsertType*) GetProcAddress(qt5core, "?insert@QJsonObject@@QEAA?AViterator@1@AEBVQString@@AEBVQJsonValue@@@Z");
    qjsonobject_constructor            = (QJsonObjectConstructorType*) GetProcAddress(qt5core, "??0QJsonObject@@QEAA@XZ");
    qjsonobject_destructor             = (QJsonObjectDestructorType*) GetProcAddress(qt5core, "??1QJsonObject@@QEAA@XZ");
    qtimer_stop                        = (QTimerStopType*) GetProcAddress(qt5core, "?stop@QTimer@@QEAAXXZ");
    qdatetime_currentmsecsinceepoch    = (QDateTimeCurrentMSecsSinceEpochType*) GetProcAddress(qt5core, "?currentMSecsSinceEpoch@QDateTime@@SA_JXZ");

    crypto_aead_xchacha20poly1305_ietf_decrypt = (CryptoAeadXchacha20poly1305IetfDecryptType*) GetProcAddress(sodium, "crypto_aead_xchacha20poly1305_ietf_decrypt");
    crypto_aead_xchacha20poly1305_ietf_encrypt = (CryptoAeadXchacha20poly1305IetfEncryptType*) GetProcAddress(sodium, "crypto_aead_xchacha20poly1305_ietf_encrypt");
    crypto_secretbox_easy                      = (CryptoSecretboxEasyType*) GetProcAddress(sodium, "crypto_secretbox_easy");
    crypto_secretbox_open_easy                 = (CryptoSecretboxOpenEasyType*) GetProcAddress(sodium, "crypto_secretbox_open_easy");
    randombytes_buf                            = (RandombytesBufType*) GetProcAddress(sodium, "randombytes_buf");

    return result;
}

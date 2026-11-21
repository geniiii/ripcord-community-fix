static DISVOICEENCODE_CREATEENCODINGCONTEXT(DisVoiceEncodeCreateEncodingContextHook) {
    DisVoiceEncode_EncodingContext* context = disvoiceencode_createencodingcontext(this, forceMusicSignal);
    RtlGenRandom(&context->timestamp, sizeof context->timestamp);
    return context;
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

void SendVoiceData(u32* noncePtr, void* udpSocket, u8* buffer, u32 encMode, u8* secretKey, QString* hostName, u16 port, u32 ssrc, u16* seq, u8* data, u64 dataSize) {
    if (!secretKey || !hostName->d->size) {
        return;
    }

    // NOTE(geni): Ripcord's timestamp stops counting during silence
    //             Instead of using its timestamp at all, we just do 960 per voice packet
    //             and during silence we move the timestamp by actual wall time
    static u32 timestamp;
    static u64 last_send_ms;
    u64        now     = GetTickCount64();
    u64        elapsed = now - last_send_ms;
    timestamp += elapsed > 100 ? (u32) (elapsed * 48) : 960;
    last_send_ms = now;

    // NOTE(geni): Generate RTP header
    buffer[0] = 0x80;
    buffer[1] = RTP_PACKET_TYPE_VOICE;
    buffer[2] = (*seq) >> 8;
    buffer[3] = (*seq) & 0xFF;
    ++(*seq);

    buffer[4] = (u8) (timestamp >> 24);
    buffer[5] = (u8) (timestamp >> 16);
    buffer[6] = (u8) (timestamp >> 8);
    buffer[7] = timestamp & 0xFF;

    buffer[8]  = (u8) (ssrc >> 24);
    buffer[9]  = (u8) (ssrc >> 16);
    buffer[10] = (u8) (ssrc >> 8);
    buffer[11] = ssrc & 0xFF;

    const u8* encrypt_payload = data;
    u64       encrypt_size    = dataSize;
    u8        dave_buf[4096];

    if (g_dave.dave_enabled) {
        size_t                  written = 0;
        DAVEEncryptorResultCode result  = daveEncryptorEncrypt(g_dave.encryptor, DAVE_MEDIA_TYPE_AUDIO, ssrc,
                                                               data, (size_t) dataSize, dave_buf, sizeof dave_buf, &written);
        if (result != DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS) {
            DebugMsg("DAVE encrypt failed: result=%d", result);
            return;
        }
        encrypt_payload = dave_buf;
        encrypt_size    = (u64) written;
    }

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
            i32 result = crypto_aead_xchacha20poly1305_ietf_encrypt(
                buffer + 12, &encrypted_len,
                encrypt_payload, encrypt_size,
                buffer, 12,
                NULL,
                nonce, secretKey);
            if (result) {
                ErrorMessage("Failed to encrypt voice data: result=%d", result);
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
        QJsonObject d;
        qjsonobject_constructor(&d);
        QJsonInsertInt(&d, S8Lit("audio_ssrc"), vlWorker->ssrc);
        QJsonInsertInt(&d, S8Lit("video_ssrc"), 0);
        QJsonInsertInt(&d, S8Lit("rtx_ssrc"), 0);
        SendVoiceOp(vlWorker->webSocket, 12, &d);
    }
    ++vlWorker->emptyVoicePacketsSent;

    u8 silence_packet[3] = {0xF8, 0xFF, 0xFE};

    SendVoiceData(
        &vlWorker->COMMUNITY_FIX_nonce,
        vlWorker->udpSocket,
        vlWorker->sendPacketBuffer,
        vlWorker->encMode,
        vlWorker->secretKey,
        &vlWorker->serverAddress, vlWorker->serverPort,
        vlWorker->ssrc, &vlWorker->sequence,
        silence_packet, 3);

    if (vlWorker->emptyVoicePacketsSent >= 6) {
        qtimer_stop(vlWorker->emptyVoicePacketsTimer);
    }
}
static SEND_VOICE_DATAGRAM(SendVoiceDatagramHook) {
    Unreferenced(timestamp);
    DisVLWorker* vlWorker = this->priv->vlWorker;
    if (!vlWorker || !vlWorker->serverAddress.d->size || !vlWorker->secretKey) {
        return;
    }

    SendVoiceData(
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
        dataSize);
}

static DISVLWORKER_CONSTRUCTOR(DisVLWorkerConstructorHook) {
    disvlworker_constructor(this, parent);
    // NOTE(geni): This takes the space of stolen padding, hence it's usually going to be uninitialized.
    //             The nonce is an incrementing integer, so we have to initialize it
    this->COMMUNITY_FIX_nonce = 0;
    // NOTE(geni): Our implementation doesn't call realloc
    this->sendPacketBuffer     = malloc(2048);
    this->sendPacketBufferSize = 2048;

    // NOTE(geni): Hellspawn
    if (g_binary_msg_signal_fn && qobject_connectimpl) {
        DaveBinarySlotObject* slot = (DaveBinarySlotObject*) malloc(sizeof(DaveBinarySlotObject));
        slot->m_ref                = 1;
        slot->m_impl               = (void*) DaveBinarySlotImpl;

        u8 conn_retval[8];
        qobject_connectimpl(
            conn_retval,
            this->webSocket,
            &g_binary_msg_signal_fn,
            this,
            NULL,
            slot,
            0,
            NULL,
            g_qwebsocket_static_meta);
    }

    return this;
}

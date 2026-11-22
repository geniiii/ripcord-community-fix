static DISVOICEENCODE_CREATEENCODINGCONTEXT(DisVoiceEncode_CreateEncodingContextHook) {
    DisVoiceEncode_EncodingContext* context = DisVoiceEncode_CreateEncodingContext(this, forceMusicSignal);
    RtlGenRandom(&context->timestamp, sizeof context->timestamp);
    return context;
}

static DISCLIENTIMPL_VOICEENCSTRINGS(DisClientImpl_VoiceEncStringsHook) {
    // NOTE(geni): Lie about our encryption support to get Ripcord to connect

    // NOTE(geni): From now on, the xsalsa20_poly1305 path is xchacha20_poly1305_rtpsize
    VoiceEncStrings* arr = DisClientImpl_VoiceEncStrings(this);
    QString_SetFromQLatin1String(&arr->xsalsa20_poly1305, QLatin1StringLit("aead_xchacha20_poly1305_rtpsize"));

    // NOTE(geni): I originally added support for this mode but realized it just adds unnecessary complexity
    QString_SetFromQLatin1String(&arr->xsalsa20_poly1305_suffix, QLatin1StringLit("nope"));
    return arr;
}

void Voice_SendData(u32* noncePtr, void* udpSocket, u8* buffer, u32 encMode, u8* secretKey, QString* hostName, u16 port, u32 ssrc, u16* seq, u8* data, u64 dataSize) {
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
            Log_Debug("DAVE encrypt failed: result=%d", result);
            return;
        }
        encrypt_payload = dave_buf;
        encrypt_size    = (u64) written;
    }

    u64 packet_size;
    switch (encMode) {
        case VoiceEncMode_XChaCha20_Poly1305_RtpSize: {
            u8  nonce[24]   = { 0 };
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
                Log_Error("Failed to encrypt voice data: result=%d", result);
                return;
            }

            packet_size = 12 + encrypted_len + 4;
            memcpy(buffer + 12 + encrypted_len, nonce, 4);
        } break;
        default: {
            Log_Error("Unsupported encryption mode");
            return;
        } break;
    }

    QHostAddress addr;
    QHostAddress_ConstructorQString(&addr, hostName);
    QUdpSocket_WriteDatagram(udpSocket, buffer, packet_size, &addr, port);
    QHostAddress_Destructor(&addr);
}

static void DisVLWorker_SendEmptyVoicePacketsHook(DisVLWorker** vlWorkerPtr) {
    DisVLWorker* vlWorker = *vlWorkerPtr;

    if (!vlWorker->emptyVoicePacketsSent) {
        QJsonObject d;
        QJsonObject_Constructor(&d);
        QJson_InsertInt(&d, S8Lit("audio_ssrc"), vlWorker->ssrc);
        QJson_InsertInt(&d, S8Lit("video_ssrc"), 0);
        QJson_InsertInt(&d, S8Lit("rtx_ssrc"), 0);
        Op_SendVoice(vlWorker->webSocket, VOICE_OP_VIDEO, &d);
    }
    ++vlWorker->emptyVoicePacketsSent;

    u8 silence_packet[3] = { 0xF8, 0xFF, 0xFE };

    Voice_SendData(
        &vlWorker->COMMUNITY_FIX_nonce,
        vlWorker->udpSocket,
        vlWorker->sendPacketBuffer,
        vlWorker->encMode,
        vlWorker->secretKey,
        &vlWorker->serverAddress, vlWorker->serverPort,
        vlWorker->ssrc, &vlWorker->sequence,
        silence_packet, 3);

    if (vlWorker->emptyVoicePacketsSent >= 6) {
        QTimer_Stop(vlWorker->emptyVoicePacketsTimer);
    }
}
static DISVOICELINE_SENDVOICEDATAGRAM(DisVoiceLine_SendVoiceDatagramHook) {
    Unreferenced(timestamp);
    DisVLWorker* vlWorker = this->priv->vlWorker;
    if (!vlWorker || !vlWorker->serverAddress.d->size || !vlWorker->secretKey) {
        return;
    }

    Voice_SendData(
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

static DISVLWORKER_CONSTRUCTOR(DisVLWorker_ConstructorHook) {
    DisVLWorker_Constructor(this, parent);
    // NOTE(geni): This takes the space of stolen padding, hence it's usually going to be uninitialized.
    //             The nonce is an incrementing integer, so we have to initialize it
    this->COMMUNITY_FIX_nonce  = 0;
    // NOTE(geni): Our implementation doesn't call realloc
    this->sendPacketBuffer     = malloc(2048);
    this->sendPacketBufferSize = 2048;

    // NOTE(geni): Hellspawn
    if (g_binary_msg_signal_fn && QObject_ConnectImpl) {
        DaveBinarySlotObject* slot = (DaveBinarySlotObject*) malloc(sizeof(DaveBinarySlotObject));
        slot->m_ref                = 1;
        slot->m_impl               = (void*) Dave_BinarySlotImpl;

        u8 conn_retval[8];
        QObject_ConnectImpl(
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

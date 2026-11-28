static void stream_set_status(stream_state state, const wchar_t* text) {
    g_stream_state = state;
    wcsncpy(g_stream_text, text, ArrayCount(g_stream_text) - 1);
    g_stream_text[ArrayCount(g_stream_text) - 1] = 0;
}

static void stream_fail(const wchar_t* text) {
    stream_set_status(stream_state_failed, text);
    Log_Debug("Go Live failed: %ls", text);
}

// NOTE(Xelph): For aead_aes256_gcm_rtpsize I authenticate the RTP header (the first 8 bytes of an RTCP packet) but don't
//              encrypt it. My nonce is a 32-bit counter in its first 4 bytes, and I append those 4 bytes after the tag
static u8 stream_crypto_init(void) {
    stream_conn* c = &g_stream;
    if (BCryptOpenAlgorithmProvider(&c->alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        return 0;
    }
    if (BCryptSetProperty(c->alg, BCRYPT_CHAINING_MODE, (PUCHAR) BCRYPT_CHAIN_MODE_GCM, sizeof BCRYPT_CHAIN_MODE_GCM, 0) != 0) {
        return 0;
    }
    return BCryptGenerateSymmetricKey(c->alg, &c->bkey, NULL, 0, c->key, sizeof c->key, 0) == 0;
}

static u32 stream_seal(u8* packet, u32 header_len, const u8* payload, u32 payload_size) {
    stream_conn* c = &g_stream;
    if (payload_size == 0 || !c->bkey || header_len + payload_size + stream_tag_size + stream_counter_size > stream_packet_max) {
        return 0;
    }

    u32 counter   = (u32) InterlockedIncrement(&c->nonce) - 1;
    u8  nonce[12] = { 0 };
    memcpy(nonce, &counter, stream_counter_size);
    u8 tag[stream_tag_size];

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce    = nonce;
    info.cbNonce    = sizeof nonce;
    info.pbAuthData = packet;
    info.cbAuthData = header_len;
    info.pbTag      = tag;
    info.cbTag      = sizeof tag;

    ULONG written = 0;
    if (BCryptEncrypt(c->bkey, (PUCHAR) payload, payload_size, &info, NULL, 0, packet + header_len, payload_size, &written, 0) != 0) {
        return 0;
    }
    memcpy(packet + header_len + written, tag, sizeof tag);
    memcpy(packet + header_len + written + sizeof tag, &counter, stream_counter_size);
    return header_len + written + (u32) sizeof tag + stream_counter_size;
}

static u32 stream_open(const u8* data, u32 aad_len, u32 size, u8* out) {
    stream_conn* c = &g_stream;
    if (!c->bkey || size < aad_len + stream_tag_size + stream_counter_size) {
        return 0;
    }
    u32 cipher_len = size - aad_len - stream_tag_size - stream_counter_size;
    u8  nonce[12]  = { 0 };
    memcpy(nonce, data + size - stream_counter_size, stream_counter_size);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce    = nonce;
    info.cbNonce    = sizeof nonce;
    info.pbAuthData = (PUCHAR) data;
    info.cbAuthData = aad_len;
    info.pbTag      = (PUCHAR) (data + aad_len + cipher_len);
    info.cbTag      = stream_tag_size;

    ULONG written = 0;
    if (BCryptDecrypt(c->bkey, (PUCHAR) (data + aad_len), cipher_len, &info, NULL, 0, out, cipher_len, &written, 0) != 0) {
        return 0;
    }
    return written;
}

static u32 stream_rtp_header(u8* buffer, u8 marker, u8 payload_type, u16 sequence, u32 timestamp, u32 ssrc) {
    buffer[0] = 0x80;
    buffer[1] = (u8) ((marker ? 0x80 : 0) | (payload_type & 0x7F));
    WriteU16BE(buffer + 2, sequence);
    WriteU32BE(buffer + 4, timestamp);
    WriteU32BE(buffer + 8, ssrc);
    return 12;
}

// NOTE(Xelph): Token bucket. The stream may send at twice its own bitrate (the extra room is for retransmissions) with a burst
//              allowance of 48 KB. Anything bigger, which in practice means a keyframe, is spread over the following ticks
//              instead of leaving as one burst that a router on the way would drop the end of
static void stream_refill_tokens(void) {
    stream_conn* c   = &g_stream;
    stream_tx*   tx  = &c->tx;
    i64          now = ss_now_us();
    if (tx->pacing_last_us == 0) {
        tx->tokens         = stream_bucket_bytes;
        tx->pacing_last_us = now;
        return;
    }
    double rate = (double) c->info.bitrate * stream_pace_factor / 8.0;
    tx->tokens += (double) (now - tx->pacing_last_us) * rate / 1000000.0;
    if (tx->tokens > stream_bucket_bytes) {
        tx->tokens = stream_bucket_bytes;
    }
    tx->pacing_last_us = now;
}

static void stream_queue_flush(void) {
    stream_tx* tx   = &g_stream.tx;
    tx->queue_head  = 0;
    tx->queue_count = 0;
    tx->queue_bytes = 0;
}

static void stream_pump(void) {
    stream_conn* c  = &g_stream;
    stream_tx*   tx = &c->tx;
    if (c->sock == INVALID_SOCKET || tx->queue_count == 0) {
        return;
    }
    stream_refill_tokens();
    while (tx->queue_count > 0) {
        stream_datagram* front = &tx->queue[tx->queue_head];
        if (tx->tokens < (double) front->size) {
            break;
        }
        tx->tokens -= (double) front->size;
        send(c->sock, (const char*) front->data, (int) front->size, 0);
        tx->queue_bytes -= front->size;
        tx->queue_head = (tx->queue_head + 1) % stream_queue_max;
        --tx->queue_count;
    }
}

static void stream_queue_datagram(const u8* data, u32 size) {
    stream_conn* c  = &g_stream;
    stream_tx*   tx = &c->tx;
    stream_refill_tokens();

    if (tx->queue_count == 0 && tx->tokens >= (double) size) {
        tx->tokens -= (double) size;
        send(c->sock, (const char*) data, (int) size, 0);
        return;
    }
    if (tx->queue_count == stream_queue_max) {
        stream_queue_flush();
    }
    stream_datagram* slot = &tx->queue[(tx->queue_head + tx->queue_count) % stream_queue_max];
    memcpy(slot->data, data, size);
    slot->size = size;
    ++tx->queue_count;
    tx->queue_bytes += size;

    // NOTE(Xelph): Half a second of video waiting means the link can't keep up. Sending it late would only make the picture lag
    //              more, so I drop the backlog and restart from a fresh keyframe
    if (tx->queue_bytes > (u64) (c->info.bitrate / 8 / stream_max_backlog_s)) {
        stream_queue_flush();
        ss_request_key();
    }
}

// One RTP packet carrying `payload` (already DAVE-encrypted when DAVE is on). No RTP header extension: the server drops video that
// carries one that wasn't negotiated. Called with send_lock held
static void stream_send_rtp(const u8* payload, u32 payload_size, u32 timestamp, u8 marker) {
    stream_conn* c  = &g_stream;
    stream_tx*   tx = &c->tx;
    if (payload_size == 0 || payload_size > stream_max_payload + stream_tag_size) {
        return;
    }
    u8  packet[stream_packet_max];
    u16 sequence   = tx->video_sequence++;
    u32 header_len = stream_rtp_header(packet, marker, stream_pt_video, sequence, timestamp, c->video_ssrc);
    u32 size       = stream_seal(packet, header_len, payload, payload_size);
    if (size == 0) {
        return;
    }

    stream_history_entry* entry = &tx->history[sequence % stream_history];
    entry->sequence             = sequence;
    entry->size                 = (u16) payload_size;
    entry->timestamp            = timestamp;
    entry->marker               = marker;
    memcpy(entry->payload, payload, payload_size);
    stream_queue_datagram(packet, size);
}

static void stream_send_nal(const u8* nal, u32 length, u32 timestamp, u8 last_nal) {
    if (length == 0) {
        return;
    }
    if (length <= stream_max_payload) {
        stream_send_rtp(nal, length, timestamp, last_nal);
        return;
    }

    // NOTE(Xelph): FU-A (RFC 6184): a one-byte indicator, a one-byte header with the start and end bits, then a slice of the NAL
    u8  indicator = (u8) ((nal[0] & 0xE0) | 28);
    u8  type      = nal[0] & 0x1F;
    u32 offset    = 1;
    u8  first     = 1;
    u8  fragment[stream_max_payload];
    while (offset < length) {
        u32 chunk = length - offset;
        if (chunk > stream_max_payload - 2) {
            chunk = stream_max_payload - 2;
        }
        u8 last_fragment = offset + chunk >= length;
        fragment[0]      = indicator;
        fragment[1]      = (u8) ((first ? 0x80 : 0) | (last_fragment ? 0x40 : 0) | type);
        memcpy(fragment + 2, nal + offset, chunk);
        stream_send_rtp(fragment, chunk + 2, timestamp, last_nal && last_fragment);
        offset += chunk;
        first = 0;
    }
}

// Splits an Annex B buffer into its NALs and sends each one
static void stream_send_annex_b(const u8* data, u32 length, u32 timestamp) {
    u32 starts[64];
    u32 start_lengths[64];
    u32 count = 0;
    for (u32 i = 0; i + 3 <= length && count < ArrayCount(starts); ++i) {
        if (data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1) {
            starts[count]        = i + 3;
            start_lengths[count] = i > 0 && data[i - 1] == 0 ? 4 : 3;
            ++count;
            i += 2;
        }
    }
    if (count == 0) {
        stream_send_nal(data, length, timestamp, 1);
        return;
    }
    for (u32 n = 0; n < count; ++n) {
        u32 end = n + 1 < count ? starts[n + 1] - start_lengths[n + 1] : length;
        while (end > starts[n] && data[end - 1] == 0) {
            --end;
        }
        stream_send_nal(data + starts[n], end - starts[n], timestamp, n + 1 == count);
    }
}

static void stream_send_frame(const u8* data, u32 size, u32 rtp_timestamp) {
    stream_conn* c = &g_stream;
    if (!InterlockedCompareExchange(&c->ready, 0, 0) || c->sock == INVALID_SOCKET || !data || size == 0) {
        return;
    }

    EnterCriticalSection(&g_stream_send_lock);
    const u8* frame        = data;
    u32       frame_length = size;
    if (c->dave.use_dave) {
        // NOTE(Xelph): DAVE encrypts the whole access unit (it knows to leave NAL headers and parameter sets readable) and the
        //              NALs are split out of the encrypted frame afterwards
        EnterCriticalSection(&g_stream_dave_lock);
        size_t capacity = c->dave.encryptor ? daveEncryptorGetMaxCiphertextByteSize(c->dave.encryptor, DAVE_MEDIA_TYPE_VIDEO, size) : 0;
        u8*    cipher   = capacity && daveEncryptorHasKeyRatchet(c->dave.encryptor) ? (u8*) ss_scratch_push(capacity) : NULL;
        size_t written  = 0;
        if (cipher &&
            daveEncryptorEncrypt(c->dave.encryptor, DAVE_MEDIA_TYPE_VIDEO, c->video_ssrc, data, size, cipher, capacity, &written) ==
                DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS) {
            frame        = cipher;
            frame_length = (u32) written;
        } else {
            frame_length = 0;
        }
        LeaveCriticalSection(&g_stream_dave_lock);
    }
    if (frame_length) {
        stream_send_annex_b(frame, frame_length, rtp_timestamp);
        stream_pump();
    }
    LeaveCriticalSection(&g_stream_send_lock);
}

static void stream_resend_packet(u16 sequence) {
    stream_conn*          c     = &g_stream;
    stream_tx*            tx    = &c->tx;
    stream_history_entry* entry = &tx->history[sequence % stream_history];
    if (entry->sequence != sequence || entry->size == 0) {
        return;
    }

    // NOTE(Xelph): Retransmissions share the link with the stream: a fifth of its bitrate at most, so a viewer on a bad
    //              connection can't turn NACKs into a flood
    i64 now = ss_now_us();
    if (now - tx->rtx_window_start_us >= 1000000) {
        tx->rtx_window_start_us = now;
        tx->rtx_window_bytes    = 0;
    }
    if (tx->rtx_window_bytes + entry->size > c->info.bitrate / 8 / stream_rtx_share) {
        return;
    }
    tx->rtx_window_bytes += entry->size;

    // RFC 4588: the original sequence number first, then the original payload, on the RTX stream
    u8 rtx[stream_max_payload + stream_tag_size + 2];
    WriteU16BE(rtx, sequence);
    memcpy(rtx + 2, entry->payload, entry->size);

    u8  packet[stream_packet_max];
    u32 header_len = stream_rtp_header(packet, entry->marker, stream_pt_rtx, tx->rtx_sequence, entry->timestamp, c->rtx_ssrc);
    u32 size       = stream_seal(packet, header_len, rtx, entry->size + 2u);
    if (size) {
        ++tx->rtx_sequence;
        stream_queue_datagram(packet, size);
    }
}

static void stream_on_nack(const u8* data, u32 size) {
    u8  plain[stream_packet_max];
    u32 plain_length = stream_open(data, rtcp_min_size, size, plain);
    if (plain_length < rtcp_min_size) {
        return;
    }
    EnterCriticalSection(&g_stream_send_lock);
    const u8* entries = plain + 4;
    for (u32 i = 0; i < (plain_length - 4) / 4; ++i) {
        u16 first   = ReadU16BE(entries + i * 4);
        u16 bitmask = ReadU16BE(entries + i * 4 + 2);
        stream_resend_packet(first);
        for (u32 bit = 0; bit < 16; ++bit) {
            if (bitmask & (1u << bit)) {
                stream_resend_packet((u16) (first + bit + 1));
            }
        }
    }
    stream_pump();
    LeaveCriticalSection(&g_stream_send_lock);
}

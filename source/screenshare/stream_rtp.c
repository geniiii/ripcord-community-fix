static void stream_set_status(stream_state state, const wchar_t* text) {
    g_stream_state = state;
    wcsncpy(g_stream_text, text, ArrayCount(g_stream_text) - 1);
    g_stream_text[ArrayCount(g_stream_text) - 1] = 0;
}

static void stream_fail(const wchar_t* text) {
    stream_set_status(stream_state_failed, text);
    Log_Debug("Go Live failed: %ls", text);
}

static i64 stream_now_us(void) {
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (i64) ((double) now.QuadPart * 1000000.0 / (double) freq.QuadPart);
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
    if (payload_size == 0 || !c->bkey || header_len + payload_size + 16 + 4 > stream_packet_max) {
        return 0;
    }

    u32 counter   = (u32) InterlockedIncrement(&c->nonce) - 1;
    u8  nonce[12] = { 0 };
    memcpy(nonce, &counter, 4);
    u8 tag[16];

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
    memcpy(packet + header_len + written + sizeof tag, &counter, 4);
    return header_len + written + (u32) sizeof tag + 4;
}

static u32 stream_open(const u8* data, u32 aad_len, u32 size, u8* out) {
    stream_conn* c = &g_stream;
    if (!c->bkey || size < aad_len + 16 + 4) {
        return 0;
    }
    u32 cipher_len = size - aad_len - 16 - 4;
    u8  nonce[12]  = { 0 };
    memcpy(nonce, data + size - 4, 4);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce    = nonce;
    info.cbNonce    = sizeof nonce;
    info.pbAuthData = (PUCHAR) data;
    info.cbAuthData = aad_len;
    info.pbTag      = (PUCHAR) (data + aad_len + cipher_len);
    info.cbTag      = 16;

    ULONG written = 0;
    if (BCryptDecrypt(c->bkey, (PUCHAR) (data + aad_len), cipher_len, &info, NULL, 0, out, cipher_len, &written, 0) != 0) {
        return 0;
    }
    return written;
}

static u32 stream_rtp_header(u8* buffer, u8 marker, u8 payload_type, u16 sequence, u32 timestamp, u32 ssrc) {
    buffer[0]  = 0x80;
    buffer[1]  = (u8) ((marker ? 0x80 : 0) | (payload_type & 0x7F));
    buffer[2]  = (u8) (sequence >> 8);
    buffer[3]  = (u8) (sequence & 0xFF);
    buffer[4]  = (u8) (timestamp >> 24);
    buffer[5]  = (u8) (timestamp >> 16);
    buffer[6]  = (u8) (timestamp >> 8);
    buffer[7]  = (u8) (timestamp & 0xFF);
    buffer[8]  = (u8) (ssrc >> 24);
    buffer[9]  = (u8) (ssrc >> 16);
    buffer[10] = (u8) (ssrc >> 8);
    buffer[11] = (u8) (ssrc & 0xFF);
    return 12;
}
// Token bucket. The stream may send at twice its own bitrate (the extra room is for retransmissions), with a burst
// allowance of 48 KB. Anything bigger, which in practice means a keyframe, is spread over the following ticks
// instead of leaving as one burst that a router on the way would drop the end of
static void stream_refill_tokens(void) {
    stream_conn* c           = &g_stream;
    const double bucket_size = 48.0 * 1024.0;
    i64          now         = stream_now_us();
    if (c->pacing_last_us == 0) {
        c->tokens         = bucket_size;
        c->pacing_last_us = now;
        return;
    }
    double rate = (double) c->bitrate * 2.0 / 8.0;
    c->tokens += (double) (now - c->pacing_last_us) * rate / 1000000.0;
    if (c->tokens > bucket_size) {
        c->tokens = bucket_size;
    }
    c->pacing_last_us = now;
}

static void stream_queue_flush(void) {
    stream_conn* c = &g_stream;
    for (u32 i = 0; i < c->queue_count; ++i) {
        free(c->queue[(c->queue_head + i) % stream_queue_max].data);
    }
    c->queue_head  = 0;
    c->queue_count = 0;
    c->queue_bytes = 0;
}
static void stream_pump(void) {
    stream_conn* c = &g_stream;
    if (c->sock == INVALID_SOCKET || c->queue_count == 0) {
        return;
    }
    stream_refill_tokens();
    while (c->queue_count > 0) {
        stream_datagram* front = &c->queue[c->queue_head];
        if (c->tokens < (double) front->size) {
            break;
        }
        c->tokens -= (double) front->size;
        send(c->sock, (const char*) front->data, (int) front->size, 0);
        c->queue_bytes -= front->size;
        free(front->data);
        front->data   = NULL;
        c->queue_head = (c->queue_head + 1) % stream_queue_max;
        --c->queue_count;
    }
}
static void stream_queue_datagram(const u8* data, u32 size) {
    stream_conn* c = &g_stream;
    stream_refill_tokens();

    if (c->queue_count == 0 && c->tokens >= (double) size) {
        c->tokens -= (double) size;
        send(c->sock, (const char*) data, (int) size, 0);
        return;
    }
    if (c->queue_count == stream_queue_max) {
        stream_queue_flush();
    }
    u8* copy = (u8*) malloc(size);
    if (!copy) {
        return;
    }
    memcpy(copy, data, size);
    u32 slot            = (c->queue_head + c->queue_count) % stream_queue_max;
    c->queue[slot].data = copy;
    c->queue[slot].size = size;
    ++c->queue_count;
    c->queue_bytes += size;

    // Half a second of video waiting means the link can't keep up. Sending it late would only make the picture lag
    // more: drop the backlog and restart from a fresh keyframe
    if (c->queue_bytes > (u64) (c->bitrate / 8 / 2)) {
        stream_queue_flush();
        ss_request_key();
    }
}

// One RTP packet carrying `payload` (already DAVE-encrypted when DAVE is on). No RTP header extension: the server
// drops video that carries one that wasn't negotiated. Called with send_lock held
static void stream_send_rtp(const u8* payload, u32 payload_size, u32 timestamp, u8 marker) {
    stream_conn* c = &g_stream;
    if (payload_size == 0) {
        return;
    }
    u16 sequence   = c->video_sequence++;
    u32 header_len = stream_rtp_header(c->packet, marker, stream_pt_video, sequence, timestamp, c->video_ssrc);
    u32 size       = stream_seal(c->packet, header_len, payload, payload_size);
    if (size == 0) {
        return;
    }

    stream_history_entry* entry = &c->history[sequence % stream_history];
    free(entry->payload);
    entry->payload = (u8*) malloc(payload_size);
    if (entry->payload) {
        memcpy(entry->payload, payload, payload_size);
        entry->size      = payload_size;
        entry->sequence  = sequence;
        entry->timestamp = timestamp;
        entry->marker    = marker;
    } else {
        entry->size = 0;
    }
    stream_queue_datagram(c->packet, size);
}
static void stream_send_nal(const u8* nal, u32 length, u32 timestamp, u8 last_nal) {
    if (length == 0) {
        return;
    }
    if (length <= stream_max_payload) {
        stream_send_rtp(nal, length, timestamp, last_nal);
        return;
    }

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

typedef struct {
    const u8* data;
    u32       length;
} stream_nal;

static u8 stream_find_start_code(const u8* data, u32 length, u32 from, u32* position, u32* start_length) {
    for (u32 i = from; i + 3 <= length; ++i) {
        if (data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1) {
            *position     = i;
            *start_length = 3;
            return 1;
        }
        if (i + 4 <= length && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 0 && data[i + 3] == 1) {
            *position     = i;
            *start_length = 4;
            return 1;
        }
    }
    return 0;
}

static u32 stream_collect_nals(const u8* data, u32 length, stream_nal* out, u32 max) {
    u32 count = 0, position = 0, start_length = 0;
    if (!stream_find_start_code(data, length, 0, &position, &start_length)) {
        return 0;
    }
    for (;;) {
        u32 nal_start = position + start_length;
        u32 next = length, next_length = 0;
        u8  has_next = stream_find_start_code(data, length, nal_start, &next, &next_length);
        u32 nal_end  = has_next ? next : length;
        while (nal_end > nal_start && data[nal_end - 1] == 0) {
            --nal_end;
        }
        if (nal_end > nal_start && count < max) {
            out[count].data   = data + nal_start;
            out[count].length = nal_end - nal_start;
            ++count;
        }
        if (!has_next) {
            break;
        }
        position     = next;
        start_length = next_length;
    }
    return count;
}
static void stream_send_frame(const u8* data, u32 size, u32 rtp_timestamp) {
    stream_conn* c = &g_stream;
    if (!InterlockedCompareExchange(&c->ready, 0, 0) || c->sock == INVALID_SOCKET || !data || size == 0) {
        return;
    }

    EnterCriticalSection(&g_stream_send_lock);
    const u8* frame        = data;
    u32       frame_length = size;

    if (c->use_dave) {
        // DAVE encrypts the whole access unit (it knows to leave NAL headers and parameter sets readable) and the
        // NALs are split out of the encrypted frame afterwards
        EnterCriticalSection(&g_stream_dave_lock);
        if (!c->encryptor || !daveEncryptorHasKeyRatchet(c->encryptor)) {
            LeaveCriticalSection(&g_stream_dave_lock);
            LeaveCriticalSection(&g_stream_send_lock);
            return;
        }
        size_t capacity = daveEncryptorGetMaxCiphertextByteSize(c->encryptor, DAVE_MEDIA_TYPE_VIDEO, size);
        ss_bytes_reserve(&c->dave_out, (u32) capacity);
        size_t                  written = 0;
        DAVEEncryptorResultCode result  = daveEncryptorEncrypt(c->encryptor, DAVE_MEDIA_TYPE_VIDEO, c->video_ssrc, data, size,
                                                               c->dave_out.data, c->dave_out.capacity, &written);
        LeaveCriticalSection(&g_stream_dave_lock);
        if (result != DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS || written == 0) {
            LeaveCriticalSection(&g_stream_send_lock);
            return;
        }
        frame        = c->dave_out.data;
        frame_length = (u32) written;
    }

    stream_nal  nals_stack[64];
    stream_nal* nals  = nals_stack;
    u32         count = stream_collect_nals(frame, frame_length, nals, ArrayCount(nals_stack));
    if (count == 0) {
        nals_stack[0].data   = frame;
        nals_stack[0].length = frame_length;
        count                = 1;
    }
    for (u32 i = 0; i < count; ++i) {
        stream_send_nal(nals[i].data, nals[i].length, rtp_timestamp, i + 1 == count);
    }
    stream_pump();
    LeaveCriticalSection(&g_stream_send_lock);
}

static void stream_resend_packet(u16 sequence) {
    stream_conn*          c     = &g_stream;
    stream_history_entry* entry = &c->history[sequence % stream_history];
    if (!entry->payload || entry->sequence != sequence || entry->size == 0) {
        return;
    }

    // Retransmissions share the link with the stream: a fifth of its bitrate at most, so a viewer on a bad
    // connection can't turn NACKs into a flood
    i64 now = stream_now_us();
    if (now - c->rtx_window_start_us >= 1000000) {
        c->rtx_window_start_us = now;
        c->rtx_window_bytes    = 0;
    }
    if (c->rtx_window_bytes + entry->size > c->bitrate / 8 / 5) {
        return;
    }
    c->rtx_window_bytes += entry->size;

    // RFC 4588: the original sequence number first, then the original payload, on the RTX stream
    u8* rtx = (u8*) malloc(entry->size + 2);
    if (!rtx) {
        return;
    }
    rtx[0] = (u8) (sequence >> 8);
    rtx[1] = (u8) (sequence & 0xFF);
    memcpy(rtx + 2, entry->payload, entry->size);

    u32 header_len = stream_rtp_header(c->packet, entry->marker, stream_pt_rtx, c->rtx_sequence, entry->timestamp, c->rtx_ssrc);
    u32 size       = stream_seal(c->packet, header_len, rtx, entry->size + 2);
    free(rtx);
    if (size == 0) {
        return;
    }
    ++c->rtx_sequence;
    stream_queue_datagram(c->packet, size);
}

static void stream_on_nack(const u8* data, u32 size) {
    u8  plain[stream_packet_max];
    u32 plain_length = stream_open(data, 8, size, plain);
    if (plain_length < 8) {
        return;
    }
    EnterCriticalSection(&g_stream_send_lock);
    const u8* entries     = plain + 4;
    u32       entry_count = (plain_length - 4) / 4;
    for (u32 i = 0; i < entry_count; ++i) {
        u16 first   = (u16) ((entries[i * 4] << 8) | entries[i * 4 + 1]);
        u16 bitmask = (u16) ((entries[i * 4 + 2] << 8) | entries[i * 4 + 3]);
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

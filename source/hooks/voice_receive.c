#define RTP_HEADER_SIZE           12
#define RTP_CSRC_SIZE             4
#define RTP_EXTENSION_HEADER_SIZE 4
#define RTP_NONCE_SIZE            4
#define RTP_CSRC_COUNT_MASK       0b00001111
#define RTP_EXTENSION_BIT         0b00010000
#define RTP_PAYLOAD_TYPE_MASK     0b01111111

static DISCLIENTIMPL_READVOICEDATAPACKET(DisClientImpl_ReadVoiceDataPacketHook) {
    if (modeSpec == 0 || secretKey == NULL || size < RTP_HEADER_SIZE) {
        return;
    }

    if ((data[1] & RTP_PAYLOAD_TYPE_MASK) != RTP_PACKET_TYPE_VOICE) {
        Log_Error("Invalid RTP packet type");
        return;
    }
    u16 sequence  = ReadU16BE(data + 2);
    u32 timestamp = ReadU32BE(data + 4);
    u32 ssrc      = ReadU32BE(data + 8);

    switch (modeSpec) {
        case VoiceEncMode_XChaCha20_Poly1305_RtpSize: {
            u64 csrc_count = data[0] & RTP_CSRC_COUNT_MASK;
            // NOTE(geni): Add CSRCs (4 bytes each) + RTP header extension
            u64 header_size    = RTP_HEADER_SIZE + csrc_count * RTP_CSRC_SIZE;
            u64 extension_size = 0;
            if (data[0] & RTP_EXTENSION_BIT) {
                if (size < header_size + RTP_EXTENSION_HEADER_SIZE) {
                    return;
                }
                u16 extension_dwords = ReadU16BE(data + header_size + 2);
                extension_size       = extension_dwords * 4;
                // NOTE(geni): Skip RTP extension header
                header_size += RTP_EXTENSION_HEADER_SIZE;
            }

            if (size < header_size + crypto_aead_xchacha20poly1305_ietf_ABYTES + RTP_NONCE_SIZE) {
                return;
            }
            u8* ciphertext     = data + header_size;
            u64 ciphertext_len = size - header_size - RTP_NONCE_SIZE;

            u8  decrypted[4096];
            u64 decrypted_len;
            if (ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES > sizeof decrypted) {
                return;
            }

            // NOTE(geni): Nonce is last 4 bytes
            u8 nonce[24] = {0};
            memcpy(nonce, ciphertext + ciphertext_len, RTP_NONCE_SIZE);
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL,
                                                           ciphertext, ciphertext_len,
                                                           data, header_size,
                                                           nonce, secretKey) != 0) {
                // NOTE(geni): Presumably we actually got xsalsa20_poly1305 somehow... or we messed up
                Log_Error("Failed to decrypt voice data");
                return;
            }
            if (decrypted_len < extension_size) {
                return;
            }

            u8* payload     = decrypted + extension_size;
            u64 payload_len = decrypted_len - extension_size;

            // NOTE(geni): Silence frames are not DAVE-encrypted
            u8 is_silence = payload_len == 3 && payload[0] == 0xF8 && payload[1] == 0xFF && payload[2] == 0xFE;
            // NOTE(geni): Try to avoid passing DAVE frames to Opus.
            //			   I don't know if this can ever really happen, but it would blow up users' ears
            u8 is_dave_frame = payload_len >= 2 && ReadU16BE(payload + payload_len - 2) == DAVE_MAGIC_BYTES;
            u8 passthrough   = !g_dave.dave_enabled || g_dave.pending_protocol_version == 0;
            if (is_silence || (passthrough && !is_dave_frame)) {
                // NOTE(geni): Ripcord expects full first byte instead of just version
                // NOTE(geni): Hardcode "version" to 80 so Ripcord doesn't apply its evil processing to it
                VoiceDatasAccum_Append(voiceAccum, payload, payload_len, 0x80, sequence, timestamp, ssrc);
                break;
            }

            u8                      dave_plain[4096];
            size_t                  written = 0;
            DAVEDecryptorResultCode result  = DAVE_DECRYPTOR_RESULT_CODE_DECRYPTION_FAILURE;
            DAVEDecryptorHandle     dec     = Dave_GetDecryptor(ssrc);
            if (dec) {
                result = daveDecryptorDecrypt(dec, DAVE_MEDIA_TYPE_AUDIO, payload, (size_t) payload_len,
                                              dave_plain, sizeof dave_plain, &written);
            }
            if (result == DAVE_DECRYPTOR_RESULT_CODE_SUCCESS) {
                VoiceDatasAccum_Append(voiceAccum, dave_plain, (u64) written, 0x80, sequence, timestamp, ssrc);
            }
        } break;
        default: {
            // NOTE(geni): Just append it as-is for now, since that's what Ripcord originally did lol
            VoiceDatasAccum_Append(voiceAccum, data + RTP_HEADER_SIZE, size - RTP_HEADER_SIZE, data[0], sequence, timestamp, ssrc);
        } break;
    }
}

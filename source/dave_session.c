static void DaveReset(void) {
    if (g_dave.session) {
        daveSessionDestroy(g_dave.session);
    }
    if (g_dave.encryptor) {
        daveEncryptorDestroy(g_dave.encryptor);
    }
    for (u32 i = 0; i < g_dave.decryptor_count; ++i) {
        if (g_dave.decryptors[i].decryptor) {
            daveDecryptorDestroy(g_dave.decryptors[i].decryptor);
        }
    }
    memset(&g_dave, 0, sizeof(g_dave));
    g_dave.pending_transition_id = -1;
    g_dave.last_seq              = -1;
}

static void DaveCompleteTransition(void) {
    if (!g_dave.pending_transition_ready) {
        return;
    }
    g_dave.pending_transition_ready = 0;

    char uid_buf[32];

    if (!g_dave.session || !g_dave.encryptor) {
        return;
    }

    if (g_dave.local_ssrc) {
        daveEncryptorAssignSsrcToCodec(g_dave.encryptor, g_dave.local_ssrc, DAVE_CODEC_OPUS);
    }

    String8 uid_str      = S8FromU64(g_dave.user_id, uid_buf, sizeof(uid_buf));
    void*   self_ratchet = daveSessionGetKeyRatchet(g_dave.session, uid_str.cstr);
    if (self_ratchet) {
        daveEncryptorSetKeyRatchet(g_dave.encryptor, self_ratchet);
        daveKeyRatchetDestroy(self_ratchet);
    }

    // NOTE(geni): Refresh existing decryptors
    for (u32 i = 0; i < g_dave.decryptor_count; ++i) {
        u64 uid = g_dave.decryptors[i].userId;
        if (uid == 0) {
            continue;
        }
        uid_str       = S8FromU64(uid, uid_buf, sizeof(uid_buf));
        void* ratchet = daveSessionGetKeyRatchet(g_dave.session, uid_str.cstr);
        if (ratchet) {
            daveDecryptorTransitionToKeyRatchet(g_dave.decryptors[i].decryptor, ratchet);
            daveKeyRatchetDestroy(ratchet);
        }
    }

    if (!g_dave.dave_enabled) {
        g_dave.dave_enabled    = 1;
        g_dave.dave_downgraded = 0;
        DebugMsg("DAVE encryption enabled");
    }

    g_dave.pending_transition_id = -1;
}

static void DaveReinit(void) {
    if (!g_dave.session) {
        return;
    }

    g_dave.dave_enabled    = 0;
    g_dave.dave_downgraded = 0;

    char    uid_buf[32];
    String8 uid_str = S8FromU64(g_dave.user_id, uid_buf, sizeof(uid_buf));
    daveSessionInit(g_dave.session, g_dave.protocol_version, g_dave.channel_id, uid_str.cstr);

    // NOTE(geni): Send key package
    u8*    pkg      = NULL;
    size_t pkg_size = 0;
    daveSessionGetMarshalledKeyPackage(g_dave.session, &pkg, &pkg_size);
    if (pkg && pkg_size > 0) {
        DaveSendBinary(g_dave.webSocket, DAVE_MLS_KEY_PACKAGE, pkg, pkg_size);
        daveFree(pkg);
    }

    for (u32 i = 0; i < g_dave.decryptor_count; ++i) {
        if (g_dave.decryptors[i].decryptor) {
            daveDecryptorDestroy(g_dave.decryptors[i].decryptor);
        }
    }
    g_dave.decryptor_count = 0;

    if (g_dave.encryptor) {
        daveEncryptorDestroy(g_dave.encryptor);
    }
    g_dave.encryptor = daveEncryptorCreate();
    if (g_dave.local_ssrc) {
        daveEncryptorAssignSsrcToCodec(g_dave.encryptor, g_dave.local_ssrc, DAVE_CODEC_OPUS);
    }
}

static void DaveInit(u16 version) {
    g_dave.protocol_version         = version;
    g_dave.pending_protocol_version = version;

    if (!g_dave.session) {
        g_dave.session = daveSessionCreate(NULL, NULL, NULL, NULL);
    }

    DaveReinit();
}

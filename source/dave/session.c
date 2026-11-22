static void Dave_Reset(void) {
    Dave_DestroyDecryptors();
    if (g_dave.session) {
        daveSessionDestroy(g_dave.session);
    }
    if (g_dave.encryptor) {
        daveEncryptorDestroy(g_dave.encryptor);
    }
    g_dave = (DaveState) {
        .last_seq  = -1,
        .session   = daveSessionCreate(NULL, NULL, NULL, NULL),
        .encryptor = daveEncryptorCreate(),
    };
}

static void Dave_ExecuteTransition(void) {
    g_dave.pending_transition_id = 0;
    if (g_dave.pending_protocol_version == 0) {
        daveSessionReset(g_dave.session);
        g_dave.dave_enabled = 0;
        return;
    }

    // NOTE(geni): NULL until a commit/welcome is processed, e.g. when we're alone in the call
    DAVEKeyRatchetHandle self_ratchet = Dave_GetRatchet(g_dave.user_id);
    if (!self_ratchet) {
        g_dave.dave_enabled = 0;
        return;
    }
    daveEncryptorSetKeyRatchet(g_dave.encryptor, self_ratchet);
    daveKeyRatchetDestroy(self_ratchet);
    g_dave.dave_enabled = 1;
}

static void Dave_PrepareTransition(u16 transition_id, u16 protocol_version) {
    g_dave.pending_protocol_version = protocol_version;
    Dave_RefreshDecryptors();
    if (transition_id == 0) {
        Dave_ExecuteTransition();
        return;
    }
    g_dave.pending_transition_id = transition_id;
    Dave_SendTransitionOp(VOICE_OP_READY_FOR_TRANSITION, transition_id);
}

static void Dave_Init(u16 version) {
    g_dave.dave_enabled             = 0;
    g_dave.pending_protocol_version = version;
    g_dave.pending_transition_id    = 0;

    char buf[32];
    daveSessionInit(g_dave.session, version, g_dave.channel_id, S8_FromU64(g_dave.user_id, buf, sizeof buf).cstr);

    u8*    pkg      = NULL;
    size_t pkg_size = 0;
    daveSessionGetMarshalledKeyPackage(g_dave.session, &pkg, &pkg_size);
    if (pkg && pkg_size > 0) {
        Dave_SendBinary(DAVE_MLS_KEY_PACKAGE, pkg, pkg_size);
        daveFree(pkg);
    }

    Dave_DestroyDecryptors();
}

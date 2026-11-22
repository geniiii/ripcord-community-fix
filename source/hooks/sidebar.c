static void Sidebar_HideGuildChannel(DisDbPrepared* stmts, u64 channel_id) {
    static const char* const sqls[] = {
        "update guild_channel set deleted = 2 where deleted = 0 and id = ?",
        "update guild_voice_channel set deleted = 2 where deleted = 0 and id = ?",
        "update guild_channel_category set deleted = 2 where deleted = 0 and id = ?",
    };
    for (u32 i = 0; i < ArrayCount(sqls); ++i) {
        Db_ExecU64(stmts, sqls[i], channel_id);
    }
}

static void Sidebar_HideGuildChannels(DisDbPrepared* stmts, u64 guild_id) {
    static const char* const sqls[] = {
        "update guild_channel set deleted = 2 where deleted = 0 and guild_id = ?",
        "update guild_voice_channel set deleted = 2 where deleted = 0 and guild_id = ?",
        "update guild_channel_category set deleted = 2 where deleted = 0 and guild_id = ?",
    };
    for (u32 i = 0; i < ArrayCount(sqls); ++i) {
        Db_ExecU64(stmts, sqls[i], guild_id);
    }
}

static DISDB_UPDATEADDGUILDCHANNELJSON(DisDb_UpdateAddGuildChannelJsonHook) {
    DisDb_UpdateAddGuildChannelJson(comStmts, chanMap, guildId);

    // NOTE(geni): Mark hidden channels with deleted = 2, which conveniently already filters them out from the sidebar for us.
    //             We use 2 as the hidden flag in order to later unhide channels when we get a channel update that removes the obfuscated flag
    if (Erf_GetU64(chanMap, S8Lit("flags"), 0) & DiscordChannelFlag_Obfuscated) {
        Sidebar_HideGuildChannel(comStmts, Erf_GetFlake(chanMap, S8Lit("id"), 0));
    }
}

//~ Resync

// NOTE(geni): We just ask for every guild channel lol
static void Sidebar_SendResync(DisSessionWorker* w, u64 guild_id) {
    QJsonArray ids;
    QJsonArray_Constructor(&ids);
    Db_QueryFlakes(&ids, w->common_stmts,
                   "select id from guild_channel where guild_id = ?1 and deleted != 1\n"
                   "union all select id from guild_voice_channel where guild_id = ?1 and deleted != 1\n"
                   "union all select id from guild_channel_category where guild_id = ?1 and deleted != 1",
                   DISCORD_MAX_GUILD_CHANNELS, guild_id);

    QJsonObject d;
    QJsonObject_Constructor(&d);
    QJson_InsertFlake(&d, S8Lit("guild_id"), guild_id);
    QJson_InsertArray(&d, S8Lit("obfuscated_channel_ids"), &ids);
    QJsonArray_Destructor(&ids);

    Op_Send(WebSocketHelpers_SendJsonAsEtf, w->web_socket, GATEWAY_OP_RESYNC_GUILD_CHANNELS, &d);
}

static void Sidebar_ApplyChannelSync(DisSessionWorker* w, ErfMap* data) {
    FlakeId guild_id = {
        .u = Erf_GetFlake(data, S8Lit("guild_id"), 0),
    };
    ErfMapAny channels;
    if (!Erf_GetOfType(data, S8Lit("channels"), ErfTag_Arr, &channels)) {
        return;
    }

    // NOTE(geni): Hide everything and have Ripcord replace the channel rows (hence clearing the deleted column)
    DisDbPrepared_BeginTx(w->common_stmts);
    Sidebar_HideGuildChannels(w->common_stmts, guild_id.u);
    for (i32 i = 0; i < channels.arr.count; ++i) {
        ErfMapAny channel;
        ErfArr_At(&channels.arr, &channel, i);
        DisDb_UpdateAddGuildChannelJsonHook(w->common_stmts, &channel.map, guild_id);
    }
    DisDbPrepared_EndTx(w->common_stmts);

    ChgsRef chgs;
    ChgsRef_Constructor(&chgs);
    DisChange_AddChange(chgs.dis_changes, DisChangeType_ChannelUpdated);
    DisClientImpl_SendAnyChgs(w, &chgs);
}

static u32 Sidebar_IsOwnMemberUpdate(DisSessionWorker* w, ErfMap* data) {
    ErfMapAny user;
    return Erf_GetOfType(data, S8Lit("user"), ErfTag_Map, &user) &&
           Erf_GetFlake(&user.map, S8Lit("id"), 0) == w->own_user_id.u;
}

static u32 Sidebar_IsOwnRoleUpdate(DisSessionWorker* w, u64 guild_id, ErfMap* data) {
    ErfMapAny role;
    if (!Erf_GetOfType(data, S8Lit("role"), ErfTag_Map, &role)) {
        return 0;
    }
    u64 role_id = Erf_GetFlake(&role.map, S8Lit("id"), 0);
    if (role_id == guild_id) {
        return 1;
    }

    return Db_ExecU64(w->common_stmts, "select 1 from guild_member_role where user_id = ? and role_id = ?",
                      w->own_user_id.u, role_id);
}

// NOTE(geni): Gaining or losing access through roles doesn't send us any channels, so ask for them again
static DISCLIENTIMPL_PROCESSGATEWAYMESSAGE(DisClientImpl_ProcessGatewayMessageHook) {
    DisClientImpl_ProcessGatewayMessage(w, root_map);

    ErfMapAny t, d;
    if (!Erf_GetOfType(root_map, S8Lit("t"), ErfTag_Str, &t) || !Erf_GetOfType(root_map, S8Lit("d"), ErfTag_Map, &d)) {
        return;
    }

    u64 guild_id = Erf_GetFlake(&d.map, S8Lit("guild_id"), 0);
    switch (DisClientImpl_EventNameToEnum(&t.str)) {
        // NOTE(geni): Ripcord obviously doesn't map CHANNEL_SYNC for us
        case GatewayEvent_Unknown: {
            String8 event = {
                .cstr = t.str.data,
                .size = (u64) t.str.length,
            };
            if (S8_Equals(event, S8Lit("CHANNEL_SYNC"))) {
                Sidebar_ApplyChannelSync(w, &d.map);
            }
        } break;

        // NOTE(geni): Role changes can show or hide channels too, so we resync
        case GatewayEvent_GuildRoleUpdate: {
            if (Sidebar_IsOwnRoleUpdate(w, guild_id, &d.map)) {
                Sidebar_SendResync(w, guild_id);
            }
        } break;
        case GatewayEvent_GuildRoleDelete: {
            Sidebar_SendResync(w, guild_id);
        } break;
        case GatewayEvent_GuildMemberUpdate: {
            if (Sidebar_IsOwnMemberUpdate(w, &d.map)) {
                Sidebar_SendResync(w, guild_id);
            }
        } break;
    }
}

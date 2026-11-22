static u64 g_guilds[DISCORD_MAX_GUILDS * 2];
static u32 g_guild_count;

static DISDB_UPDATEUSERGUILDPOSITIONS(DisDb_UpdateUserGuildPositionsHook) {
    Unreferenced(guildPosList);

    if (!comStmts) {
        return;
    }
    DisDbPrepared_BeginTx(comStmts);
    Db_ExecU64(comStmts, "delete from user_guild_position where user_id = ?", userId.u);

    RipStmt orderQ;
    Db_Prepare(&orderQ, comStmts, "replace into user_guild_position (user_id, guild_id, position) values (?, ?, ?)");
    for (u32 i = 0; i < g_guild_count; ++i) {
        Db_RunU64(&orderQ, userId.u, g_guilds[i], i);
    }
    RipStmt_Destructor(&orderQ);
    DisDbPrepared_EndTx(comStmts);
}

static void Guilds_PatchChannelType(ErfMapAny* type) {
    if (type->tag == ErfTag_Int32 && type->int32 == DisChannelType_GuildVoiceStage) {
        type->int32 = DisChannelType_GuildVoice;
    }
}

static void Guilds_LoadFolderOrder(ErfMap* user_settings_map) {
    ErfMapAny new_out = {
        .tag = ErfTag_Nil,
    };
    if (!ErfMap_Find(user_settings_map, "guild_folders", 13, &new_out) || new_out.tag != ErfTag_Arr) {
        return;
    }

    ErfArr arr          = new_out.arr;
    ErfMap guild_folder = { 0 };
    g_guild_count       = 0;
    for (i32 i = 0; i < arr.count; ++i) {
        ErfArr_At(&arr, &new_out, i);
        if (new_out.tag != ErfTag_Map) {
            continue;
        }
        guild_folder = new_out.map;

        if (ErfMap_Find(&guild_folder, "guild_ids", 9, &new_out) && new_out.tag == ErfTag_Arr) {
            ErfArr guild_ids = new_out.arr;
            for (i32 j = 0; j < guild_ids.count; ++j) {
                ErfArr_At(&guild_ids, &new_out, j);
                if (new_out.tag == ErfTag_Uint64 && g_guild_count < ArrayCount(g_guilds)) {
                    u64 guild_id              = new_out.uint64;
                    g_guilds[g_guild_count++] = guild_id;
                }
            }
        }
    }
}

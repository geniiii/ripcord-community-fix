// NOTE(geni): The current maximum on Discord's side is 200 so we'll be fine
static u64 guilds[512];
static u32 guilds_count;

static UPDATEUSERGUILDPOSITIONS(UpdateUserGuildPositionsHook) {
    Unreferenced(guildPosList);

    RipStmt orderQ;
    RipStmt deleteQ;

    if (!comStmts) {
        return;
    }
    disdbprepared_begintx(comStmts);
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
    u8      result = erf_map_find(map, key, key_size, out);
    String8 key_s8 = {
        .s    = (u8*) key,
        .size = key_size,
    };

    if (!result) {
        return result;
    }

    if (S8Equals(key_s8, S8Lit("type")) &&
        out->tag == ErfTag_Int32 && out->int32 == DisChannelType_GuildVoiceStage) {
        out->int32 = DisChannelType_GuildVoice;
        return result;
    }

    ErfMapAny new_out = {
        .tag = ErfTag_Nil,
    };
    // NOTE(geni): We can probably just check return address instead and it would probably be faster
    if (map && S8Equals(key_s8, S8Lit("guild_positions")) &&
        erf_map_find(map, "guild_folders", 13, &new_out) &&
        new_out.tag == ErfTag_Arr) {
        ErfArr arr          = new_out.arr;
        ErfMap guild_folder = {0};
        guilds_count        = 0;
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
                    if (new_out.tag == ErfTag_Uint64 && guilds_count < ArrayCount(guilds)) {
                        u64 guild_id           = new_out.uint64;
                        guilds[guilds_count++] = guild_id;
                    }
                }
            }
        }
    }

    return result;
}

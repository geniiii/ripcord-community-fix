static ErfStr Users_GlobalName(ErfMap* user) {
    ErfStr global_name = Erf_GetStr(user, S8Lit("global_name"));
    ErfStr username    = Erf_GetStr(user, S8Lit("username"));
    if (global_name.length == username.length && memcmp(global_name.data, username.data, username.length) == 0) {
        return (ErfStr) { 0 };
    }
    return global_name;
}

static u8 Users_FindNick(ErfMap* member, ErfMapAny* out, u8 found) {
    if (out->tag == ErfTag_Str) {
        return found;
    }

    ErfMap user        = Erf_GetMap(member, S8Lit("user"));
    ErfStr global_name = Users_GlobalName(&user);
    if (global_name.length == 0) {
        return found;
    }

    out->tag = ErfTag_Str;
    out->str = global_name;
    return 1;
}

static DISDB_UPDATEWITHCHANNELMESSAGE(DisDb_UpdateWithChannelMessageHook) {
    DisDb_UpdateWithChannelMessage(comStmts, map);

    ErfMap author = Erf_GetMap(map, S8Lit("author"));
    if (author.count == 0) {
        return;
    }

    ErfMap member = Erf_GetMap(map, S8Lit("member"));
    ErfStr nick   = Erf_GetStr(&member, S8Lit("nick"));
    if (nick.length == 0) {
        nick = Users_GlobalName(&author);
    }

    FlakeId author_id = {
        .u = Erf_GetFlake(&author, S8Lit("id"), 0),
    };
    FlakeId channel_id = {
        .u = Erf_GetFlake(map, S8Lit("channel_id"), 0),
    };
    DisDbPrepared_SetUserAsGuildMemberInChannel(comStmts, author_id, channel_id);

    RipStmt stmt;
    Db_Prepare(&stmt, comStmts,
               "update guild_member\n"
               "set nick = ?4\n"
               "where user_id = ?1\n"
               "and guild_id = (select guild_id from guild_channel where id = ?2)\n"
               "and (?3 or nick is null or nick = '')\n");
    Db_BindU64(&stmt, author_id.u, channel_id.u, member.count != 0);
    RipStmt_BindStr(&stmt, 4, &nick);
    RipStmt_Step(&stmt);
    RipStmt_Destructor(&stmt);
}

static DISCACHE_USERDISCRIMWITHHASH(DisCache_UserDiscrimWithHashHook) {
    Unreferenced(user_id);
    result->d = QString_FromAsciiHelper("", 0);
    return result;
}

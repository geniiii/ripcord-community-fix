static ERFMAP_FIND(ErfMap_FindHook) {
    u8      result = ErfMap_Find(map, key, key_size, out);
    String8 key_s8 = {
        .s    = (u8*) key,
        .size = key_size,
    };

    if (S8_Equals(key_s8, S8Lit("nick"))) {
        return Users_FindNick(map, out, result);
    }
    if (!result) {
        return result;
    }

    if (S8_Equals(key_s8, S8Lit("type"))) {
        Guilds_PatchChannelType(out);
    } else if (S8_Equals(key_s8, S8Lit("guild_positions"))) {
        // NOTE(geni): We can probably just check return address instead and it would probably be faster
        Guilds_LoadFolderOrder(map);
    }

    return result;
}

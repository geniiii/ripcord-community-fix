global funchook_t* funchook;

WRITE_DATAGRAM(_ZN10QUdpSocket13writeDatagramEPKcxRK12QHostAddresst) {
    if (!write_datagram) {
        write_datagram = dlsym(RTLD_NEXT, "_ZN10QUdpSocket13writeDatagramEPKcxRK12QHostAddresst");
    }

    // NOTE(geni): Ripcord sends what is likely an old version of this packet, which *only some* Discord servers seem to respond to.
    //             See here: https://discord.com/developers/docs/topics/voice-connections#ip-discovery
    if (size == 70) {
        u32 ssrc         = *((u32*) data);
        data[0]          = 0;
        data[1]          = 1;
        data[2]          = 0;
        data[3]          = 70;
        ((u32*) data)[1] = ssrc;
        return write_datagram(this, data, 74, addr, port);
    }

    return write_datagram(this, data, size, addr, port);
}

static READ_VOICE_DATA_PACKET(ReadVoiceDataPacketHook) {
    read_voice_data_packet(accum, a2, a3, a4, a5);

    if (accum == NULL || accum->some_voice_data_array == NULL) {
        return;
    }

    DisVoiceDatagram* dg = &accum->some_voice_data_array[-1].datagram;
    if (dg->dataSize >= 4 && dg->data[0] == 0xBE && dg->data[1] == 0xDE) {
        u16 size_in_dwords = dg->data[3] | dg->data[2] << 8;
        u64 extension_size = 4 + 4 * (u64) size_in_dwords;
        if (dg->dataSize >= extension_size) {
            dg->data += extension_size;
            dg->dataSize -= extension_size;
        }
    }
}

// NOTE(geni): The current maximum on Discord's side is 200 so we'll be fine
static u64 guilds[512];
static u32 guilds_count;

static UPDATEUSERGUILDPOSITIONS(UpdateUserGuildPositionsHook) {
    Unreferenced(guildPosList);

    RipStmt orderQ;
    RipStmt deleteQ;

    if (comStmts) {
        disdbprepared_begintx(comStmts);
    }
    ripstmt_constructor(&deleteQ, comStmts->db, "\ndelete from user_guild_position\nwhere user_id = ?\n", 0);
    ripstmt_bind_u64(&deleteQ, 1, userId.u);
    ripstmt_step(&deleteQ);
    ripstmt_reset(&deleteQ);
    ripstmt_destructor(&deleteQ);
    ripstmt_constructor(
        &orderQ,
        comStmts->db,
        "\nreplace into user_guild_position\n(user_id, guild_id, position)\nvalues (?, ?, ?)\n",
        0);
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

// NOTE(geni): Linux version inlines this everywhere...
static ErfMapAny* ErfArrAt(ErfArr* this, ErfMapAny* result, i32 i) {
    ErfCell* cells = (ErfCell*) this->addr;
    ErfCell* cell  = &cells[i];

    result->tag = cell->any.t;
    switch (cell->any.t) {
        case ErfTag_Bool: {
            result->uint64 = cell->boolean.v;
        } break;
        case ErfTag_Int32: {
            result->uint64 = (u32) cell->int32.v;
        } break;
        case ErfTag_Int64:
        case ErfTag_Uint64:
        case ErfTag_Float64: {
            result->uint64 = cell->uint64.v;
        } break;
        case ErfTag_Str: {
            result->str.data   = cell->str.data;
            result->str.length = cell->str.size;
        } break;
        case ErfTag_Arr: {
            result->arr.addr  = (u8*) cell + cell->arr.valsOffset;
            result->arr.count = (i32) cell->arr.count;
        } break;
        case ErfTag_Map: {
            result->map.addr  = (u8*) cell + cell->map.keysOffset;
            result->map.count = (i32) cell->map.count;
        } break;
        default: {
            result->uint64 = 0;
        } break;
    }

    return result;
}

static ERF_MAP_FIND(ErfMapFindHook) {
    u8      result = erf_map_find(map, key, key_size, out);
    String8 key_s8 = {
        .s    = (u8*) key,
        .size = key_size,
    };

    if (result && S8Equals(key_s8, S8Lit("type")) &&
        out->tag == ErfTag_Int32 && out->int32 == DisChannelType_GuildVoiceStage) {
        out->int32 = DisChannelType_GuildVoice;
    } else {
        ErfMapAny new_out = {.tag = ErfTag_Nil};
        // NOTE(geni): We can probably just check return address instead and it would probably be faster
        if (map && S8Equals(key_s8, S8Lit("guild_positions")) &&
            erf_map_find(map, "guild_folders", 13, &new_out) &&
            new_out.tag == ErfTag_Arr) {
            ErfArr arr          = new_out.arr;
            ErfMap guild_folder = {0};
            guilds_count        = 0;
            for (i32 i = 0; i < arr.count; ++i) {
                ErfArrAt(&arr, &new_out, i);
                if (new_out.tag != ErfTag_Map) {
                    continue;
                }
                guild_folder = new_out.map;
                if (erf_map_find(&guild_folder, "guild_ids", 9, &new_out) && new_out.tag == ErfTag_Arr) {
                    ErfArr guild_ids = new_out.arr;
                    for (i32 j = 0; j < guild_ids.count; ++j) {
                        ErfArrAt(&guild_ids, &new_out, j);
                        if (new_out.tag == ErfTag_Uint64 && guilds_count < ArrayCount(guilds)) {
                            u64 guild_id           = new_out.uint64;
                            guilds[guilds_count++] = guild_id;
                        }
                    }
                }
            }
        }
    }

    return result;
}

// NOTE(geni): List size limit + 1
//             Maps can be larger than this, but they're flagged
//             by setting the least-significant bit and hence take a different path
#define DEDFRAME_TUPLE_FLAG 0x8000000
static DED_STEP(DedStepHook) {
    if (s->index != 255) {
        DedFrame frame = s->frames[s->index];
        // NOTE(geni): Take tuple path instead of list path to avoid skipping NIL_EXT on accident.
        //             See Ded::step in IDA if confused
        if (frame == DEDFRAME_TUPLE_FLAG) {
            ++s->index;
            result->event.type = DedEventType_ListEnd;
            result->type       = DedResultType_Event;
            return result;
        }

        // NOTE(geni): Original Ded::step logic
        if (frame < 2) {
            return ded_step(result, s);
        }
    }

    u64 term_size = s->length;
    u8* term_data = s->data;
    // NOTE(geni): The dreaded-by-packers ETF type 104/'h' (SMALL_TUPLE_EXT)
    if (term_size == 0 || *term_data != DedETFTerm_SmallTuple) {
        return ded_step(result, s);
    }

    // NOTE(geni): This is done at the top of Ded::step, which means
    //             we have to move it down here to avoid decrementing twice
    if (s->index != 255) {
        DedFrame frame = s->frames[s->index];
        s->frames[s->index] =
            (DedFrame) ((frame & 1) | (2 * (frame >> 1) - 2));
    }

    if (term_size < 2) {
        result->error.type = DedErrorType_EndedUnexpectedly;
        result->type       = DedResultType_Error;
        return result;
    }

    u8 arity = term_data[1];
    if (s->index == 0) {
        result->error.type = DedErrorType_ExceededSizeLimit;
        result->type       = DedResultType_Error;
        return result;
    }
    result->event.type    = DedEventType_ListStart;
    s->frames[--s->index] = DEDFRAME_TUPLE_FLAG | (2 * arity);

    result->event.int64 = arity;
    result->type        = DedResultType_Event;

    s->data += 2;
    s->length -= 2;

    return result;
}

static u32 CreateAndEnableHook(u8* base, u64 ptr, void* hook, void** orig) {
    *orig = base + ptr;

    i32 status = funchook_prepare(funchook, orig, hook);
    if (status != 0) {
        ErrorMsg("Failed to prepare hook at 0x%lX\nError code: %d (%s)", ptr, status, funchook_error_message(funchook));
        return 0;
    }

    return 1;
}

static void Unprotect(u8* addr, u64 size) {
    u64 page_size = (u64) sysconf(_SC_PAGE_SIZE);
    u8* start     = (u8*) ((u64) addr & ~(page_size - 1));
    u64 length    = (u64) ((addr + size) - start);
    if (mprotect(start, length, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        ErrorMsg("mprotect failed for %p (%lu bytes)", (void*) addr, size);
    }
}

static void PatchByte(u8* base, u64 ptr, u8 new) {
    u8* addr = base + ptr;
    Unprotect(addr, 1);
    *addr = new;
}

static void PatchString(u8* base, u64 ptr, String8 new) {
    u8* addr = base + ptr;
    Unprotect(addr, new.size);
    memcpy(addr, new.data, new.size);
}

static u32 LoadHooks(void) {
    u8* base = (u8*) RIPCORD_IMAGE_BASE;

    for (u32 i = 0; i < sizeof SUPPORTED_VERSION; ++i) {
        if (base[0x4CF4F3 + i] != SUPPORTED_VERSION[i]) {
            ErrorMsg("Unsupported Ripcord version (expected " SUPPORTED_VERSION ")");
            return 0;
        }
    }

    // NOTE(geni): Patch IP discovery packet sizes
    u64 receive_udp = 0x155870;
    PatchByte(base, receive_udp + 0x102, 74);
    PatchByte(base, receive_udp + 0x110, 8);
    PatchByte(base, receive_udp + 0x172, 72);

    // NOTE(geni): Discard invalid map keys instead of aborting. Thanks @muffinlord and @literally_saksham on Discord!
    u64 from_etf_v = 0x123DD0;
    PatchByte(base, from_etf_v + 0x3AD + 0, 0xE9);
    PatchByte(base, from_etf_v + 0x3AD + 1, 0xEE);
    PatchByte(base, from_etf_v + 0x3AD + 2, 0xFE);
    PatchByte(base, from_etf_v + 0x3AD + 3, 0xFF);
    PatchByte(base, from_etf_v + 0x3AD + 4, 0xFF);

    // NOTE(geni): Disable gateway port splitting
    u64 openvlconnwebsocket = 0x1547B0;
    PatchByte(base, openvlconnwebsocket + 0x17, 0x10);

    // NOTE(geni): Fix image previews. Thanks @u130b8!
    PatchString(base, 0x4E997D, S8Lit("cdn.discordapp.com/\0\0\0"));

    DebugMsg("Patched bytes\n");

    funchook = funchook_create();
    if (!funchook) {
        ErrorMsg("Failed to create funchook");
        return 0;
    }

    u32 result = 1;
    result &= CreateAndEnableHook(base, 0x1557B0, ReadVoiceDataPacketHook, (void**) &read_voice_data_packet);
    result &= CreateAndEnableHook(base, 0x1216B0, ErfMapFindHook, (void**) &erf_map_find);
    result &= CreateAndEnableHook(base, 0x179F00, UpdateUserGuildPositionsHook, (void**) &update_user_guild_positions);
    result &= CreateAndEnableHook(base, 0x121270, DedStepHook, (void**) &ded_step);
    if (!result) {
        return 0;
    }

    ripstmt_constructor   = (RipStmtConstructorType*) (base + 0x5B350);
    ripstmt_destructor    = (RipStmtDestructorType*) (base + 0x5B450);
    ripstmt_bind_u64      = (RipStmtBindU64Type*) (base + 0x5B4D0);
    ripstmt_step          = (RipStmtStepType*) (base + 0x5B590);
    ripstmt_reset         = (RipStmtResetType*) (base + 0x5B920);
    disdbprepared_begintx = (DisDbPreparedBegintxType*) (base + 0x175E90);
    disdbprepared_endtx   = (DisDbPreparedEndtxType*) (base + 0x175EC0);

    i32 status = funchook_install(funchook, 0);
    if (status != 0) {
        ErrorMsg("Failed to install hooks\nError code: %d (%s)", status, funchook_error_message(funchook));
        return 0;
    }

    DebugMsg("Installed hooks\n");
    return 1;
}

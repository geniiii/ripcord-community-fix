typedef struct {
    String8    src;
    jsmntok_t* tok;
    i32        count;
} Json;

static Json Json_Parse(String8 src, jsmntok_t* tok, u32 max) {
    jsmn_parser parser;
    jsmn_init(&parser);

    i32 count = jsmn_parse(&parser, src.cstr, src.size, tok, max);
    if (count < 0) {
        count = 0;
    }
    return (Json) {
        .src   = src,
        .tok   = tok,
        .count = count,
    };
}

static String8 Json_TokenStr(Json* j, i32 idx) {
    jsmntok_t* t = &j->tok[idx];
    return (String8) {
        .s    = j->src.s + t->start,
        .size = (u64) (t->end - t->start),
    };
}

static i32 Json_SkipValue(Json* j, i32 idx) {
    i32 end  = j->tok[idx].end;
    i32 next = idx + 1;
    while (next < j->count && j->tok[next].start < end) {
        ++next;
    }
    return next;
}

static i32 Json_Find(Json* j, i32 obj, String8 key) {
    if (obj < 0 || j->tok[obj].type != JSMN_OBJECT) {
        return -1;
    }

    i32 key_idx = obj + 1;
    for (i32 pair = 0; pair < j->tok[obj].size; ++pair) {
        i32 value_idx = key_idx + 1;
        if (value_idx >= j->count) {
            return -1;
        }
        if (S8_Equals(Json_TokenStr(j, key_idx), key)) {
            return value_idx;
        }
        key_idx = Json_SkipValue(j, value_idx);
    }
    return -1;
}

static i32 Json_FindOfType(Json* j, i32 obj, String8 key, jsmntype_t type) {
    i32 idx = Json_Find(j, obj, key);
    if (idx < 0 || j->tok[idx].type != type) {
        return -1;
    }
    return idx;
}

static i32 Json_GetI32(Json* j, i32 obj, String8 key, i32 def) {
    i32 idx = Json_FindOfType(j, obj, key, JSMN_PRIMITIVE);
    i32 value;
    if (idx < 0 || !S8_ParseI32(Json_TokenStr(j, idx), &value)) {
        return def;
    }
    return value;
}

static u32 Json_GetU32(Json* j, i32 obj, String8 key, u32 def) {
    i32 idx = Json_FindOfType(j, obj, key, JSMN_PRIMITIVE);
    u32 value;
    if (idx < 0 || !S8_ParseU32(Json_TokenStr(j, idx), &value)) {
        return def;
    }
    return value;
}

static u32 Json_ParseU64At(Json* j, i32 idx, u64* out) {
    jsmntype_t type = j->tok[idx].type;
    if (type != JSMN_PRIMITIVE && type != JSMN_STRING) {
        return 0;
    }
    return S8_ParseU64(Json_TokenStr(j, idx), out);
}

static u64 Json_GetU64(Json* j, i32 obj, String8 key, u64 def) {
    i32 idx = Json_Find(j, obj, key);
    u64 value;
    if (idx < 0 || !Json_ParseU64At(j, idx, &value)) {
        return def;
    }
    return value;
}

static u32 Json_GetU64Array(Json* j, i32 obj, String8 key, u64* out, u32 max) {
    i32 arr = Json_FindOfType(j, obj, key, JSMN_ARRAY);
    if (arr < 0) {
        return 0;
    }

    u32 n        = 0;
    i32 elem_idx = arr + 1;
    for (i32 i = 0; i < j->tok[arr].size && n < max; ++i) {
        if (Json_ParseU64At(j, elem_idx, &out[n])) {
            ++n;
        }
        elem_idx = Json_SkipValue(j, elem_idx);
    }
    return n;
}

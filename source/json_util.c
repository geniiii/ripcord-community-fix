typedef struct {
    String8    src;
    jsmntok_t* tok;
    i32        count;
} Json;

static Json JsonParse(String8 src, jsmntok_t* tok, u32 max) {
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

static String8 JsonStr(Json* j, i32 idx) {
    jsmntok_t* t = &j->tok[idx];
    return (String8) {
        .s    = j->src.s + t->start,
        .size = (u64) (t->end - t->start),
    };
}

static i32 JsonSkipValue(Json* j, i32 idx) {
    i32 end  = j->tok[idx].end;
    i32 next = idx + 1;
    while (next < j->count && j->tok[next].start < end) {
        ++next;
    }
    return next;
}

static i32 JsonGet(Json* j, i32 obj, String8 key) {
    if (obj < 0 || j->tok[obj].type != JSMN_OBJECT) {
        return -1;
    }

    i32 key_idx = obj + 1;
    for (i32 pair = 0; pair < j->tok[obj].size; ++pair) {
        i32 value_idx = key_idx + 1;
        if (value_idx >= j->count) {
            return -1;
        }
        if (S8Equals(JsonStr(j, key_idx), key)) {
            return value_idx;
        }
        key_idx = JsonSkipValue(j, value_idx);
    }
    return -1;
}

static i32 JsonGetOfType(Json* j, i32 obj, String8 key, jsmntype_t type) {
    i32 idx = JsonGet(j, obj, key);
    if (idx < 0 || j->tok[idx].type != type) {
        return -1;
    }
    return idx;
}

static i32 JsonArrayAt(Json* j, i32 arr, i32 n) {
    if (arr < 0 || j->tok[arr].type != JSMN_ARRAY) {
        return -1;
    }
    if (n < 0 || n >= j->tok[arr].size) {
        return -1;
    }

    i32 elem_idx = arr + 1;
    for (i32 i = 0; i < n; ++i) {
        elem_idx = JsonSkipValue(j, elem_idx);
    }
    return elem_idx;
}

static u32 JsonBool(Json* j, i32 obj, String8 key, u32 def) {
    i32 idx = JsonGetOfType(j, obj, key, JSMN_PRIMITIVE);
    if (idx < 0) {
        return def;
    }

    String8 text = JsonStr(j, idx);
    if (S8Equals(text, S8Lit("true"))) {
        return 1;
    }
    if (S8Equals(text, S8Lit("false"))) {
        return 0;
    }
    return def;
}

static i32 JsonI32(Json* j, i32 obj, String8 key, i32 def) {
    i32 idx = JsonGetOfType(j, obj, key, JSMN_PRIMITIVE);
    i32 value;
    if (idx < 0 || !S8ParseI32(JsonStr(j, idx), &value)) {
        return def;
    }
    return value;
}

static u32 JsonU32(Json* j, i32 obj, String8 key, u32 def) {
    i32 idx = JsonGetOfType(j, obj, key, JSMN_PRIMITIVE);
    u32 value;
    if (idx < 0 || !S8ParseU32(JsonStr(j, idx), &value)) {
        return def;
    }
    return value;
}

static u32 JsonParseU64At(Json* j, i32 idx, u64* out) {
    jsmntype_t type = j->tok[idx].type;
    if (type != JSMN_PRIMITIVE && type != JSMN_STRING) {
        return 0;
    }
    return S8ParseU64(JsonStr(j, idx), out);
}

static u64 JsonU64(Json* j, i32 obj, String8 key, u64 def) {
    i32 idx = JsonGet(j, obj, key);
    u64 value;
    if (idx < 0 || !JsonParseU64At(j, idx, &value)) {
        return def;
    }
    return value;
}

static u32 JsonU64Array(Json* j, i32 obj, String8 key, u64* out, u32 max) {
    i32 arr = JsonGetOfType(j, obj, key, JSMN_ARRAY);
    if (arr < 0) {
        return 0;
    }

    u32 n        = 0;
    i32 elem_idx = arr + 1;
    for (i32 i = 0; i < j->tok[arr].size && n < max; ++i) {
        if (JsonParseU64At(j, elem_idx, &out[n])) {
            ++n;
        }
        elem_idx = JsonSkipValue(j, elem_idx);
    }
    return n;
}

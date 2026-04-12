static void ErrorMessage(const char* fmt, ...) {
    char    buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    MessageBoxA(0, buf, "Audio Hook Failure", MB_ICONERROR);
}

static void DebugMsg(const char* fmt, ...) {
    char    buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    OutputDebugStringA(buf);
    fprintf(stderr, "%s", buf);
}

static u32 JsmnEq(const char* json, const jsmntok_t* tok, String8 s) {
    i32 len = tok->end - tok->start;
    return tok->type == JSMN_STRING && (i32) s.size == len &&
           memcmp(json + tok->start, s.data, (u64) len) == 0;
}

static u32 JsmnSkip(const jsmntok_t* tokens, u32 idx) {
    i32 n = tokens[idx++].size;
    switch (tokens[idx - 1].type) {
        case JSMN_OBJECT: {
            for (i32 i = 0; i < n; ++i) {
                ++idx;
                idx = JsmnSkip(tokens, idx);
            }
        } break;
        case JSMN_ARRAY: {
            for (i32 i = 0; i < n; ++i) {
                idx = JsmnSkip(tokens, idx);
            }
        } break;
    }
    return idx;
}

static i32 JsmnFind(const char* json, const jsmntok_t* tokens, u32 count, i32 obj, String8 key) {
    if (obj < 0 || tokens[obj].type != JSMN_OBJECT) {
        return -1;
    }

    u32 idx = (u32) (obj + 1);
    for (i32 i = 0; i < tokens[obj].size; ++i) {
        if (idx + 1 >= count) {
            return -1;
        }

        if (JsmnEq(json, &tokens[idx], key)) {
            return (i32) (idx + 1);
        }

        ++idx;
        idx = JsmnSkip(tokens, idx);
    }

    return -1;
}

static i32 JsmnInt(const char* json, const jsmntok_t* tokens, u32 count, i32 obj, String8 key, i32 def) {
    i32 vi = JsmnFind(json, tokens, count, obj, key);
    if (vi < 0 || tokens[vi].type != JSMN_PRIMITIVE) {
        return def;
    }

    const char* s      = json + tokens[vi].start;
    i32         len    = tokens[vi].end - tokens[vi].start;
    u32         neg    = 0;
    i32         result = 0;
    u32         i      = 0;
    if ((i32) i < len && s[i] == '-') {
        neg = 1;
        ++i;
    }

    while ((i32) i < len && s[i] >= '0' && s[i] <= '9') {
        result = result * 10 + (s[i++] - '0');
    }
    return neg ? -result : result;
}

static String8 JsmnStr(const char* json, const jsmntok_t* tokens, u32 count, i32 obj, String8 key, char* buf, u32 bufsize) {
    i32 vi = JsmnFind(json, tokens, count, obj, key);
    if (vi < 0 || tokens[vi].type != JSMN_STRING) {
        buf[0] = 0;
        return (String8) {0};
    }

    i32 len = tokens[vi].end - tokens[vi].start;
    if (len >= (i32) bufsize) {
        len = (i32) bufsize - 1;
    }

    memcpy(buf, json + tokens[vi].start, (u64) len);
    buf[len] = 0;

    return (String8) {(u8*) buf, (u64) len};
}

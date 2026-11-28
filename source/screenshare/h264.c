typedef struct {
    u8* data;
    u32 size;
    u32 capacity;
} ss_bytes;

static void ss_bytes_free(ss_bytes* bytes) {
    free(bytes->data);
    memset(bytes, 0, sizeof *bytes);
}

static u8 ss_bytes_reserve(ss_bytes* bytes, u32 needed) {
    if (needed <= bytes->capacity) {
        return 1;
    }
    u32 capacity = bytes->capacity ? bytes->capacity : 4096;
    while (capacity < needed) {
        capacity *= 2;
    }
    u8* data = (u8*) realloc(bytes->data, capacity);
    if (!data) {
        return 0;
    }
    bytes->data     = data;
    bytes->capacity = capacity;
    return 1;
}

static u8 ss_bytes_append(ss_bytes* bytes, const void* data, u32 size) {
    if (!ss_bytes_reserve(bytes, bytes->size + size)) {
        return 0;
    }
    memcpy(bytes->data + bytes->size, data, size);
    bytes->size += size;
    return 1;
}

static u8 ss_bytes_prepend(ss_bytes* bytes, const void* data, u32 size) {
    if (!ss_bytes_reserve(bytes, bytes->size + size)) {
        return 0;
    }
    memmove(bytes->data + size, bytes->data, bytes->size);
    memcpy(bytes->data, data, size);
    bytes->size += size;
    return 1;
}

static const u8 g_ss_start_code[4] = { 0, 0, 0, 1 };

static u8 ss_has_start_code(const u8* p, u32 length) {
    for (u32 i = 0; i + 3 <= length; ++i) {
        if (p[i] == 0 && p[i + 1] == 0 && p[i + 2] == 1) {
            return 1;
        }
    }
    return 0;
}

static u8 ss_avcc_to_annex_b(const u8* data, u32 length, ss_bytes* out) {
    u32 pos = 0;
    while (pos + 4 <= length) {
        u32 nal_length = ((u32) data[pos] << 24) | ((u32) data[pos + 1] << 16) | ((u32) data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (nal_length == 0 || pos + nal_length > length) {
            out->size = 0;
            return 0;
        }
        ss_bytes_append(out, g_ss_start_code, 4);
        ss_bytes_append(out, data + pos, nal_length);
        pos += nal_length;
    }
    return pos == length;
}

static u8 ss_sps_pps_to_annex_b(const u8* data, u32 length, ss_bytes* out) {
    if (length < 7 || data[0] != 1) {
        return 0;
    }
    u32 pos       = 5;
    u32 sps_count = data[pos++] & 0x1F;
    for (u32 i = 0; i < sps_count; ++i) {
        if (pos + 2 > length) {
            return 0;
        }
        u32 size = ((u32) data[pos] << 8) | data[pos + 1];
        pos += 2;
        if (size == 0 || pos + size > length) {
            return 0;
        }
        ss_bytes_append(out, g_ss_start_code, 4);
        ss_bytes_append(out, data + pos, size);
        pos += size;
    }
    if (pos >= length) {
        return out->size > 0;
    }
    u32 pps_count = data[pos++];
    for (u32 i = 0; i < pps_count; ++i) {
        if (pos + 2 > length) {
            return 0;
        }
        u32 size = ((u32) data[pos] << 8) | data[pos + 1];
        pos += 2;
        if (size == 0 || pos + size > length) {
            return 0;
        }
        ss_bytes_append(out, g_ss_start_code, 4);
        ss_bytes_append(out, data + pos, size);
        pos += size;
    }
    return out->size > 0;
}

static void ss_to_annex_b(ss_bytes* bytes) {
    if (bytes->size == 0 || ss_has_start_code(bytes->data, bytes->size)) {
        return;
    }
    ss_bytes converted = { 0 };
    if (ss_avcc_to_annex_b(bytes->data, bytes->size, &converted)) {
        ss_bytes_free(bytes);
        *bytes = converted;
    } else {
        ss_bytes_free(&converted);
    }
}

static u8 ss_has_nal(const u8* p, u32 length, u32 wanted) {
    for (u32 i = 0; i + 4 < length; ++i) {
        u32 start = 0;
        if (p[i] == 0 && p[i + 1] == 0 && p[i + 2] == 1) {
            start = 3;
        } else if (p[i] == 0 && p[i + 1] == 0 && p[i + 2] == 0 && p[i + 3] == 1) {
            start = 4;
        }
        if (start && i + start < length && (u32) (p[i + start] & 0x1F) == wanted) {
            return 1;
        }
    }
    return 0;
}

// The per-pixel loops are too slow unoptimized (build.bat builds debug by default), so they always get optimized
#pragma optimize("gt", on)
// BT.601 limited range BGRA to NV12. Chroma is the average of each 2x2 block, which keeps small text readable
static void ss_bgra_to_nv12(const u8* bgra, i32 w, i32 h, u8* nv12) {
    u8* y_plane  = nv12;
    u8* uv_plane = nv12 + (size_t) w * h;

    for (i32 y = 0; y < h; ++y) {
        const u8* line  = bgra + (size_t) y * w * 4;
        u8*       y_row = y_plane + (size_t) y * w;
        for (i32 x = 0; x < w; ++x) {
            i32 b    = line[x * 4];
            i32 g    = line[x * 4 + 1];
            i32 r    = line[x * 4 + 2];
            y_row[x] = (u8) (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16);
        }
    }

    for (i32 y = 0; y < h / 2; ++y) {
        const u8* line0  = bgra + (size_t) (y * 2) * w * 4;
        const u8* line1  = line0 + (size_t) w * 4;
        u8*       uv_row = uv_plane + (size_t) y * w;
        for (i32 x = 0; x < w / 2; ++x) {
            const u8* a       = line0 + x * 8;
            const u8* b       = line1 + x * 8;
            i32       blue    = (a[0] + a[4] + b[0] + b[4]) / 4;
            i32       green   = (a[1] + a[5] + b[1] + b[5]) / 4;
            i32       red     = (a[2] + a[6] + b[2] + b[6]) / 4;
            uv_row[x * 2]     = (u8) (((-38 * red - 74 * green + 112 * blue + 128) >> 8) + 128);
            uv_row[x * 2 + 1] = (u8) (((112 * red - 94 * green - 18 * blue + 128) >> 8) + 128);
        }
    }
}
#pragma optimize("", on)

// Output size for a source of the given size: the configured height, width from the source's aspect ratio
// (kept even and capped at 2560, which is what Discord's servers carry)
static void ss_output_size(const ss_config* config, i32 src_w, i32 src_h, i32* out_w, i32* out_h) {
    i32 height = (i32) config->height;
    // A screen is never upscaled: asking for 1440p on a 1080p display streams 1080p
    if (config->kind == ss_kind_screen && src_h > 0 && height > src_h) {
        height = src_h;
    }
    i32 width = src_h > 0 ? (i32) ((i64) src_w * height / src_h) : height * 16 / 9;
    if (width > 2560) {
        height = (i32) ((i64) height * 2560 / width);
        width  = 2560;
    }
    width &= ~1;
    height &= ~1;
    *out_w = width < 16 ? 16 : width;
    *out_h = height < 16 ? 16 : height;
}

static u32 ss_bitrate(i32 width, i32 height, i32 fps, u32 quality) {
    static const double bits_per_pixel[] = { 0.04, 0.07, 0.10 };
    static const double minimum[]        = { 1500000.0, 2000000.0, 3000000.0 };
    static const double maximum[]        = { 4000000.0, 8000000.0, 10000000.0 };

    u32    level   = quality > 2 ? 2 : quality;
    double bitrate = (double) width * height * fps * bits_per_pixel[level];
    if (bitrate < minimum[level]) {
        bitrate = minimum[level];
    }
    if (bitrate > maximum[level]) {
        bitrate = maximum[level];
    }
    return (u32) bitrate;
}

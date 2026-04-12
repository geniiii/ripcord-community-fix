typedef struct {
    union {
        u8*   s;
        u8*   str;
        char* cstr;
        void* data;
    };
    u64 size;
} String8;

#define S8Lit(s) (String8) S8LitComp(s)
#define S8LitComp(s) \
    {(u8*) (s), sizeof(s) - 1}

static u32 S8Equals(String8 a, String8 b) {
    return a.size == b.size && memcmp(a.data, b.data, a.size) == 0;
}

// NOTE(geni): Stolen from https://lemire.me/blog/2021/11/18/converting-integers-to-fix-digit-representations-quickly/
static u64 EncodeTenThousands(u64 hi, u64 lo) {
    u64 merged   = hi | (lo << 32);
    u64 top      = ((merged * 10486ULL) >> 20) & ((0x7FULL << 32) | 0x7FULL);
    u64 bot      = merged - 100ULL * top;
    u64 hundreds = (bot << 16) + top;
    u64 tens     = (hundreds * 103ULL) >> 10;
    tens &= (0xFULL << 48) | (0xFULL << 32) | (0xFULL << 16) | 0xFULL;
    tens += (hundreds - 10ULL * tens) << 8;
    return tens;
}

static String8 S8FromU64(u64 value, char* buf, u32 bufsize) {
    Unreferenced(bufsize);
    u64 hi  = value / 10000000000000000ULL;
    u64 mid = (value / 100000000ULL) % 100000000ULL;
    u64 lo  = value % 100000000ULL;

    u64 a = 0x3030303030303030ULL + EncodeTenThousands(hi / 10000, hi % 10000);
    u64 b = 0x3030303030303030ULL + EncodeTenThousands(mid / 10000, mid % 10000);
    u64 c = 0x3030303030303030ULL + EncodeTenThousands(lo / 10000, lo % 10000);

    memcpy(buf, &a, 8);
    memcpy(buf + 8, &b, 8);
    memcpy(buf + 16, &c, 8);
    buf[24] = 0;

    char* start = buf;
    char* end   = buf + 24;
    while (start < end - 1 && *start == '0') {
        ++start;
    }
    return (String8) {(u8*) start, (u64) (end - start)};
}

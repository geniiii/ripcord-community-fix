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

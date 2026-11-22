static u32 Erf_GetOfType(ErfMap* map, String8 key, ErfTag tag, ErfMapAny* out) {
    return ErfMap_Find(map, key.cstr, key.size, out) && out->tag == tag;
}

static u64 Erf_GetU64(ErfMap* map, String8 key, u64 def) {
    ErfMapAny any;
    u64       value;
    if (!ErfMap_Find(map, key.cstr, key.size, &any) || !Erf_ConvertU64(&any, &value)) {
        return def;
    }
    return value;
}

static u64 Erf_GetFlake(ErfMap* map, String8 key, u64 def) {
    ErfMapAny any;
    FlakeId   value;
    if (!ErfMap_Find(map, key.cstr, key.size, &any) || !Erf_ConvertFlake(&any, &value)) {
        return def;
    }
    return value.u;
}

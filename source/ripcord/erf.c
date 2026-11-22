static u32 Erf_GetOfType(ErfMap* map, String8 key, ErfTag tag, ErfMapAny* out) {
    return ErfMap_Find(map, key.cstr, key.size, out) && out->tag == tag;
}

static ErfStr Erf_GetStr(ErfMap* map, String8 key) {
    ErfMapAny any;
    if (!Erf_GetOfType(map, key, ErfTag_Str, &any)) {
        return (ErfStr) { 0 };
    }
    return any.str;
}

static ErfMap Erf_GetMap(ErfMap* map, String8 key) {
    ErfMapAny any;
    if (!Erf_GetOfType(map, key, ErfTag_Map, &any)) {
        return (ErfMap) { 0 };
    }
    return any.map;
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

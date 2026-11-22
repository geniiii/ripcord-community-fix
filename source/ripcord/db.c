#define U64Args(...) \
    ArrayCount(((u64[]) { __VA_ARGS__ })), (u64[]) { __VA_ARGS__ }
#define Db_BindU64(stmt, ...)       Db_BindU64N(stmt, U64Args(__VA_ARGS__))
#define Db_RunU64(stmt, ...)        Db_RunU64N(stmt, U64Args(__VA_ARGS__))
#define Db_ExecU64(stmts, sql, ...) Db_ExecU64N(stmts, sql, U64Args(__VA_ARGS__))
#define Db_QueryFlakes(arr, stmts, sql, max, ...) \
    Db_QueryFlakesN(arr, stmts, sql, max, U64Args(__VA_ARGS__))

static void Db_Prepare(RipStmt* stmt, DisDbPrepared* stmts, const char* sql) {
    RipStmt_Constructor(stmt, stmts->db, sql, 0);
}

static void Db_BindU64N(RipStmt* stmt, u32 count, const u64* params) {
    for (u32 i = 0; i < count; ++i) {
        RipStmt_BindU64(stmt, (i32) i + 1, params[i]);
    }
}

static u8 Db_RunU64N(RipStmt* stmt, u32 count, const u64* params) {
    Db_BindU64N(stmt, count, params);
    u8 result = RipStmt_Step(stmt);
    RipStmt_Reset(stmt);
    return result;
}

static u8 Db_ExecU64N(DisDbPrepared* stmts, const char* sql, u32 count, const u64* params) {
    RipStmt stmt;
    Db_Prepare(&stmt, stmts, sql);
    u8 result = Db_RunU64N(&stmt, count, params);
    RipStmt_Destructor(&stmt);
    return result;
}

static u32 Db_QueryFlakesN(QJsonArray* arr, DisDbPrepared* stmts, const char* sql, u32 max, u32 count, const u64* params) {
    RipStmt stmt;
    Db_Prepare(&stmt, stmts, sql);
    Db_BindU64N(&stmt, count, params);
    u32 n = 0;
    while (n < max && RipStmt_Step(&stmt)) {
        QJson_AppendFlake(arr, RipStmt_ColU64(&stmt, 0));
        ++n;
    }
    RipStmt_Destructor(&stmt);
    return n;
}

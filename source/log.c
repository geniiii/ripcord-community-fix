static void Log_Error(const char* fmt, ...) {
    char    buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof buf, fmt, args);
    va_end(args);
    MessageBoxA(0, buf, "Ripcord Community Fix Failure", MB_ICONERROR);
}

static void Log_Ripcord(String8 msg);

static void Log_Debug(const char* fmt, ...) {
    SYSTEMTIME t;
    GetLocalTime(&t);

    char    buf[512];
    i32     prefix = snprintf(buf, sizeof buf, "[%04d-%02d-%02d %02d:%02d:%02d] ", t.wYear, t.wMonth, t.wDay, t.wHour,
                              t.wMinute, t.wSecond);
    String8 tag    = S8Lit("[RCF] ");
    memcpy(buf + prefix, tag.data, tag.size);
    i32 size = prefix + (i32) tag.size;

    va_list args;
    va_start(args, fmt);
    size += vsnprintf(buf + size, sizeof buf - size - 1, fmt, args);
    va_end(args);
    if (size > (i32) sizeof buf - 2) {
        size = sizeof buf - 2;
    }
    buf[size++] = '\n';
    buf[size]   = 0;

    OutputDebugStringA(buf);
    Log_Ripcord((String8) {
        .cstr = buf + prefix,
        .size = (u64) (size - prefix - 1),
    });
#if BUILD_DEBUG
    DWORD written;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD) size, &written, NULL);
#endif
}

static void ErrorMessage(const char* fmt, ...) {
    char    buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof buf, fmt, args);
    va_end(args);
    MessageBoxA(0, buf, "Ripcord Community Fix Failure", MB_ICONERROR);
}

static void DebugMsg(const char* fmt, ...) {
    SYSTEMTIME t;
    GetLocalTime(&t);

    char buf[512];
    i32  size = snprintf(buf, sizeof buf, "[%04d-%02d-%02d %02d:%02d:%02d] ", t.wYear, t.wMonth, t.wDay, t.wHour,
                         t.wMinute, t.wSecond);

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
#if BUILD_DEBUG
    DWORD written;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, (DWORD) size, &written, NULL);
#endif
}

static void ErrorMessage(const char* fmt, ...) {
    char    buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof buf, fmt, args);
    va_end(args);
    MessageBoxA(0, buf, "Audio Hook Failure", MB_ICONERROR);
}

static void DebugMsg(const char* fmt, ...) {
    // TODO(geni): I should've used Win32 but I was too lazy. Sorry!
    time_t     t  = time(NULL);
    struct tm* tm = localtime(&t);
    char       time_buf[64];
    i32        time_size = (i32) strftime(time_buf, sizeof time_buf, "%c", tm);

    char    buf[2048];
    va_list args;
    va_start(args, fmt);
    i32 size = vsnprintf(buf, sizeof buf, fmt, args);
    va_end(args);
    if (size < 0) {
        return;
    }
    if (size >= (i32) sizeof buf) {
        size = sizeof buf - 1;
    }
    OutputDebugStringA(buf);
    fprintf(stderr, "[%.*s] %.*s", time_size, time_buf, size, buf);
}

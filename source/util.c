static void ErrorMsg(const char* fmt, ...) {
    char    buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof buf, fmt, args);
    va_end(args);
    fprintf(stderr, "[ripcord-community-fix] error: %s\n", buf);
    fflush(stderr);
}

static void DebugMsg(const char* fmt, ...) {
    time_t     t  = time(NULL);
    struct tm* tm = localtime(&t);
    char       time_buf[64];
    i32        time_size = (i32) strftime(time_buf, sizeof time_buf, "%c", tm);

    char    buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof buf, fmt, args);
    va_end(args);
    fprintf(stderr, "[%.*s] %s", time_size, time_buf, buf);
    fflush(stderr);
}

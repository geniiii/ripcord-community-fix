#define UPDATE_HOST     L"geni.site"
#define UPDATE_PATH     L"/rcf-latest"
#define UPDATE_PAGE_URL "https://geni.site/projects/ripcord-community-fix/"
#define UPDATE_TIMEOUT  5000

typedef struct {
    u8 major;
    u8 minor;
    u8 patch;
    // NOTE(geni): 0 for stable builds
    u8 pre;
} Version;

static u8 ParseVersion(String8 str, Version* out) {
    *out = (Version) {0};
    if (!S8ConsumeU8(&str, &out->major) || !S8ConsumePrefix(&str, S8Lit(".")) ||
        !S8ConsumeU8(&str, &out->minor) || !S8ConsumePrefix(&str, S8Lit(".")) ||
        !S8ConsumeU8(&str, &out->patch)) {
        return 0;
    }
    if (S8ConsumePrefix(&str, S8Lit("-pre")) && (!S8ConsumeU8(&str, &out->pre) || out->pre == 0)) {
        return 0;
    }
    return str.size == 0;
}

// NOTE(geni): Stable builds (pre0) wrap around to 0xFF, hence are considered higher than all >=pre1
static u32 VersionKey(Version v) {
    return ((u32) v.major << 24) | ((u32) v.minor << 16) | ((u32) v.patch << 8) | (u8) (v.pre - 1);
}

static u8 IsOutdated(Version current, Version latest) {
    // NOTE(geni): Never update stable to prerelease
    if (current.pre == 0 && latest.pre != 0) {
        return 0;
    }
    return VersionKey(latest) > VersionKey(current);
}

static String8 FetchLatestVersion(u8* buf, u32 buf_size) {
    String8   result  = {0};
    HINTERNET session = WinHttpOpen(L"ripcord-community-fix-" VERSION, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connect = NULL;
    HINTERNET request = NULL;
    if (!session) {
        goto cleanup;
    }
    WinHttpSetTimeouts(session, UPDATE_TIMEOUT, UPDATE_TIMEOUT, UPDATE_TIMEOUT, UPDATE_TIMEOUT);

    connect = WinHttpConnect(session, UPDATE_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connect) {
        goto cleanup;
    }
    request = WinHttpOpenRequest(connect, L"GET", UPDATE_PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) {
        goto cleanup;
    }
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, NULL)) {
        goto cleanup;
    }

    u32 total = 0;
    while (total < buf_size) {
        DWORD read = 0;
        if (!WinHttpReadData(request, buf + total, buf_size - total, &read) || read == 0) {
            break;
        }
        total += read;
    }
    result = (String8) {
        .s    = buf,
        .size = total,
    };

cleanup:
    if (request) {
        WinHttpCloseHandle(request);
    }
    if (connect) {
        WinHttpCloseHandle(connect);
    }
    if (session) {
        WinHttpCloseHandle(session);
    }
    return result;
}

static DWORD WINAPI UpdateCheckThread(LPVOID param) {
    Unreferenced(param);

    u8      buf[64];
    String8 latest_str = S8UntilNewline(FetchLatestVersion(buf, sizeof buf));

    Version current, latest;
    if (!ParseVersion(S8Lit(VERSION), &current) || !ParseVersion(latest_str, &latest) || !IsOutdated(current, latest)) {
        return 0;
    }

    char msg[256];
    snprintf(msg, sizeof msg, "A new version of Ripcord Community Fix is available. Updating is highly recommended.\n\nCurrent: %.*s\nLatest: %.*s\n\nOpen the download page?", S8VArg(S8Lit(VERSION)), S8VArg(latest_str));
    if (MessageBoxA(NULL, msg, "RCF Update Available", MB_YESNO | MB_ICONINFORMATION) == IDYES) {
        ShellExecuteA(NULL, "open", UPDATE_PAGE_URL, NULL, NULL, SW_SHOWNORMAL);
    }
    return 0;
}

static void StartUpdateCheck(void) {
    HANDLE thread = CreateThread(NULL, 0, UpdateCheckThread, NULL, 0, NULL);
    if (thread) {
        CloseHandle(thread);
    }
}

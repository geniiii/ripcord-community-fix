#include "qt/plugin_metadata.h"

static u8 RemoveLegacyDlls(void) {
    static const wchar_t* legacy_dlls[] = { L"winmm.dll", L"uxtheme.dll" };

    wchar_t dir[MAX_PATH];
    GetModuleFileNameW(NULL, dir, MAX_PATH);
    PathRemoveFileSpecW(dir);

    u8 found = 0;
    for (u32 i = 0; i < ArrayCount(legacy_dlls); ++i) {
        wchar_t path[MAX_PATH];
        wchar_t old_path[MAX_PATH];
        PathCombineW(path, dir, legacy_dlls[i]);
        _snwprintf(old_path, MAX_PATH, L"%s.old", path);

        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
            continue;
        }
        found = 1;

        if (MoveFileExW(path, old_path, MOVEFILE_REPLACE_EXISTING)) {
            wchar_t msg[256];
            _snwprintf(msg, ArrayCount(msg), L"Renamed %s from an older version of the Ripcord Community Fix to %s.old. Restart Ripcord to use the new version.", legacy_dlls[i], legacy_dlls[i]);
            MessageBoxW(NULL, msg, L"Ripcord Community Fix", MB_ICONINFORMATION);
        } else {
            Log_Error("Failed to rename %ls. Please delete or rename it manually.", legacy_dlls[i]);
        }
    }
    return found;
}

__declspec(dllexport) const char* qt_plugin_query_metadata(void) {
    return (const char*) &g_plugin_metadata;
}

__declspec(dllexport) void* qt_plugin_instance(void) {
    static int initialized;
    if (initialized) {
        return 0;
    }
    initialized = 1;

    if (!GetModuleHandleA("Ripcord.exe")) {
        return 0;
    }

    HMODULE self;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, (LPCWSTR) &qt_plugin_instance, &self);

#if BUILD_DEBUG
    AllocConsole();
    freopen("CONIN$", "rb", stdin);
    freopen("CONOUT$", "wb", stdout);
    freopen("CONOUT$", "wb", stderr);
#endif

    if (RemoveLegacyDlls()) {
        return 0;
    }

    if (Hook_Init()) {
        Update_StartCheck();
        voice_line_init();
        ss_start();
    } else {
        Log_Error("Failed to load hooks.");
    }
    return 0;
}

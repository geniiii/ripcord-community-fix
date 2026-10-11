#define Proxy(name) static FARPROC Func_##name;
#include "proxied.inc"
#undef Proxy

#define WARNING_MESSAGE                                                               \
    HIJACKED_DLL                                                                      \
    " from Ripcord Community Fix was loaded by a process other than Ripcord.exe.\n\n" \
    "To avoid potential issues, please delete " HIJACKED_DLL " from %s."

static HINSTANCE lib_handle;
BOOL WINAPI      DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void) reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t buffer[32768];
        GetSystemDirectoryW(buffer, 32768 - sizeof HIJACKED_DLL - 2);
        // NOTE(geni): No PathCchAppend since it's only available on Windows 8 and later, while Ripcord is still supported on 7
        PathAppendW(buffer, L"\\" HIJACKED_DLL);
        lib_handle = LoadLibraryExW(buffer, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!lib_handle) {
            ErrorMessage("Failed to hijack " HIJACKED_DLL ".");
            return 0;
        }
#define Proxy(name) Func_##name = GetProcAddress(lib_handle, #name);
#include "proxied.inc"
#undef Proxy

        DisableThreadLibraryCalls(inst);

        if (!GetModuleHandleA("Ripcord.exe")) {
            char dll_dir[MAX_PATH];
            GetModuleFileNameA(inst, dll_dir, sizeof dll_dir);
            PathRemoveFileSpecA(dll_dir);
            char msg[MAX_PATH + sizeof WARNING_MESSAGE];
            snprintf(msg, sizeof msg, WARNING_MESSAGE, dll_dir);
            MessageBoxA(0, msg, "Ripcord Community Fix Warning", MB_ICONWARNING);
            return 1;
        }

#if BUILD_DEBUG
        AllocConsole();
        freopen("CONIN$", "rb", stdin);
        freopen("CONOUT$", "wb", stdout);
        freopen("CONOUT$", "wb", stderr);
#endif
        u32 result = LoadHooks();
        if (result) {
            StartUpdateCheck();
        }
        return result;
    } else if (reason == DLL_PROCESS_DETACH) {
        FreeLibrary(lib_handle);
    }

    return 1;
}

#define Proxy(name) \
    void PROXY_##name() { Func_##name(); }
#include "proxied.inc"
#undef Proxy

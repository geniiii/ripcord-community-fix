static u32 Hook_Create(u8* base, u64 ptr, void* hook, void** orig) {
    static char buffer[4096];

    MH_STATUS status;
    if ((status = MH_CreateHook(base + ptr, hook, orig)) != MH_OK) {
        snprintf(buffer, sizeof buffer, "Failed to create hook at 0x%llX\nError code: %d", ptr, status);
        Log_Error(buffer);
        return 0;
    }
    if ((status = MH_EnableHook(base + ptr)) != MH_OK) {
        snprintf(buffer, sizeof buffer, "Failed to enable hook at 0x%llX\nError code: %d", ptr, status);
        Log_Error(buffer);
        return 0;
    }

    return 1;
}

static void Hook_PatchByte(u8* base, u64 ptr, u8 new) {
    DWORD old_protect;
    u8*   addr = base + ptr;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old_protect);
    *addr = new;
    VirtualProtect(addr, 1, old_protect, &old_protect);
}

static void Hook_PatchString(u8* base, u64 ptr, String8 new) {
    DWORD old_protect;
    u8*   addr = base + ptr;
    VirtualProtect(addr, new.size, PAGE_EXECUTE_READWRITE, &old_protect);
    CopyMemory(addr, new.data, new.size);
    VirtualProtect(addr, new.size, old_protect, &old_protect);
}

static u32 Hook_Init() {
    if (MH_Initialize() != MH_OK) {
        Log_Error("Failed to initialize MinHook");
        return 0;
    }

    MODULEINFO module_info;
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA("Ripcord.exe"), &module_info, sizeof module_info);
    u8* rip_base = (u8*) module_info.lpBaseOfDll;

    for (u32 i = 0; i < sizeof SUPPORTED_VERSION; ++i) {
        if (rip_base[0x3BAB70 + i] != SUPPORTED_VERSION[i]) {
            Log_Error("Unsupported Ripcord version (expected " SUPPORTED_VERSION ")");
            return 0;
        }
    }

    // NOTE(geni): Patch IP discovery packet sizes
    Hook_PatchByte(rip_base, 0xDE8D8, 74);
    Hook_PatchByte(rip_base, 0xDE8EA, 8);
    Hook_PatchByte(rip_base, 0xDE90C, 8);
    Hook_PatchByte(rip_base, 0xDE936, 72);

    // NOTE(geni): Set voice gateway version to 8
    Hook_PatchByte(rip_base, 0x3CF0B4, '8');
    // NOTE(geni): Patch "speaking" field check for v4 and later of voice gateway
    // NOTE(geni): Check for double instead of bool for "speaking" field
    Hook_PatchByte(rip_base, 0xE6C5C, 0x83);
    Hook_PatchByte(rip_base, 0xE6C5C + 1, 0xF8);
    Hook_PatchByte(rip_base, 0xE6C5C + 2, 0x02);
    // NOTE(geni): Call QJsonValue::toInt() instead of QJsonValue::toBool()
    Hook_PatchByte(rip_base, 0xE6C67 + 2, 0x03);
    Hook_PatchByte(rip_base, 0xE6C67 + 3, 0x76);

    // NOTE(geni): Fixes image previews not loading. Thanks u130b8!
    Hook_PatchString(rip_base, 0x3E63F8, S8Lit("cdn.discordapp.com/\0\0\0"));

    // NOTE(geni): Discard invalid map keys instead of aborting. Thanks @muffinlord on Discord!
    Hook_PatchByte(rip_base, 0xB9BBF, 0xEB);
    Hook_PatchByte(rip_base, 0xB9BC0, 0x80);

    // NOTE(geni): Disable gateway port splitting
    Hook_PatchByte(rip_base, 0xD677E, 0x10);

    HMODULE qt5core       = GetModuleHandleA("Qt5Core.dll");
    HMODULE qt5network    = GetModuleHandleA("Qt5Network.dll");
    HMODULE sodium        = GetModuleHandleA("libsodium.dll");
    HMODULE qt5websockets = GetModuleHandleA("Qt5WebSockets.dll");

    u32 result = 1;
#define QT_HOOK(module, name, sig, mangled) result &= Hook_Create(0, (u64) GetProcAddress(module, mangled), (void*) &name##Hook, (void**) &name);
#define QT_FN(module, name, sig, mangled)   name = (name##Type*) GetProcAddress(module, mangled);
#include "qt/functions.inc"
#undef QT_FN
#undef QT_HOOK

#define RIP_HOOK(name, sig, offset) result &= Hook_Create(rip_base, offset, (void*) &name##Hook, (void**) &name);
#define RIP_FN(name, sig, offset)   name = (name##Type*) (rip_base + offset);
#include "ripcord/functions.inc"
#undef RIP_FN
#undef RIP_HOOK

    crypto_aead_xchacha20poly1305_ietf_decrypt = (CryptoAeadXchacha20poly1305IetfDecryptType*) GetProcAddress(sodium, "crypto_aead_xchacha20poly1305_ietf_decrypt");
    crypto_aead_xchacha20poly1305_ietf_encrypt = (CryptoAeadXchacha20poly1305IetfEncryptType*) GetProcAddress(sodium, "crypto_aead_xchacha20poly1305_ietf_encrypt");

    g_binary_msg_signal_fn   = (void*) GetProcAddress(qt5websockets,
                                                      "?binaryMessageReceived@QWebSocket@@QEAAXAEBVQByteArray@@@Z");
    g_qwebsocket_static_meta = (void*) GetProcAddress(qt5websockets,
                                                      "?staticMetaObject@QWebSocket@@2UQMetaObject@@B");

    return result;
}

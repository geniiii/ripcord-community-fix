static void ss_list_free(ss_source_list* list) {
    if (!list) {
        return;
    }
    for (u32 i = 0; i < list->count; ++i) {
        if (list->items[i].thumb) {
            DeleteObject(list->items[i].thumb);
        }
        if (list->items[i].icon) {
            DestroyIcon(list->items[i].icon);
        }
    }
    free(list->items);
    free(list);
}

static ss_source* ss_list_add(ss_source_list* list) {
    if (list->count == list->capacity) {
        u32        capacity = list->capacity ? list->capacity * 2 : 16;
        ss_source* items    = (ss_source*) realloc(list->items, capacity * sizeof *items);
        if (!items) {
            return NULL;
        }
        list->items    = items;
        list->capacity = capacity;
    }
    ss_source* source = &list->items[list->count++];
    memset(source, 0, sizeof *source);
    return source;
}

static HBITMAP ss_create_dib(i32 width, i32 height, u8** out_bits) {
    BITMAPINFO info              = { 0 };
    info.bmiHeader.biSize        = sizeof info.bmiHeader;
    info.bmiHeader.biWidth       = width;
    info.bmiHeader.biHeight      = -height;
    info.bmiHeader.biPlanes      = 1;
    info.bmiHeader.biBitCount    = 32;
    info.bmiHeader.biCompression = BI_RGB;
    void*   bits                 = NULL;
    HBITMAP bitmap               = CreateDIBSection(NULL, &info, DIB_RGB_COLORS, &bits, NULL, 0);
    if (out_bits) {
        *out_bits = (u8*) bits;
    }
    return bitmap;
}

static HBITMAP ss_build_thumb(HDC screen, HDC src, i32 src_x, i32 src_y, i32 src_w, i32 src_h, DWORD rop) {
    if (src_w <= 0 || src_h <= 0) {
        return NULL;
    }
    HBITMAP thumb = ss_create_dib(ss_thumb_w, ss_thumb_h, NULL);
    if (!thumb) {
        return NULL;
    }
    HDC     dst = CreateCompatibleDC(screen);
    HGDIOBJ old = SelectObject(dst, thumb);

    RECT all = { 0, 0, ss_thumb_w, ss_thumb_h };
    SetBkColor(dst, RGB(16, 16, 16));
    ExtTextOutW(dst, 0, 0, ETO_OPAQUE, &all, NULL, 0, NULL);

    i32 w = ss_thumb_w;
    i32 h = (i32) ((i64) src_h * ss_thumb_w / src_w);
    if (h > ss_thumb_h) {
        h = ss_thumb_h;
        w = (i32) ((i64) src_w * ss_thumb_h / src_h);
    }
    if (w < 1) {
        w = 1;
    }
    if (h < 1) {
        h = 1;
    }
    SetStretchBltMode(dst, HALFTONE);
    SetBrushOrgEx(dst, 0, 0, NULL);
    StretchBlt(dst, (ss_thumb_w - w) / 2, (ss_thumb_h - h) / 2, w, h, src, src_x, src_y, src_w, src_h, rop);

    SelectObject(dst, old);
    DeleteDC(dst);
    return thumb;
}

typedef struct {
    ss_source_list* list;
    HDC             screen;
} ss_enum_ctx;

static BOOL CALLBACK ss_enum_windows(HWND hwnd, LPARAM lparam) {
    ss_enum_ctx* ctx = (ss_enum_ctx*) lparam;

    if (!IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != NULL) {
        return TRUE;
    }
    LONG_PTR ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    if ((ex_style & WS_EX_TOOLWINDOW) && !(ex_style & WS_EX_APPWINDOW)) {
        return TRUE;
    }

    // Suspended UWP windows and windows on other virtual desktops are "cloaked"
    BOOL cloaked = FALSE;
    DwmGetWindowAttribute(hwnd, 14, &cloaked, sizeof cloaked);
    if (cloaked) {
        return TRUE;
    }

    wchar_t class_name[64];
    GetClassNameW(hwnd, class_name, ArrayCount(class_name));
    if (wcscmp(class_name, L"Progman") == 0 || wcscmp(class_name, ss_picker_class) == 0 ||
        wcscmp(class_name, ss_control_class) == 0) {
        return TRUE;
    }

    wchar_t title[160];
    i32     title_length = GetWindowTextW(hwnd, title, ArrayCount(title));
    if (title_length <= 0 || IsHungAppWindow(hwnd)) {
        return TRUE;
    }

    ss_source* source = ss_list_add(ctx->list);
    if (!source) {
        return FALSE;
    }
    source->kind   = ss_kind_application;
    source->window = hwnd;
    wcscpy(source->name, title);

    DWORD_PTR icon = 0;
    if (SendMessageTimeoutW(hwnd, WM_GETICON, ICON_SMALL2, 0, SMTO_ABORTIFHUNG, 50, &icon) && icon) {
        source->icon = CopyIcon((HICON) icon);
    }
    if (!source->icon) {
        HICON class_icon = (HICON) GetClassLongPtrW(hwnd, GCLP_HICONSM);
        if (!class_icon) {
            class_icon = (HICON) GetClassLongPtrW(hwnd, GCLP_HICON);
        }
        if (class_icon) {
            source->icon = CopyIcon(class_icon);
        }
    }

    RECT rect;
    GetWindowRect(hwnd, &rect);
    i32 width  = rect.right - rect.left;
    i32 height = rect.bottom - rect.top;
    if (!IsIconic(hwnd) && width > 0 && height > 0 && width <= 8192 && height <= 8192) {
        HDC     mem  = CreateCompatibleDC(ctx->screen);
        HBITMAP full = CreateCompatibleBitmap(ctx->screen, width, height);
        if (mem && full) {
            HGDIOBJ old = SelectObject(mem, full);
            // PW_RENDERFULLCONTENT, so GPU-drawn windows (browsers, games) aren't black
            if (PrintWindow(hwnd, mem, 2)) {
                source->thumb = ss_build_thumb(ctx->screen, mem, 0, 0, width, height, SRCCOPY);
            }
            SelectObject(mem, old);
        }
        if (full) {
            DeleteObject(full);
        }
        if (mem) {
            DeleteDC(mem);
        }
    }
    return TRUE;
}

static BOOL CALLBACK ss_enum_monitors(HMONITOR monitor, HDC dc, LPRECT rect, LPARAM lparam) {
    Unreferenced(monitor);
    Unreferenced(dc);
    ss_enum_ctx* ctx    = (ss_enum_ctx*) lparam;
    ss_source*   source = ss_list_add(ctx->list);
    if (!source) {
        return FALSE;
    }
    source->kind   = ss_kind_screen;
    source->screen = *rect;
    _snwprintf(source->name, ArrayCount(source->name), L"Screen %u", ctx->list->count);
    source->name[ArrayCount(source->name) - 1] = 0;
    source->thumb                              = ss_build_thumb(ctx->screen, ctx->screen, rect->left, rect->top,
                                                                rect->right - rect->left, rect->bottom - rect->top, SRCCOPY | CAPTUREBLT);
    return TRUE;
}

// KSCATEGORY_VIDEO_CAMERA
static const GUID g_ss_camera_guid = {
    0xE5323777,
    0xF976,
    0x4f5b,
    { 0x9B, 0x55, 0xB9, 0x46, 0x99, 0xC4, 0x6E, 0x44 }
};

static void ss_list_devices(ss_source_list* list) {
    HDEVINFO set = SetupDiGetClassDevsW(&g_ss_camera_guid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (set == INVALID_HANDLE_VALUE) {
        return;
    }
    for (DWORD i = 0;; ++i) {
        SP_DEVICE_INTERFACE_DATA interface_data = { sizeof interface_data };
        if (!SetupDiEnumDeviceInterfaces(set, NULL, &g_ss_camera_guid, i, &interface_data)) {
            break;
        }

        DWORD needed = 0;
        SetupDiGetDeviceInterfaceDetailW(set, &interface_data, NULL, 0, &needed, NULL);
        if (needed == 0) {
            continue;
        }
        SP_DEVICE_INTERFACE_DETAIL_DATA_W* detail = (SP_DEVICE_INTERFACE_DETAIL_DATA_W*) malloc(needed);
        if (!detail) {
            continue;
        }
        detail->cbSize          = sizeof *detail;
        SP_DEVINFO_DATA devinfo = { sizeof devinfo };
        if (SetupDiGetDeviceInterfaceDetailW(set, &interface_data, detail, needed, NULL, &devinfo)) {
            ss_source* source = ss_list_add(list);
            if (source) {
                source->kind = ss_kind_device;
                wcsncpy(source->device_id, detail->DevicePath, ArrayCount(source->device_id) - 1);
                if (!SetupDiGetDeviceRegistryPropertyW(set, &devinfo, SPDRP_FRIENDLYNAME, NULL,
                                                       (PBYTE) source->name, sizeof source->name - sizeof(wchar_t), NULL) &&
                    !SetupDiGetDeviceRegistryPropertyW(set, &devinfo, SPDRP_DEVICEDESC, NULL,
                                                       (PBYTE) source->name, sizeof source->name - sizeof(wchar_t), NULL)) {
                    wcscpy(source->name, L"Camera");
                }
            }
        }
        free(detail);
    }
    SetupDiDestroyDeviceInfoList(set);
}

static DWORD WINAPI ss_load_thread(LPVOID param) {
    ss_load_job job = *(ss_load_job*) param;
    free(param);

    ss_source_list* list = (ss_source_list*) calloc(1, sizeof *list);
    if (!list) {
        return 0;
    }
    list->kind       = job.kind;
    list->generation = job.generation;

    HDC         screen = GetDC(NULL);
    ss_enum_ctx ctx    = { .list = list, .screen = screen };
    switch (job.kind) {
        case ss_kind_application: {
            EnumWindows(ss_enum_windows, (LPARAM) &ctx);
        } break;
        case ss_kind_screen: {
            EnumDisplayMonitors(NULL, NULL, ss_enum_monitors, (LPARAM) &ctx);
        } break;
        case ss_kind_device: {
            ss_list_devices(list);
        } break;
    }
    ReleaseDC(NULL, screen);

    if (!PostMessageW(job.notify, wm_ss_loaded, 0, (LPARAM) list)) {
        ss_list_free(list);
    }
    return 0;
}

static void ss_start_load(HWND notify, u32 kind, u32 generation) {
    ss_load_job* job = (ss_load_job*) malloc(sizeof *job);
    if (!job) {
        return;
    }
    job->notify     = notify;
    job->kind       = kind;
    job->generation = generation;
    HANDLE thread   = CreateThread(NULL, 0, ss_load_thread, job, 0, NULL);
    if (thread) {
        CloseHandle(thread);
    } else {
        free(job);
    }
}

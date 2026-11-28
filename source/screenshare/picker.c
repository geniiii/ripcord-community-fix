#define ui_bg         RGB(43, 43, 43)
#define ui_bg_dark    RGB(31, 31, 31)
#define ui_bg_bar     RGB(50, 50, 50)
#define ui_bg_hot     RGB(74, 77, 82)
#define ui_border     RGB(70, 70, 70)
#define ui_fg         RGB(224, 224, 224)
#define ui_fg_dim     RGB(140, 140, 140)

#define ui_timer_id   1
#define ui_timer_ms   30

#define ui_picker_w   900
#define ui_picker_h   640
#define ui_pad        16
#define ui_tile_gap   12
#define ui_caption    24
#define ui_tab_w      130
#define ui_tab_h      30

#define ui_id_tab     1
#define ui_id_gear    10
#define ui_id_res     20
#define ui_id_fps     30
#define ui_id_panel   40
#define ui_id_scroll  50
#define ui_id_tile    1000
#define ui_id_edit    201
#define ui_id_c_start 1
#define ui_id_c_stop  2
#define ui_id_c_mute  3

#define ui_max(a, b)  ((a) > (b) ? (a) : (b))
#define ui_min(a, b)  ((a) < (b) ? (a) : (b))

static const u32 g_ui_heights[4]     = { 480, 720, 1080, 1440 };
static const u32 g_ui_fps_presets[2] = { 30, 60 };

static HFONT g_ui_font;

static HWND g_control_hwnd;
static HWND g_picker_hwnd;
static i32  g_control_hot;

static struct {
    HWND            edit;
    HBRUSH          edit_brush;
    u32             tab;
    ss_source_list* list;
    u32             generation;
    u8              loading;
    u8              settings_open;
    u8              tracking;
    u8              syncing;
    u8              dragging;
    i32             hot;
    i32             pressed;
    i32             scroll;
    i32             drag_start_y;
    i32             drag_start_scroll;
} g_picker;

typedef struct {
    RECT tabs;
    RECT tab[3];
    RECT grid;
    RECT gear;
    RECT track;
    i32  tile_w;
    i32  thumb_h;
    i32  tile_h;
} picker_layout;

typedef struct {
    RECT panel;
    RECT res[4];
    RECT fps[3];
    RECT edit;
    u8   show_edit;
} settings_layout;

static void picker_quality_text(wchar_t* out, u32 size) {
    _snwprintf(out, size, L"%up, %u fps", g_ss_settings.height, g_ss_settings.fps);
    out[size - 1] = 0;
}

static u8 ui_in_rect(const RECT* rect, i32 x, i32 y) {
    return x >= rect->left && x < rect->right && y >= rect->top && y < rect->bottom;
}

static RECT ui_make_rect(i32 x, i32 y, i32 w, i32 h) {
    RECT rect = { x, y, x + w, y + h };
    return rect;
}

static void ui_fill(HDC dc, const RECT* rect, COLORREF color) {
    SetBkColor(dc, color);
    ExtTextOutW(dc, 0, 0, ETO_OPAQUE, rect, NULL, 0, NULL);
}

static void ui_box(HDC dc, const RECT* rect, COLORREF fill, COLORREF border) {
    ui_fill(dc, rect, border);
    RECT inner = { rect->left + 1, rect->top + 1, rect->right - 1, rect->bottom - 1 };
    ui_fill(dc, &inner, fill);
}

static void ui_text(HDC dc, const wchar_t* text, RECT rect, COLORREF color, UINT flags) {
    HGDIOBJ old = SelectObject(dc, g_ui_font);
    SetTextColor(dc, color);
    SetBkMode(dc, TRANSPARENT);
    DrawTextW(dc, text, -1, &rect, flags | DT_NOPREFIX | DT_SINGLELINE);
    SelectObject(dc, old);
}

static void ui_theme_title_bar(HWND hwnd) {
    BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd, 20, &dark, sizeof dark);
}

static void ui_center_on_screen(HWND hwnd) {
    RECT rect;
    GetWindowRect(hwnd, &rect);
    i32 width  = rect.right - rect.left;
    i32 height = rect.bottom - rect.top;

    HWND     foreground = GetForegroundWindow();
    HMONITOR monitor;
    if (foreground) {
        monitor = MonitorFromWindow(foreground, MONITOR_DEFAULTTONEAREST);
    } else {
        POINT cursor;
        GetCursorPos(&cursor);
        monitor = MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST);
    }
    MONITORINFO info = { sizeof info };
    GetMonitorInfoW(monitor, &info);
    RECT area = info.rcWork;

    i32 x = area.left + ((area.right - area.left) - width) / 2;
    i32 y = area.top + ((area.bottom - area.top) - height) / 2;
    SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

static picker_layout picker_get_layout(i32 width, i32 height) {
    picker_layout layout = { 0 };
    layout.tabs          = ui_make_rect(ui_pad, ui_pad, width - 2 * ui_pad, ui_tab_h);
    for (i32 i = 0; i < 3; ++i) {
        layout.tab[i] = ui_make_rect(ui_pad + i * ui_tab_w, ui_pad, ui_tab_w, ui_tab_h);
    }
    i32 footer_top = height - 48;
    layout.grid    = ui_make_rect(ui_pad, layout.tabs.bottom + 12, width - 2 * ui_pad - 14, footer_top - (layout.tabs.bottom + 12));
    layout.gear    = ui_make_rect(width - ui_pad - 90, footer_top + 10, 90, 28);
    layout.track   = ui_make_rect(width - ui_pad - 6, layout.grid.top, 6, layout.grid.bottom - layout.grid.top);
    layout.tile_w  = (layout.grid.right - layout.grid.left - ui_tile_gap) / 2;
    layout.thumb_h = layout.tile_w * 9 / 16;
    layout.tile_h  = layout.thumb_h + ui_caption;
    return layout;
}

static i32 picker_content_height(const picker_layout* layout) {
    u32 count = g_picker.list ? g_picker.list->count : 0;
    u32 rows  = (count + 1) / 2;
    return rows ? (i32) rows * layout->tile_h + ((i32) rows - 1) * ui_tile_gap : 0;
}

static i32 picker_max_scroll(const picker_layout* layout) {
    return ui_max(0, picker_content_height(layout) - (layout->grid.bottom - layout->grid.top));
}

static void picker_clamp_scroll(const picker_layout* layout) {
    g_picker.scroll = ui_max(0, ui_min(g_picker.scroll, picker_max_scroll(layout)));
}

static RECT picker_tile_rect(const picker_layout* layout, u32 index) {
    i32 col = (i32) (index % 2);
    i32 row = (i32) (index / 2);
    i32 x   = layout->grid.left + col * (layout->tile_w + ui_tile_gap);
    i32 y   = layout->grid.top - g_picker.scroll + row * (layout->tile_h + ui_tile_gap);
    return ui_make_rect(x, y, layout->tile_w, layout->tile_h);
}

static RECT picker_scroll_thumb(const picker_layout* layout) {
    i32 view    = layout->grid.bottom - layout->grid.top;
    i32 content = picker_content_height(layout);
    i32 max     = picker_max_scroll(layout);
    if (max <= 0) {
        return ui_make_rect(0, 0, 0, 0);
    }
    i32 size = ui_max(40, (i32) ((i64) view * view / content));
    i32 pos  = (i32) ((i64) g_picker.scroll * (view - size) / max);
    return ui_make_rect(layout->track.left, layout->track.top + pos, layout->track.right - layout->track.left, size);
}

static settings_layout picker_get_settings(const picker_layout* layout) {
    settings_layout s = { 0 };
    s.show_edit       = g_ss_settings.fps_mode == 2;
    i32 width         = 272;
    i32 height        = s.show_edit ? 160 : 124;
    s.panel           = ui_make_rect(layout->gear.right - width, layout->gear.top - height - 6, width, height);
    for (i32 i = 0; i < 4; ++i) {
        s.res[i] = ui_make_rect(s.panel.left + 12 + i * 62, s.panel.top + 28, 56, 26);
    }
    for (i32 i = 0; i < 3; ++i) {
        s.fps[i] = ui_make_rect(s.panel.left + 12 + i * 82, s.panel.top + 80, 76, 26);
    }
    s.edit = ui_make_rect(s.panel.left + 12, s.panel.top + 118, 60, 26);
    return s;
}

static void picker_position_edit(const picker_layout* layout) {
    settings_layout s       = picker_get_settings(layout);
    u8              visible = g_picker.settings_open && s.show_edit;
    if (visible) {
        SetWindowPos(g_picker.edit, HWND_TOP, s.edit.left + 6, s.edit.top + 6, s.edit.right - s.edit.left - 12, 15, SWP_NOACTIVATE);
    }
    ShowWindow(g_picker.edit, visible ? SW_SHOWNA : SW_HIDE);
}

static i32 picker_hit_test(const picker_layout* layout, i32 x, i32 y) {
    if (g_picker.settings_open) {
        settings_layout s = picker_get_settings(layout);
        if (ui_in_rect(&s.panel, x, y)) {
            for (i32 i = 0; i < 4; ++i) {
                if (ui_in_rect(&s.res[i], x, y)) {
                    return ui_id_res + i;
                }
            }
            for (i32 i = 0; i < 3; ++i) {
                if (ui_in_rect(&s.fps[i], x, y)) {
                    return ui_id_fps + i;
                }
            }
            return ui_id_panel;
        }
    }
    if (ui_in_rect(&layout->gear, x, y)) {
        return ui_id_gear;
    }
    for (i32 i = 0; i < 3; ++i) {
        if (ui_in_rect(&layout->tab[i], x, y)) {
            return ui_id_tab + i;
        }
    }
    RECT thumb = picker_scroll_thumb(layout);
    if (thumb.bottom > thumb.top && x >= thumb.left - 6 && x < thumb.right + 6 && y >= thumb.top && y < thumb.bottom) {
        return ui_id_scroll;
    }
    if (g_picker.list && ui_in_rect(&layout->grid, x, y)) {
        for (u32 i = 0; i < g_picker.list->count; ++i) {
            RECT tile = picker_tile_rect(layout, i);
            if (ui_in_rect(&tile, x, y)) {
                return ui_id_tile + (i32) i;
            }
        }
    }
    return 0;
}

static void picker_reload(HWND hwnd, u8 clear) {
    if (clear) {
        ss_list_free(g_picker.list);
        g_picker.list   = NULL;
        g_picker.scroll = 0;
    }
    g_picker.hot     = 0;
    g_picker.loading = 1;
    ++g_picker.generation;
    ss_start_load(hwnd, g_picker.tab + 1, g_picker.generation);
    InvalidateRect(hwnd, NULL, FALSE);
}

static void picker_paint_tile(HDC dc, const picker_layout* layout, u32 index, const ss_source* source) {
    RECT tile  = picker_tile_rect(layout, index);
    RECT image = ui_make_rect(tile.left, tile.top, layout->tile_w, layout->thumb_h);
    u8   hot   = g_picker.hot == ui_id_tile + (i32) index;

    ui_fill(dc, &image, ui_bg_dark);
    if (source->thumb) {
        HDC     src = CreateCompatibleDC(dc);
        HGDIOBJ old = SelectObject(src, source->thumb);
        SetStretchBltMode(dc, HALFTONE);
        SetBrushOrgEx(dc, 0, 0, NULL);
        StretchBlt(dc, image.left, image.top, layout->tile_w, layout->thumb_h, src, 0, 0, ss_thumb_w, ss_thumb_h, SRCCOPY);
        SelectObject(src, old);
        DeleteDC(src);
    } else if (source->icon) {
        DrawIconEx(dc, (image.left + image.right) / 2 - 16, (image.top + image.bottom) / 2 - 16, source->icon, 32, 32, 0, NULL, DI_NORMAL);
    }

    COLORREF border = hot ? ui_fg : ui_border;
    RECT     top    = { image.left, image.top, image.right, image.top + 1 };
    RECT     bottom = { image.left, image.bottom - 1, image.right, image.bottom };
    RECT     left   = { image.left, image.top, image.left + 1, image.bottom };
    RECT     right  = { image.right - 1, image.top, image.right, image.bottom };
    ui_fill(dc, &top, border);
    ui_fill(dc, &bottom, border);
    ui_fill(dc, &left, border);
    ui_fill(dc, &right, border);

    i32 text_x = tile.left + 2;
    if (source->kind == ss_kind_application && source->icon) {
        DrawIconEx(dc, text_x, image.bottom + (ui_caption - 16) / 2, source->icon, 16, 16, 0, NULL, DI_NORMAL);
        text_x += 22;
    }
    RECT label = ui_make_rect(text_x, image.bottom, tile.right - text_x, ui_caption);
    ui_text(dc, source->name, label, ui_fg, DT_LEFT | DT_VCENTER | DT_END_ELLIPSIS);
}

static void picker_paint_option(HDC dc, const RECT* rect, const wchar_t* text, u8 selected, u8 hot) {
    COLORREF fill = selected ? ui_bg_hot : (hot ? ui_bg_bar : ui_bg);
    ui_box(dc, rect, fill, ui_border);
    ui_text(dc, text, *rect, ui_fg, DT_CENTER | DT_VCENTER);
}

static void picker_paint_settings(HDC dc, const picker_layout* layout) {
    settings_layout s = picker_get_settings(layout);
    ui_box(dc, &s.panel, ui_bg_dark, ui_border);

    RECT label = ui_make_rect(s.panel.left + 12, s.panel.top + 6, 200, 18);
    ui_text(dc, L"Resolution", label, ui_fg_dim, DT_LEFT | DT_VCENTER);
    for (i32 i = 0; i < 4; ++i) {
        wchar_t text[16];
        _snwprintf(text, ArrayCount(text), L"%up", g_ui_heights[i]);
        picker_paint_option(dc, &s.res[i], text, g_ss_settings.height == g_ui_heights[i], g_picker.hot == ui_id_res + i);
    }

    label = ui_make_rect(s.panel.left + 12, s.panel.top + 58, 200, 18);
    ui_text(dc, L"Frame rate", label, ui_fg_dim, DT_LEFT | DT_VCENTER);
    for (i32 i = 0; i < 3; ++i) {
        wchar_t text[16];
        if (i < 2) {
            _snwprintf(text, ArrayCount(text), L"%u fps", g_ui_fps_presets[i]);
        } else {
            wcscpy(text, L"Custom");
        }
        picker_paint_option(dc, &s.fps[i], text, g_ss_settings.fps_mode == (u32) i, g_picker.hot == ui_id_fps + i);
    }
    if (s.show_edit) {
        ui_box(dc, &s.edit, ui_bg_bar, ui_border);
        RECT unit = ui_make_rect(s.edit.right + 8, s.edit.top, 120, 26);
        ui_text(dc, L"fps (1 to 240)", unit, ui_fg_dim, DT_LEFT | DT_VCENTER);
    }
}

static void picker_paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC         screen = BeginPaint(hwnd, &ps);
    RECT        client;
    GetClientRect(hwnd, &client);
    i32 width  = client.right;
    i32 height = client.bottom;

    HDC     dc  = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, width, height);
    HGDIOBJ old = SelectObject(dc, bmp);
    ui_fill(dc, &client, ui_bg);

    picker_layout layout = picker_get_layout(width, height);
    picker_clamp_scroll(&layout);

    ui_fill(dc, &layout.tabs, ui_bg_dark);
    static const wchar_t* tab_names[3] = { L"Applications", L"Entire Screen", L"Devices" };
    for (i32 i = 0; i < 3; ++i) {
        u8 selected = g_picker.tab == (u32) i;
        u8 hot      = g_picker.hot == ui_id_tab + i;
        if (selected) {
            ui_fill(dc, &layout.tab[i], ui_bg_hot);
        } else if (hot) {
            ui_fill(dc, &layout.tab[i], ui_bg_bar);
        }
        ui_text(dc, tab_names[i], layout.tab[i], (selected || hot) ? ui_fg : ui_fg_dim, DT_CENTER | DT_VCENTER);
    }

    SaveDC(dc);
    IntersectClipRect(dc, layout.grid.left, layout.grid.top, layout.track.right, layout.grid.bottom);
    if (g_picker.list && g_picker.list->count) {
        for (u32 i = 0; i < g_picker.list->count; ++i) {
            RECT tile = picker_tile_rect(&layout, i);
            if (tile.bottom < layout.grid.top || tile.top > layout.grid.bottom) {
                continue;
            }
            picker_paint_tile(dc, &layout, i, &g_picker.list->items[i]);
        }
        RECT thumb = picker_scroll_thumb(&layout);
        if (thumb.bottom > thumb.top) {
            ui_fill(dc, &thumb, (g_picker.hot == ui_id_scroll || g_picker.dragging) ? ui_fg_dim : ui_bg_hot);
        }
    } else {
        const wchar_t* message = g_picker.loading ? L"Loading..." : g_picker.tab == 2 ? L"No devices found"
                                                                                      : L"Nothing to share";
        ui_text(dc, message, layout.grid, ui_fg_dim, DT_CENTER | DT_VCENTER);
    }
    RestoreDC(dc, -1);

    wchar_t quality[48];
    wchar_t text[64];
    picker_quality_text(quality, ArrayCount(quality));
    _snwprintf(text, ArrayCount(text), L"Quality: %ls", quality);
    RECT footer = ui_make_rect(ui_pad, layout.gear.top, 300, 28);
    ui_text(dc, text, footer, ui_fg_dim, DT_LEFT | DT_VCENTER);

    picker_paint_option(dc, &layout.gear, L"Settings", g_picker.settings_open, g_picker.hot == ui_id_gear);

    if (g_picker.settings_open) {
        picker_paint_settings(dc, &layout);
    }

    BitBlt(screen, 0, 0, width, height, dc, 0, 0, SRCCOPY);
    SelectObject(dc, old);
    DeleteObject(bmp);
    DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

static void picker_set_tab(HWND hwnd, u32 tab) {
    if (tab == g_picker.tab) {
        return;
    }
    g_picker.tab = tab;
    picker_reload(hwnd, 1);
}

static void picker_start_share(HWND hwnd, u32 index) {
    if (!g_picker.list || index >= g_picker.list->count) {
        return;
    }
    const ss_source* source = &g_picker.list->items[index];
    if (source->kind == ss_kind_application && !IsWindow(source->window)) {
        picker_reload(hwnd, 0);
        return;
    }

    ss_config config = { 0 };
    config.kind      = source->kind;
    config.window    = source->window;
    config.screen    = source->screen;
    wcscpy(config.name, source->name);
    wcscpy(config.device_id, source->device_id);
    config.height   = g_ss_settings.height;
    config.fps      = g_ss_settings.fps;
    config.quality  = g_ss_settings.quality;
    config.hardware = g_ss_settings.hardware;

    ShowWindow(hwnd, SW_HIDE);
    ss_begin(&config);
    if (g_control_hwnd) {
        PostMessageW(g_control_hwnd, wm_ss_state, 0, 0);
    }
}

static void picker_settings(HWND hwnd, u8 open) {
    g_picker.settings_open = open;
    RECT client;
    GetClientRect(hwnd, &client);
    picker_layout layout = picker_get_layout(client.right, client.bottom);
    picker_position_edit(&layout);
    InvalidateRect(hwnd, NULL, FALSE);
}

static void picker_refresh_all(HWND hwnd) {
    InvalidateRect(hwnd, NULL, FALSE);
    if (g_control_hwnd) {
        InvalidateRect(g_control_hwnd, NULL, FALSE);
    }
}

static void picker_set_fps_mode(HWND hwnd, u32 mode) {
    g_ss_settings.fps_mode = mode;
    if (mode < 2) {
        g_ss_settings.fps = g_ui_fps_presets[mode];
    } else {
        wchar_t text[8];
        _snwprintf(text, ArrayCount(text), L"%u", g_ss_settings.fps);
        g_picker.syncing = 1;
        SetWindowTextW(g_picker.edit, text);
        g_picker.syncing = 0;
    }
    RECT client;
    GetClientRect(hwnd, &client);
    picker_layout layout = picker_get_layout(client.right, client.bottom);
    picker_position_edit(&layout);
    if (mode == 2) {
        SetFocus(g_picker.edit);
        SendMessageW(g_picker.edit, EM_SETSEL, 0, -1);
    }
    picker_refresh_all(hwnd);
}

static void picker_on_fps_edited(HWND hwnd) {
    if (g_picker.syncing) {
        return;
    }
    wchar_t text[8] = { 0 };
    GetWindowTextW(g_picker.edit, text, ArrayCount(text));
    u32 value = (u32) wcstoul(text, NULL, 10);
    if (value >= 1 && value <= 240) {
        g_ss_settings.fps = value;
        picker_refresh_all(hwnd);
    }
}

static void picker_click(HWND hwnd, i32 id) {
    if (g_picker.settings_open && id != ui_id_panel && id != ui_id_gear &&
        !(id >= ui_id_res && id < ui_id_res + 4) && !(id >= ui_id_fps && id < ui_id_fps + 3)) {
        picker_settings(hwnd, 0);
        return;
    }

    if (id >= ui_id_tab && id < ui_id_tab + 3) {
        picker_set_tab(hwnd, (u32) (id - ui_id_tab));
    } else if (id == ui_id_gear) {
        picker_settings(hwnd, !g_picker.settings_open);
    } else if (id >= ui_id_res && id < ui_id_res + 4) {
        g_ss_settings.height = g_ui_heights[id - ui_id_res];
        picker_refresh_all(hwnd);
    } else if (id >= ui_id_fps && id < ui_id_fps + 3) {
        picker_set_fps_mode(hwnd, (u32) (id - ui_id_fps));
    }
}

static LRESULT CALLBACK picker_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_CREATE: {
            g_picker.edit = CreateWindowExW(0, L"EDIT", L"60", WS_CHILD | ES_NUMBER | ES_CENTER | ES_AUTOHSCROLL,
                                            0, 0, 48, 15, hwnd, (HMENU) ui_id_edit, NULL, NULL);
            SendMessageW(g_picker.edit, WM_SETFONT, (WPARAM) g_ui_font, TRUE);
            SendMessageW(g_picker.edit, EM_SETLIMITTEXT, 3, 0);
            g_picker.edit_brush = CreateSolidBrush(ui_bg_bar);
            ui_theme_title_bar(hwnd);
            return 0;
        }

        case WM_PAINT: {
            picker_paint(hwnd);
            return 0;
        }

        case WM_ERASEBKGND: {
            return 1;
        }

        case WM_CTLCOLOREDIT: {
            HDC dc = (HDC) wparam;
            SetTextColor(dc, ui_fg);
            SetBkColor(dc, ui_bg_bar);
            return (LRESULT) g_picker.edit_brush;
        }

        case WM_COMMAND: {
            if (LOWORD(wparam) == ui_id_edit && HIWORD(wparam) == EN_CHANGE) {
                picker_on_fps_edited(hwnd);
            }
            return 0;
        }

        case wm_ss_loaded: {
            ss_source_list* list = (ss_source_list*) lparam;
            if (list->generation != g_picker.generation || list->kind != g_picker.tab + 1) {
                ss_list_free(list);
                return 0;
            }
            ss_list_free(g_picker.list);
            g_picker.list    = list;
            g_picker.loading = 0;
            g_picker.hot     = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_MOUSEMOVE: {
            i32  x = (i32) (i16) LOWORD(lparam);
            i32  y = (i32) (i16) HIWORD(lparam);
            RECT client;
            GetClientRect(hwnd, &client);
            picker_layout layout = picker_get_layout(client.right, client.bottom);

            if (g_picker.dragging) {
                i32  view   = layout.grid.bottom - layout.grid.top;
                RECT thumb  = picker_scroll_thumb(&layout);
                i32  travel = view - (thumb.bottom - thumb.top);
                if (travel > 0) {
                    g_picker.scroll = g_picker.drag_start_scroll +
                                      (i32) ((i64) (y - g_picker.drag_start_y) * picker_max_scroll(&layout) / travel);
                    picker_clamp_scroll(&layout);
                    InvalidateRect(hwnd, NULL, FALSE);
                }
                return 0;
            }

            i32 id = picker_hit_test(&layout, x, y);
            if (id != g_picker.hot) {
                g_picker.hot = id;
                InvalidateRect(hwnd, NULL, FALSE);
            }
            if (!g_picker.tracking) {
                TRACKMOUSEEVENT track = { sizeof track, TME_LEAVE, hwnd, 0 };
                TrackMouseEvent(&track);
                g_picker.tracking = 1;
            }
            return 0;
        }

        case WM_MOUSELEAVE: {
            g_picker.tracking = 0;
            g_picker.hot      = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_SETCURSOR: {
            if (LOWORD(lparam) == HTCLIENT) {
                // 32649 is IDC_HAND and 32512 is IDC_ARROW, the names are excluded by the defines in build.c
                u8 clickable = g_picker.hot != 0 && g_picker.hot != ui_id_panel;
                SetCursor(LoadCursorW(NULL, MAKEINTRESOURCEW(clickable ? 32649 : 32512)));
                return TRUE;
            }
            break;
        }

        case WM_LBUTTONDOWN: {
            i32  x = (i32) (i16) LOWORD(lparam);
            i32  y = (i32) (i16) HIWORD(lparam);
            RECT client;
            GetClientRect(hwnd, &client);
            picker_layout layout = picker_get_layout(client.right, client.bottom);
            i32           id     = picker_hit_test(&layout, x, y);

            SetFocus(hwnd);
            if (id == ui_id_scroll) {
                g_picker.dragging          = 1;
                g_picker.drag_start_y      = y;
                g_picker.drag_start_scroll = g_picker.scroll;
                SetCapture(hwnd);
            } else if (id >= ui_id_tile && !g_picker.settings_open) {
                g_picker.pressed = id;
            } else {
                picker_click(hwnd, id);
            }
            return 0;
        }

        case WM_LBUTTONUP: {
            if (g_picker.dragging) {
                g_picker.dragging = 0;
                ReleaseCapture();
                InvalidateRect(hwnd, NULL, FALSE);
                return 0;
            }
            i32  x = (i32) (i16) LOWORD(lparam);
            i32  y = (i32) (i16) HIWORD(lparam);
            RECT client;
            GetClientRect(hwnd, &client);
            picker_layout layout  = picker_get_layout(client.right, client.bottom);
            i32           id      = picker_hit_test(&layout, x, y);
            i32           pressed = g_picker.pressed;
            g_picker.pressed      = 0;
            if (pressed && id == pressed) {
                picker_start_share(hwnd, (u32) (id - ui_id_tile));
            }
            return 0;
        }

        case WM_MOUSEWHEEL: {
            RECT client;
            GetClientRect(hwnd, &client);
            picker_layout layout = picker_get_layout(client.right, client.bottom);
            g_picker.scroll -= (i32) (i16) HIWORD(wparam) * 70 / 120;
            picker_clamp_scroll(&layout);
            g_picker.hot = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_KEYDOWN: {
            if (wparam == VK_ESCAPE) {
                if (g_picker.settings_open) {
                    picker_settings(hwnd, 0);
                } else {
                    ShowWindow(hwnd, SW_HIDE);
                }
            } else if (wparam == VK_F5) {
                picker_reload(hwnd, 0);
            }
            return 0;
        }

        case WM_CLOSE: {
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        }

        case WM_DESTROY: {
            DeleteObject(g_picker.edit_brush);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static void picker_show(void) {
    HWND hwnd = g_picker_hwnd;
    if (!hwnd) {
        return;
    }
    g_picker.settings_open = 0;
    ShowWindow(g_picker.edit, SW_HIDE);
    ui_center_on_screen(hwnd);
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
    SetFocus(hwnd);
    picker_reload(hwnd, g_picker.list == NULL);
}

static RECT control_button_rect(i32 id, i32 width) {
    Unreferenced(width);
    return id == ui_id_c_mute ? ui_make_rect(220, 0, 120, 28) : ui_make_rect(id == ui_id_c_start ? 0 : 110, 0, 110, 28);
}

static i32 control_hit_test(i32 x, i32 y, i32 width) {
    for (i32 id = ui_id_c_start; id <= ui_id_c_mute; ++id) {
        RECT rect = control_button_rect(id, width);
        if (id == ui_id_c_mute && !g_ss_active) {
            continue;
        }
        if (ui_in_rect(&rect, x, y)) {
            return id;
        }
    }
    return 0;
}

static void control_paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC         screen = BeginPaint(hwnd, &ps);
    RECT        client;
    GetClientRect(hwnd, &client);
    i32 width  = client.right;
    i32 height = client.bottom;

    HDC     dc  = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, width, height);
    HGDIOBJ old = SelectObject(dc, bmp);
    ui_fill(dc, &client, ui_bg);

    RECT bar = ui_make_rect(0, 0, width, 28);
    ui_fill(dc, &bar, ui_bg_bar);
    for (i32 id = ui_id_c_start; id <= ui_id_c_mute; ++id) {
        if (id == ui_id_c_mute && !g_ss_active) {
            continue;
        }
        RECT rect    = control_button_rect(id, width);
        u8   enabled = id == ui_id_c_start || g_ss_active;
        if (enabled && g_control_hot == id) {
            ui_fill(dc, &rect, ui_bg_hot);
        }
        const wchar_t* label = id == ui_id_c_start ? L"Screenshare" : id == ui_id_c_stop ? L"Stop sharing"
                                                                  : audio_is_muted()     ? L"Unmute audio"
                                                                                         : L"Mute audio";
        ui_text(dc, label, rect, enabled ? ui_fg : ui_fg_dim, DT_CENTER | DT_VCENTER);
    }

    wchar_t line[256];
    if (g_ss_active) {
        _snwprintf(line, ArrayCount(line), L"Sharing: %ls", g_ss_current.name);
        line[ArrayCount(line) - 1] = 0;
    } else {
        wcscpy(line, L"Not sharing anything");
    }
    RECT state = ui_make_rect(12, 44, width - 24, 20);
    ui_text(dc, line, state, g_ss_active ? ui_fg : ui_fg_dim, DT_LEFT | DT_VCENTER | DT_END_ELLIPSIS);

    wchar_t quality[48];
    if (g_ss_active) {
        _snwprintf(quality, ArrayCount(quality), L"%up, %u fps", g_ss_current.height, g_ss_current.fps);
        quality[ArrayCount(quality) - 1] = 0;
    } else {
        picker_quality_text(quality, ArrayCount(quality));
    }
    _snwprintf(line, ArrayCount(line), L"Quality: %ls", quality);
    RECT quality_rect = ui_make_rect(12, 68, width - 24, 20);
    ui_text(dc, line, quality_rect, ui_fg_dim, DT_LEFT | DT_VCENTER);

    RECT extra = ui_make_rect(12, 92, width - 24, 20);
    if (g_ss_active) {
        _snwprintf(line, ArrayCount(line), L"Encoder: %ls%ls", g_ss_stats.encoder, g_ss_stats.hardware ? L" (GPU)" : L"");
        line[ArrayCount(line) - 1] = 0;
        ui_text(dc, line, extra, ui_fg_dim, DT_LEFT | DT_VCENTER | DT_END_ELLIPSIS);

        extra.top += 22;
        extra.bottom += 22;
        if (g_ss_stats.fps > 0) {
            _snwprintf(line, ArrayCount(line), L"Output: %.1f fps, %.0f kbps, %.1f ms per frame", g_ss_stats.fps,
                       g_ss_stats.kbps, g_ss_stats.work_ms);
        } else {
            wcscpy(line, L"Output: starting...");
        }
        ui_text(dc, line, extra, ui_fg_dim, DT_LEFT | DT_VCENTER);

        if (g_stream_text[0]) {
            extra.top += 22;
            extra.bottom += 22;
            _snwprintf(line, ArrayCount(line), L"Go Live: %ls", g_stream_text);
            line[ArrayCount(line) - 1] = 0;
            ui_text(dc, line, extra, g_stream_state == stream_state_live ? ui_fg : ui_fg_dim, DT_LEFT | DT_VCENTER | DT_END_ELLIPSIS);
        }
    } else if (g_ss_error[0]) {
        ui_text(dc, g_ss_error, extra, ui_fg, DT_LEFT | DT_VCENTER | DT_END_ELLIPSIS);
    }

    RECT hint = ui_make_rect(12, height - 28, width - 24, 20);
    ui_text(dc, L"Ctrl+Shift+S shows or hides this window", hint, ui_fg_dim, DT_LEFT | DT_VCENTER);

    BitBlt(screen, 0, 0, width, height, dc, 0, 0, SRCCOPY);
    SelectObject(dc, old);
    DeleteObject(bmp);
    DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

static void control_toggle(HWND hwnd) {
    u8 in_voice = go_live_in_voice();
    if (IsWindowVisible(hwnd) && (GetForegroundWindow() == hwnd || !in_voice)) {
        ShowWindow(hwnd, SW_HIDE);
        if (g_picker_hwnd) {
            ShowWindow(g_picker_hwnd, SW_HIDE);
        }
        return;
    }
    if (!in_voice) {
        return;
    }
    ui_center_on_screen(hwnd);
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
    InvalidateRect(hwnd, NULL, FALSE);
}

static void control_poll_hotkey(HWND hwnd) {
    static u8 was_down;

    u8 down = (GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(VK_SHIFT) & 0x8000) &&
              (GetAsyncKeyState('S') & 0x8000) && !(GetAsyncKeyState(VK_MENU) & 0x8000);
    if (down && !was_down) {
        DWORD pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &pid);
        // Only react while one of Ripcord's own windows is focused
        if (pid == GetCurrentProcessId()) {
            control_toggle(hwnd);
        }
    }
    was_down = down;
}

static LRESULT CALLBACK control_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_CREATE: {
            ui_theme_title_bar(hwnd);
            SetTimer(hwnd, ui_timer_id, ui_timer_ms, NULL);
            return 0;
        }

        case WM_TIMER: {
            if (wparam == ui_timer_id) {
                control_poll_hotkey(hwnd);
                static u32 ticks;
                if (g_ss_active && ++ticks % (1000 / ui_timer_ms) == 0 && IsWindowVisible(hwnd)) {
                    InvalidateRect(hwnd, NULL, FALSE);
                }
                go_live_tick();
                if (g_ss_active && g_stream_state == stream_state_failed) {
                    wcscpy(g_ss_error, g_stream_text);
                    ss_end();
                    g_stream_state = stream_state_failed;
                    InvalidateRect(hwnd, NULL, FALSE);
                }
            }
            return 0;
        }

        case WM_PAINT: {
            control_paint(hwnd);
            return 0;
        }

        case WM_ERASEBKGND: {
            return 1;
        }

        case wm_ss_state: {
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_MOUSEMOVE: {
            RECT client;
            GetClientRect(hwnd, &client);
            i32 id = control_hit_test((i32) (i16) LOWORD(lparam), (i32) (i16) HIWORD(lparam), client.right);
            if (id != g_control_hot) {
                g_control_hot = id;
                InvalidateRect(hwnd, NULL, FALSE);
            }
            TRACKMOUSEEVENT track = { sizeof track, TME_LEAVE, hwnd, 0 };
            TrackMouseEvent(&track);
            return 0;
        }

        case WM_MOUSELEAVE: {
            g_control_hot = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_SETCURSOR: {
            if (LOWORD(lparam) == HTCLIENT) {
                u8 clickable = g_control_hot == ui_id_c_start || ((g_control_hot == ui_id_c_stop || g_control_hot == ui_id_c_mute) && g_ss_active);
                SetCursor(LoadCursorW(NULL, MAKEINTRESOURCEW(clickable ? 32649 : 32512)));
                return TRUE;
            }
            break;
        }

        case WM_LBUTTONDOWN: {
            RECT client;
            GetClientRect(hwnd, &client);
            i32 id = control_hit_test((i32) (i16) LOWORD(lparam), (i32) (i16) HIWORD(lparam), client.right);
            if (id == ui_id_c_start) {
                picker_show();
            } else if (id == ui_id_c_stop && g_ss_active) {
                ss_end();
                InvalidateRect(hwnd, NULL, FALSE);
            } else if (id == ui_id_c_mute && g_ss_active) {
                audio_toggle_mute();
                InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;
        }

        case WM_CLOSE: {
            ShowWindow(hwnd, SW_HIDE);
            if (g_picker_hwnd) {
                ShowWindow(g_picker_hwnd, SW_HIDE);
            }
            return 0;
        }

        case WM_DESTROY: {
            KillTimer(hwnd, ui_timer_id);
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

static DWORD WINAPI ss_window_thread(LPVOID param) {
    Unreferenced(param);

    g_ui_font = (HFONT) GetStockObject(DEFAULT_GUI_FONT);

    WNDCLASSW wc     = { 0 };
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.hCursor       = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.lpfnWndProc   = control_proc;
    wc.lpszClassName = ss_control_class;
    if (!RegisterClassW(&wc)) {
        return 0;
    }
    wc.lpfnWndProc   = picker_proc;
    wc.lpszClassName = ss_picker_class;
    if (!RegisterClassW(&wc)) {
        return 0;
    }

    RECT control_rect = { 0, 0, 440, 190 };
    AdjustWindowRect(&control_rect, WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    g_control_hwnd = CreateWindowExW(0, ss_control_class, L"Screenshare", WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                     CW_USEDEFAULT, CW_USEDEFAULT, control_rect.right - control_rect.left,
                                     control_rect.bottom - control_rect.top, NULL, NULL, wc.hInstance, NULL);
    if (!g_control_hwnd) {
        return 0;
    }

    RECT picker_rect = { 0, 0, ui_picker_w, ui_picker_h };
    AdjustWindowRect(&picker_rect, WS_CAPTION | WS_SYSMENU, FALSE);
    g_picker_hwnd = CreateWindowExW(0, ss_picker_class, L"Share your screen", WS_CAPTION | WS_SYSMENU,
                                    CW_USEDEFAULT, CW_USEDEFAULT, picker_rect.right - picker_rect.left,
                                    picker_rect.bottom - picker_rect.top, g_control_hwnd, NULL, wc.hInstance, NULL);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

static void ss_start(void) {
    HANDLE thread = CreateThread(NULL, 0, ss_window_thread, NULL, 0, NULL);
    if (thread) {
        CloseHandle(thread);
    }
}

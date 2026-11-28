// NOTE(Xelph): What ui.cpp, the Qt window, calls. It is a separate translation unit so none of this can be static

u8 ss_api_in_voice(void) {
    return go_live_in_voice();
}

u8 ss_api_active(void) {
    return g_ss_active;
}

u8 ss_api_start(u32 kind, void* window, const RECT* screen, const wchar_t* name, u32 height, u32 fps, u32 quality) {
    ss_config config = { .kind = kind, .window = (HWND) window, .height = height, .fps = fps, .quality = quality };
    if (screen) {
        config.screen = *screen;
    }
    wcsncpy(config.name, name, ArrayCount(config.name) - 1);
    return ss_begin(&config);
}

void ss_api_stop(void) {
    ss_end();
}

u8 ss_api_muted(void) {
    return audio_is_muted();
}

void ss_api_toggle_mute(void) {
    audio_toggle_mute();
}

// Called on a timer by the window: Go Live gives up after a timeout, and a failed stream has to stop the capture too
void ss_api_tick(void) {
    go_live_tick();
    if (g_ss_active && g_stream_state == stream_state_failed) {
        wcscpy(g_ss_error, g_stream_text);
        ss_end();
        g_stream_state = stream_state_failed;
    }
}

void ss_api_status(wchar_t* out, u32 count) {
    if (g_ss_active) {
        _snwprintf(out, count, L"Sharing %ls: %.0f fps, %.0f kbps. %ls", g_ss_current.name, g_ss_stats.fps, g_ss_stats.kbps, g_stream_text);
    } else if (g_ss_error[0]) {
        wcsncpy(out, g_ss_error, count);
    } else if (!go_live_in_voice()) {
        wcsncpy(out, L"Join a voice channel first.", count);
    } else {
        wcsncpy(out, L"Pick a window or a screen to share.", count);
    }
    out[count - 1] = 0;
}

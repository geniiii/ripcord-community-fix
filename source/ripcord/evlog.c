static void** g_rip_ev_logger;

static void Log_Ripcord(String8 msg) {
    if (!EvLogGlobal_AddLogEvent || !g_rip_ev_logger || !*g_rip_ev_logger) {
        return;
    }

    QString str = {
        .d = QString_FromAsciiHelper(msg.cstr, (i64) msg.size),
    };
    EvLogGlobal_AddLogEvent(EvLogCategory_Application, EvLogSeverity_Info, &str);
    QString_Destructor(&str);
}

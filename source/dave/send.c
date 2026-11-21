static void DaveSendBinary(u8 opcode, const u8* payload, size_t len) {
    u8* buf = (u8*) malloc(1 + len);
    buf[0]  = opcode;
    memcpy(buf + 1, payload, len);

    QByteArray qba;
    qbytearray_constructor(&qba, (const char*) buf, (i32) (1 + len));
    qwebsocket_sendbinarymessage(g_dave.webSocket, &qba);
    qbytearray_destructor(&qba);
    free(buf);
}

static void DaveSendTransitionOp(i32 op, i32 transition_id) {
    QJsonObject d;
    qjsonobject_constructor(&d);
    QJsonInsertInt(&d, S8Lit("transition_id"), transition_id);
    SendVoiceOp(g_dave.webSocket, op, &d);
}

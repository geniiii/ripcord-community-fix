static void Dave_SendBinary(u8 opcode, const u8* payload, size_t len) {
    u8* buf = (u8*) malloc(1 + len);
    buf[0]  = opcode;
    memcpy(buf + 1, payload, len);

    QByteArray qba;
    QByteArray_Constructor(&qba, (const char*) buf, (i32) (1 + len));
    QWebSocket_SendBinaryMessage(g_dave.webSocket, &qba);
    QByteArray_Destructor(&qba);
    free(buf);
}

static void Dave_SendTransitionOp(i32 op, i32 transition_id) {
    QJsonObject d;
    QJsonObject_Constructor(&d);
    QJson_InsertInt(&d, S8Lit("transition_id"), transition_id);
    Op_SendVoice(g_dave.webSocket, op, &d);
}

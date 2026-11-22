static void Op_Send(WebSocketHelpers_SendJsonType* send, void* webSocket, i32 op, QJsonObject* d) {
    QJsonObject root;
    QJsonValue  value;
    QJsonObject_Constructor(&root);
    QJson_InsertInt(&root, S8Lit("op"), op);
    QJson_Insert(&root, S8Lit("d"), QJsonValue_ConstructorQJsonObject(&value, d));
    send(webSocket, QJsonValue_ConstructorQJsonObject(&value, &root));
    QJsonObject_Destructor(d);
    QJsonObject_Destructor(&root);
}

static void Op_SendVoice(void* webSocket, i32 op, QJsonObject* d) {
    Op_Send(WebSocketHelpers_SendJson, webSocket, op, d);
}

static void Op_SendText(void* webSocket, String8 text) {
    QString msg;
    msg.d = QString_FromAsciiHelper(text.cstr, (i64) text.size);
    QWebSocket_SendTextMessage(webSocket, &msg);
    QString_Destructor(&msg);
}

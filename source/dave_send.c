static void DaveSendBinary(void* webSocket, u8 opcode, const u8* payload, size_t len) {
    u8* buf = (u8*) malloc(1 + len);
    buf[0]  = opcode;
    if (len > 0 && payload) {
        memcpy(buf + 1, payload, len);
    }

    QByteArray qba;
    qbytearray_constructor(&qba, (const char*) buf, (i32) (1 + len));
    qwebsocket_sendbinarymessage(webSocket, &qba);
    qbytearray_destructor(&qba);
    free(buf);
}

static void DaveSendJson1Int(void* webSocket, i32 op, String8 key1, i32 val1) {
    QJsonObject          root, d;
    QJsonObject_iterator it;
    QJsonValue           value;
    QString              key;

    qjsonobject_constructor(&root);
    qjsonvalue_constructor_int(&value, op);
    key.d = qstring_from_ascii_helper("op", 2);
    qjsonobject_insert(&root, &it, &key, &value);
    qstring_destructor(&key);
    qjsonvalue_destructor(&value);

    qjsonobject_constructor(&d);
    qjsonvalue_constructor_int(&value, val1);
    key.d = qstring_from_ascii_helper(key1.cstr, (i64) key1.size);
    qjsonobject_insert(&d, &it, &key, &value);
    qstring_destructor(&key);
    qjsonvalue_destructor(&value);

    qjsonvalue_constructor_qjsonobject(&value, &d);
    key.d = qstring_from_ascii_helper("d", 1);
    qjsonobject_insert(&root, &it, &key, &value);
    qstring_destructor(&key);
    qjsonvalue_destructor(&value);

    websockethelpers_sendjson(webSocket, qjsonvalue_constructor_qjsonobject(&value, &root));
    qjsonobject_destructor(&d);
    qjsonobject_destructor(&root);
}

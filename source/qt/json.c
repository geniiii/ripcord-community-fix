static void QJsonInsert(QJsonObject* obj, String8 key, QJsonValue* value) {
    QJsonObject_iterator it;
    QString              k;
    k.d = qstring_from_ascii_helper(key.cstr, (i64) key.size);
    qjsonobject_insert(obj, &it, &k, value);
    qstring_destructor(&k);
    qjsonvalue_destructor(value);
}

static void QJsonInsertInt(QJsonObject* obj, String8 key, i32 v) {
    QJsonValue value;
    QJsonInsert(obj, key, qjsonvalue_constructor_int(&value, v));
}

static void SendVoiceOp(void* webSocket, i32 op, QJsonObject* d) {
    QJsonObject root;
    QJsonValue  value;
    qjsonobject_constructor(&root);
    QJsonInsertInt(&root, S8Lit("op"), op);
    QJsonInsert(&root, S8Lit("d"), qjsonvalue_constructor_qjsonobject(&value, d));
    websockethelpers_sendjson(webSocket, qjsonvalue_constructor_qjsonobject(&value, &root));
    qjsonobject_destructor(d);
    qjsonobject_destructor(&root);
}

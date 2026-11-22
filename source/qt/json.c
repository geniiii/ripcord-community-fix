static void QJson_Insert(QJsonObject* obj, String8 key, QJsonValue* value) {
    QJsonObject_iterator it;
    QString              k;
    k.d = QString_FromAsciiHelper(key.cstr, (i64) key.size);
    QJsonObject_Insert(obj, &it, &k, value);
    QString_Destructor(&k);
    QJsonValue_Destructor(value);
}

static void QJson_InsertInt(QJsonObject* obj, String8 key, i32 v) {
    QJsonValue value;
    QJson_Insert(obj, key, QJsonValue_ConstructorInt(&value, v));
}

static QJsonValue* QJson_FromFlake(QJsonValue* value, u64 id) {
    FlakeId flake = {
        .u = id,
    };
    QString str;
    QJsonValue_ConstructorQString(value, FlakeId_ToString(&flake, &str));
    QString_Destructor(&str);
    return value;
}

static void QJson_InsertFlake(QJsonObject* obj, String8 key, u64 id) {
    QJsonValue value;
    QJson_Insert(obj, key, QJson_FromFlake(&value, id));
}

static void QJson_AppendFlake(QJsonArray* arr, u64 id) {
    QJsonValue value;
    QJsonArray_Append(arr, QJson_FromFlake(&value, id));
    QJsonValue_Destructor(&value);
}

static void QJson_InsertArray(QJsonObject* obj, String8 key, QJsonArray* arr) {
    QJsonValue value;
    QJson_Insert(obj, key, QJsonValue_ConstructorQJsonArray(&value, arr));
}

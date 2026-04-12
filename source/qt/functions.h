#define WRITE_DATAGRAM(name) i64 name(void* this, u8* data, i64 size, void* addr, u16 port)
typedef WRITE_DATAGRAM(WriteDatagramType);

#define READ_DATAGRAM(name) i64 name(void* this, char* data, i64 size, void* address, u16* port)
typedef READ_DATAGRAM(ReadDatagramType);

#define QSTRING_SET_FROM_QLATIN1STRING(name) QString* name(QString* str, QLatin1String lstr)
typedef QSTRING_SET_FROM_QLATIN1STRING(QStringSetFromQLatin1StringType);

#define QJSONOBJECT_CONSTRUCTOR(name) QJsonObject* name(QJsonObject* this)
typedef QJSONOBJECT_CONSTRUCTOR(QJsonObjectConstructorType);

#define QJSONVALUE_CONSTRUCTOR_INT(name) QJsonValue* name(QJsonValue* this, i32 value)
typedef QJSONVALUE_CONSTRUCTOR_INT(QJsonValueConstructorIntType);

#define QJSONVALUE_CONSTRUCTOR_DOUBLE(name) QJsonValue* name(QJsonValue* this, double value)
typedef QJSONVALUE_CONSTRUCTOR_DOUBLE(QJsonValueConstructorDoubleType);

#define QJSONVALUE_CONSTRUCTOR_QJSONOBJECT(name) QJsonValue* name(QJsonValue* this, const QJsonObject* obj)
typedef QJSONVALUE_CONSTRUCTOR_QJSONOBJECT(QJsonValueConstructorQJsonObjectType);

#define QSTRING_FROM_ASCII_HELPER(name) QTypedArrayData* name(const char* str, i64 len)
typedef QSTRING_FROM_ASCII_HELPER(QStringFromAsciiHelperType);

#define QSTRING_TOUTF8(name) QByteArray* name(const QString* this, QByteArray* out)
typedef QSTRING_TOUTF8(QStringToUtf8Type);

#define QJSONOBJECT_INSERT(name) QJsonObject_iterator* name(QJsonObject* this, QJsonObject_iterator* retstr, const QString* key, const QJsonValue* value)
typedef QJSONOBJECT_INSERT(QJsonObjectInsertType);

#define QSTRING_DESTRUCTOR(name) void name(QString* this)
typedef QSTRING_DESTRUCTOR(QStringDestructorType);

#define QJSONVALUE_DESTRUCTOR(name) void name(QJsonValue* this)
typedef QJSONVALUE_DESTRUCTOR(QJsonValueDestructorType);

#define QHOSTADDRESS_CONSTRUCTOR_FROM_QSTRING(name) QHostAddress* name(QHostAddress* this, const QString* address)
typedef QHOSTADDRESS_CONSTRUCTOR_FROM_QSTRING(QHostAddressConstructorFromQStringType);

#define QHOSTADDRESS_DESTRUCTOR(name) void name(QHostAddress* this)
typedef QHOSTADDRESS_DESTRUCTOR(QHostAddressDestructorType);

#define QJSONOBJECT_DESTRUCTOR(name) void name(void* this)
typedef QJSONOBJECT_DESTRUCTOR(QJsonObjectDestructorType);

#define WEBSOCKETHELPERS_SENDJSON(name) void name(void* webSocket, QJsonValue* jsonVal)
typedef WEBSOCKETHELPERS_SENDJSON(WebSocketHelpersSendJsonType);

#define QTIMER_STOP(name) void name(void* timer)
typedef QTIMER_STOP(QTimerStopType);

#define QDATETIME_CURRENTMSECSINCEEPOCH(name) u64 name()
typedef QDATETIME_CURRENTMSECSINCEEPOCH(QDateTimeCurrentMSecsSinceEpochType);

#define QBYTEARRAY_CONSTRUCTOR(name) void* name(void* this, const char* data, i32 size)
typedef QBYTEARRAY_CONSTRUCTOR(QByteArrayConstructorType);

#define QBYTEARRAY_DESTRUCTOR(name) void name(void* this)
typedef QBYTEARRAY_DESTRUCTOR(QByteArrayDestructorType);

#define QWEBSOCKET_SENDBINARYMESSAGE(name) i64 name(void* this, const void* data)
typedef QWEBSOCKET_SENDBINARYMESSAGE(QWebSocketSendBinaryMessageType);

#define QWEBSOCKET_SENDTEXTMESSAGE(name) i64 name(void* this, const QString* message)
typedef QWEBSOCKET_SENDTEXTMESSAGE(QWebSocketSendTextMessageType);

#define QOBJECT_CONNECTIMPL(name) void name(void* retval, const void* sender, void** signal, const void* receiver, void** slot, void* slotObj, i32 connType, const i32* types, const void* senderMeta)
typedef QOBJECT_CONNECTIMPL(QObjectConnectImplType);

static WriteDatagramType*                      write_datagram;
static ReadDatagramType*                       read_datagram;
static QStringSetFromQLatin1StringType*        qstring_set_from_qlatin1string;
static QJsonObjectConstructorType*             qjsonobject_constructor;
static QJsonValueConstructorIntType*           qjsonvalue_constructor_int;
static QJsonValueConstructorDoubleType*        qjsonvalue_constructor_double;
static QJsonValueConstructorQJsonObjectType*   qjsonvalue_constructor_qjsonobject;
static QStringFromAsciiHelperType*             qstring_from_ascii_helper;
static QStringToUtf8Type*                      qstring_toutf8;
static QJsonObjectInsertType*                  qjsonobject_insert;
static QStringDestructorType*                  qstring_destructor;
static QJsonValueDestructorType*               qjsonvalue_destructor;
static QJsonObjectDestructorType*              qjsonobject_destructor;
static QHostAddressConstructorFromQStringType* qhostaddress_constructor_from_qstring;
static QHostAddressDestructorType*             qhostaddress_destructor;
static WebSocketHelpersSendJsonType*           websockethelpers_sendjson;
static QTimerStopType*                         qtimer_stop;
static QDateTimeCurrentMSecsSinceEpochType*    qdatetime_currentmsecsinceepoch;
static QByteArrayConstructorType*              qbytearray_constructor;
static QByteArrayDestructorType*               qbytearray_destructor;
static QWebSocketSendBinaryMessageType*        qwebsocket_sendbinarymessage;
static QWebSocketSendTextMessageType*          qwebsocket_sendtextmessage;
static QObjectConnectImplType*                 qobject_connectimpl;

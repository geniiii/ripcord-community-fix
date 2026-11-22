#define QUDPSOCKET_WRITEDATAGRAM(name) i64 name(void* this, u8* data, i64 size, void* addr, u16 port)
typedef QUDPSOCKET_WRITEDATAGRAM(QUdpSocket_WriteDatagramType);

#define QUDPSOCKET_READDATAGRAM(name) i64 name(void* this, char* data, i64 size, void* address, u16* port)
typedef QUDPSOCKET_READDATAGRAM(QUdpSocket_ReadDatagramType);

#define QABSTRACTSOCKET_CONNECTTOHOST(name) void name(void* this, const QString* hostName, u16 port, i32 openMode, QAbstractSocket_NetworkLayerProtocol protocol)
typedef QABSTRACTSOCKET_CONNECTTOHOST(QAbstractSocket_ConnectToHostType);

#define QSTRING_SETFROMQLATIN1STRING(name) QString* name(QString* str, QLatin1String lstr)
typedef QSTRING_SETFROMQLATIN1STRING(QString_SetFromQLatin1StringType);

#define QJSONOBJECT_CONSTRUCTOR(name) QJsonObject* name(QJsonObject* this)
typedef QJSONOBJECT_CONSTRUCTOR(QJsonObject_ConstructorType);

#define QJSONVALUE_CONSTRUCTORINT(name) QJsonValue* name(QJsonValue* this, i32 value)
typedef QJSONVALUE_CONSTRUCTORINT(QJsonValue_ConstructorIntType);

#define QJSONVALUE_CONSTRUCTORDOUBLE(name) QJsonValue* name(QJsonValue* this, double value)
typedef QJSONVALUE_CONSTRUCTORDOUBLE(QJsonValue_ConstructorDoubleType);

#define QJSONVALUE_CONSTRUCTORQJSONOBJECT(name) QJsonValue* name(QJsonValue* this, const QJsonObject* obj)
typedef QJSONVALUE_CONSTRUCTORQJSONOBJECT(QJsonValue_ConstructorQJsonObjectType);

#define QJSONVALUE_CONSTRUCTORQSTRING(name) QJsonValue* name(QJsonValue* this, const QString* str)
typedef QJSONVALUE_CONSTRUCTORQSTRING(QJsonValue_ConstructorQStringType);

#define QJSONVALUE_CONSTRUCTORQJSONARRAY(name) QJsonValue* name(QJsonValue* this, const QJsonArray* arr)
typedef QJSONVALUE_CONSTRUCTORQJSONARRAY(QJsonValue_ConstructorQJsonArrayType);

#define QJSONARRAY_CONSTRUCTOR(name) QJsonArray* name(QJsonArray* this)
typedef QJSONARRAY_CONSTRUCTOR(QJsonArray_ConstructorType);

#define QJSONARRAY_APPEND(name) void name(QJsonArray* this, const QJsonValue* value)
typedef QJSONARRAY_APPEND(QJsonArray_AppendType);

#define QJSONARRAY_DESTRUCTOR(name) void name(QJsonArray* this)
typedef QJSONARRAY_DESTRUCTOR(QJsonArray_DestructorType);

#define QSTRING_FROMASCIIHELPER(name) QTypedArrayData* name(const char* str, i64 len)
typedef QSTRING_FROMASCIIHELPER(QString_FromAsciiHelperType);

#define QSTRING_TOUTF8(name) QByteArray* name(const QString* this, QByteArray* out)
typedef QSTRING_TOUTF8(QString_ToUtf8Type);

#define QJSONOBJECT_INSERT(name) QJsonObject_iterator* name(QJsonObject* this, QJsonObject_iterator* retstr, const QString* key, const QJsonValue* value)
typedef QJSONOBJECT_INSERT(QJsonObject_InsertType);

#define QSTRING_DESTRUCTOR(name) void name(QString* this)
typedef QSTRING_DESTRUCTOR(QString_DestructorType);

#define QJSONVALUE_DESTRUCTOR(name) void name(QJsonValue* this)
typedef QJSONVALUE_DESTRUCTOR(QJsonValue_DestructorType);

#define QHOSTADDRESS_CONSTRUCTORQSTRING(name) QHostAddress* name(QHostAddress* this, const QString* address)
typedef QHOSTADDRESS_CONSTRUCTORQSTRING(QHostAddress_ConstructorQStringType);

#define QHOSTADDRESS_DESTRUCTOR(name) void name(QHostAddress* this)
typedef QHOSTADDRESS_DESTRUCTOR(QHostAddress_DestructorType);

#define QJSONOBJECT_DESTRUCTOR(name) void name(void* this)
typedef QJSONOBJECT_DESTRUCTOR(QJsonObject_DestructorType);

#define QTIMER_STOP(name) void name(void* timer)
typedef QTIMER_STOP(QTimer_StopType);

#define QDATETIME_CURRENTMSECSSINCEEPOCH(name) u64 name()
typedef QDATETIME_CURRENTMSECSSINCEEPOCH(QDateTime_CurrentMSecsSinceEpochType);

#define QBYTEARRAY_CONSTRUCTOR(name) void* name(void* this, const char* data, i32 size)
typedef QBYTEARRAY_CONSTRUCTOR(QByteArray_ConstructorType);

#define QBYTEARRAY_DESTRUCTOR(name) void name(void* this)
typedef QBYTEARRAY_DESTRUCTOR(QByteArray_DestructorType);

#define QWEBSOCKET_SENDBINARYMESSAGE(name) i64 name(void* this, const void* data)
typedef QWEBSOCKET_SENDBINARYMESSAGE(QWebSocket_SendBinaryMessageType);

#define QWEBSOCKET_SENDTEXTMESSAGE(name) i64 name(void* this, const QString* message)
typedef QWEBSOCKET_SENDTEXTMESSAGE(QWebSocket_SendTextMessageType);

#define QOBJECT_CONNECTIMPL(name) void name(void* retval, const void* sender, void** signal, const void* receiver, void** slot, void* slotObj, i32 connType, const i32* types, const void* senderMeta)
typedef QOBJECT_CONNECTIMPL(QObject_ConnectImplType);

static QUdpSocket_WriteDatagramType*          QUdpSocket_WriteDatagram;
static QUdpSocket_ReadDatagramType*           QUdpSocket_ReadDatagram;
static QAbstractSocket_ConnectToHostType*     QAbstractSocket_ConnectToHost;
static QString_SetFromQLatin1StringType*      QString_SetFromQLatin1String;
static QJsonObject_ConstructorType*           QJsonObject_Constructor;
static QJsonValue_ConstructorIntType*         QJsonValue_ConstructorInt;
static QJsonValue_ConstructorDoubleType*      QJsonValue_ConstructorDouble;
static QJsonValue_ConstructorQJsonObjectType* QJsonValue_ConstructorQJsonObject;
static QJsonValue_ConstructorQStringType*     QJsonValue_ConstructorQString;
static QJsonValue_ConstructorQJsonArrayType*  QJsonValue_ConstructorQJsonArray;
static QJsonArray_ConstructorType*            QJsonArray_Constructor;
static QJsonArray_AppendType*                 QJsonArray_Append;
static QJsonArray_DestructorType*             QJsonArray_Destructor;
static QString_FromAsciiHelperType*           QString_FromAsciiHelper;
static QString_ToUtf8Type*                    QString_ToUtf8;
static QJsonObject_InsertType*                QJsonObject_Insert;
static QString_DestructorType*                QString_Destructor;
static QJsonValue_DestructorType*             QJsonValue_Destructor;
static QJsonObject_DestructorType*            QJsonObject_Destructor;
static QHostAddress_ConstructorQStringType*   QHostAddress_ConstructorQString;
static QHostAddress_DestructorType*           QHostAddress_Destructor;
static QTimer_StopType*                       QTimer_Stop;
static QDateTime_CurrentMSecsSinceEpochType*  QDateTime_CurrentMSecsSinceEpoch;
static QByteArray_ConstructorType*            QByteArray_Constructor;
static QByteArray_DestructorType*             QByteArray_Destructor;
static QWebSocket_SendBinaryMessageType*      QWebSocket_SendBinaryMessage;
static QWebSocket_SendTextMessageType*        QWebSocket_SendTextMessage;
static QObject_ConnectImplType*               QObject_ConnectImpl;

#define QUDPSOCKET_WRITEDATAGRAM(name)          i64 name(void* this, u8* data, i64 size, void* addr, u16 port)
#define QUDPSOCKET_READDATAGRAM(name)           i64 name(void* this, char* data, i64 size, void* address, u16* port)
#define QABSTRACTSOCKET_CONNECTTOHOST(name)     void name(void* this, const QString* hostName, u16 port, i32 openMode, QAbstractSocket_NetworkLayerProtocol protocol)
#define QSTRING_SETFROMQLATIN1STRING(name)      QString* name(QString* str, QLatin1String lstr)
#define QJSONOBJECT_CONSTRUCTOR(name)           QJsonObject* name(QJsonObject* this)
#define QJSONVALUE_CONSTRUCTORINT(name)         QJsonValue* name(QJsonValue* this, i32 value)
#define QJSONVALUE_CONSTRUCTORDOUBLE(name)      QJsonValue* name(QJsonValue* this, double value)
#define QJSONVALUE_CONSTRUCTORQJSONOBJECT(name) QJsonValue* name(QJsonValue* this, const QJsonObject* obj)
#define QJSONVALUE_CONSTRUCTORQSTRING(name)     QJsonValue* name(QJsonValue* this, const QString* str)
#define QJSONVALUE_CONSTRUCTORQJSONARRAY(name)  QJsonValue* name(QJsonValue* this, const QJsonArray* arr)
#define QJSONARRAY_CONSTRUCTOR(name)            QJsonArray* name(QJsonArray* this)
#define QJSONARRAY_APPEND(name)                 void name(QJsonArray* this, const QJsonValue* value)
#define QJSONARRAY_DESTRUCTOR(name)             void name(QJsonArray* this)
#define QSTRING_FROMASCIIHELPER(name)           QTypedArrayData* name(const char* str, i64 len)
#define QSTRING_TOUTF8(name)                    QByteArray* name(const QString* this, QByteArray* out)
#define QJSONOBJECT_INSERT(name)                QJsonObject_iterator* name(QJsonObject* this, QJsonObject_iterator* retstr, const QString* key, const QJsonValue* value)
#define QSTRING_DESTRUCTOR(name)                void name(QString* this)
#define QJSONVALUE_DESTRUCTOR(name)             void name(QJsonValue* this)
#define QHOSTADDRESS_CONSTRUCTORQSTRING(name)   QHostAddress* name(QHostAddress* this, const QString* address)
#define QHOSTADDRESS_DESTRUCTOR(name)           void name(QHostAddress* this)
#define QJSONOBJECT_DESTRUCTOR(name)            void name(void* this)
#define QTIMER_STOP(name)                       void name(void* timer)
#define QDATETIME_CURRENTMSECSSINCEEPOCH(name)  u64 name()
#define QBYTEARRAY_CONSTRUCTOR(name)            void* name(void* this, const char* data, i32 size)
#define QBYTEARRAY_DESTRUCTOR(name)             void name(void* this)
#define QWEBSOCKET_SENDBINARYMESSAGE(name)      i64 name(void* this, const void* data)
#define QWEBSOCKET_SENDTEXTMESSAGE(name)        i64 name(void* this, const QString* message)
#define QOBJECT_CONNECTIMPL(name)               void name(void* retval, const void* sender, void** signal, const void* receiver, void** slot, void* slotObj, i32 connType, const i32* types, const void* senderMeta)

#define QT_FN(module, name, sig, mangled) \
    typedef sig(name##Type);              \
    static name##Type* name;
#define QT_HOOK QT_FN
#include "functions.inc"
#undef QT_HOOK
#undef QT_FN

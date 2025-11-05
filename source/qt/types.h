#pragma pack(push, 1)
typedef struct QJsonPrivate_Data  QJsonPrivate_Data;
typedef struct QJsonPrivate_Array QJsonPrivate_Array;

typedef struct
{
    QJsonPrivate_Data*  d;
    QJsonPrivate_Array* a;
} QJsonArray;
static_assert(sizeof(QJsonArray) == 0x10);

typedef enum {
    QJsonValue_Type_Null,
    QJsonValue_Type_Bool,
    QJsonValue_Type_Double,
    QJsonValue_Type_String,
    QJsonValue_Type_Array,
    QJsonValue_Type_Object,
    QJsonValue_Type_Undefined = 0x80,
} QJsonValue_Type;

typedef struct {
    u64                u0;
    QJsonPrivate_Data* d;
    QJsonValue_Type    t;
    Pad(4);
} QJsonValue;
static_assert(sizeof(QJsonValue) == 0x18);

typedef struct {
    void* d;
    void* o;
} QJsonObject;
static_assert(sizeof(QJsonObject) == 0x10);

typedef struct {
    QJsonObject* o;
    int          i;
    Pad(4);
} QJsonObject_iterator;
static_assert(sizeof(QJsonObject_iterator) == 0x10);

typedef struct {
    i32 ref_count;

    i32  size;
    i32  alloc;
    Pad(4);
    uptr offset;
} QTypedArrayData;
static_assert(sizeof(QTypedArrayData) == 0x18);

typedef struct {
    QTypedArrayData* d;
} QString;
static_assert(sizeof(QString) == 0x8);

void* QTypedArrayData_data(QTypedArrayData* array) {
    return (void*) ((uptr) array + array->offset);
}

typedef struct {
    u32         size;
    Pad(4);
    const char* data;
} QLatin1String;
static_assert(sizeof(QLatin1String) == 0x10);
#define QLatin1StringLit(s) (QLatin1String) QLatin1StringComp(s)
#define QLatin1StringComp(s) \
{.size = sizeof(s) - 1, .data = s}

typedef struct {
    void* d;
} QHostAddress;
static_assert(sizeof(QHostAddress) == 0x8);

#pragma pack(pop)
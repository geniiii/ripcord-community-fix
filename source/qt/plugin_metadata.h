typedef u32 QJsonPrivate_Value;
enum {
    QJsonPrivate_Value_LatinOrIntValue = 1 << 3,
    QJsonPrivate_Value_LatinKey        = 1 << 4,
};
#define QJsonPrivateValue(type, flags, value) ((QJsonPrivate_Value) ((u32) (type) | (u32) (flags) | ((u32) (value) << 5)))

typedef struct {
    u32 size;
    u32 length;
    u32 table_offset;
} QJsonPrivate_Base;

typedef struct {
    u32 tag;
    u32 version;
} QJsonPrivate_Header;
enum {
    QJsonDocument_BinaryFormatTag = 'q' | ('b' << 8) | ('j' << 16) | ('s' << 24),
};
#define QJsonPrivateObjectLength(count) (((count) << 1) | 1)
#define QJsonPrivateArrayLength(count)  ((count) << 1)

#define QJsonPrivate_Latin1String(s)             \
    struct {                                     \
        u16  length;                             \
        char latin1[((sizeof(s) + 4) & ~3) - 2]; \
    }
#define QJsonPrivateLatin1String(s) \
    {.length = sizeof(s) - 1, .latin1 = s}

#define PluginMetaDataOffset(object, field) (offsetof(PluginMetaData, object.field) - offsetof(PluginMetaData, object))

#define PLUGIN_IID                          "org.qt-project.Qt.QPA.QPlatformThemeFactoryInterface.5.1"
#define PLUGIN_CLASS_NAME                   "RipcordFixPlugin"
#define PLUGIN_QT_VERSION                   0x050907
#define PLUGIN_KEY                          "windows"

typedef struct {
    char                magic[12];
    QJsonPrivate_Header header;

    struct {
        QJsonPrivate_Base base;

        struct {
            QJsonPrivate_Value value;
            QJsonPrivate_Latin1String("IID") key;
            QJsonPrivate_Latin1String(PLUGIN_IID) data;
        } iid;

        struct {
            QJsonPrivate_Value value;
            QJsonPrivate_Latin1String("className") key;
            QJsonPrivate_Latin1String(PLUGIN_CLASS_NAME) data;
        } class_name;

        struct {
            QJsonPrivate_Value value;
            QJsonPrivate_Latin1String("version") key;
        } version;

        struct {
            QJsonPrivate_Value value;
            QJsonPrivate_Latin1String("debug") key;
        } debug;

        struct {
            QJsonPrivate_Value value;
            QJsonPrivate_Latin1String("MetaData") key;
            struct {
                QJsonPrivate_Base base;

                struct {
                    QJsonPrivate_Value value;
                    QJsonPrivate_Latin1String("Keys") key;
                    struct {
                        QJsonPrivate_Base base;
                        QJsonPrivate_Latin1String(PLUGIN_KEY) key;
                        u32 table[1];
                    } data;
                } keys;

                u32 table[1];
            } data;
        } metadata;

        u32 table[5];
    } root;
} PluginMetaData;

// clang-format off
global const PluginMetaData g_plugin_metadata = {
    .magic  = {'Q', 'T', 'M', 'E', 'T', 'A', 'D', 'A', 'T', 'A', ' ', ' '},
    .header = {.tag = QJsonDocument_BinaryFormatTag, .version = 1},
    .root   = {
        .base = {
            .size         = sizeof(g_plugin_metadata.root),
            .length       = QJsonPrivateObjectLength(5),
            .table_offset = PluginMetaDataOffset(root, table),
        },
        .iid = {
            .value = QJsonPrivateValue(QJsonValue_Type_String, QJsonPrivate_Value_LatinOrIntValue | QJsonPrivate_Value_LatinKey, PluginMetaDataOffset(root, iid.data)),
            .key   = QJsonPrivateLatin1String("IID"),
            .data  = QJsonPrivateLatin1String(PLUGIN_IID),
        },
        .class_name = {
            .value = QJsonPrivateValue(QJsonValue_Type_String, QJsonPrivate_Value_LatinOrIntValue | QJsonPrivate_Value_LatinKey, PluginMetaDataOffset(root, class_name.data)),
            .key   = QJsonPrivateLatin1String("className"),
            .data  = QJsonPrivateLatin1String(PLUGIN_CLASS_NAME),
        },
        .version = {
            .value = QJsonPrivateValue(QJsonValue_Type_Double, QJsonPrivate_Value_LatinOrIntValue | QJsonPrivate_Value_LatinKey, PLUGIN_QT_VERSION),
            .key   = QJsonPrivateLatin1String("version"),
        },
        .debug = {
            .value = QJsonPrivateValue(QJsonValue_Type_Bool, QJsonPrivate_Value_LatinKey, 0),
            .key   = QJsonPrivateLatin1String("debug"),
        },
        .metadata = {
            .value = QJsonPrivateValue(QJsonValue_Type_Object, QJsonPrivate_Value_LatinKey, PluginMetaDataOffset(root, metadata.data)),
            .key   = QJsonPrivateLatin1String("MetaData"),
            .data  = {
                .base = {
                    .size         = sizeof(g_plugin_metadata.root.metadata.data),
                    .length       = QJsonPrivateObjectLength(1),
                    .table_offset = PluginMetaDataOffset(root.metadata.data, table),
                },
                .keys = {
                    .value = QJsonPrivateValue(QJsonValue_Type_Array, QJsonPrivate_Value_LatinKey, PluginMetaDataOffset(root.metadata.data, keys.data)),
                    .key   = QJsonPrivateLatin1String("Keys"),
                    .data  = {
                        .base = {
                            .size         = sizeof(g_plugin_metadata.root.metadata.data.keys.data),
                            .length       = QJsonPrivateArrayLength(1),
                            .table_offset = PluginMetaDataOffset(root.metadata.data.keys.data, table),
                        },
                        .key   = QJsonPrivateLatin1String(PLUGIN_KEY),
                        .table = {
                            QJsonPrivateValue(QJsonValue_Type_String, QJsonPrivate_Value_LatinOrIntValue, PluginMetaDataOffset(root.metadata.data.keys.data, key)),
                        },
                    },
                },
                .table = {
                    PluginMetaDataOffset(root.metadata.data, keys),
                },
            },
        },
        .table = {
            PluginMetaDataOffset(root, iid),
            PluginMetaDataOffset(root, metadata),
            PluginMetaDataOffset(root, class_name),
            PluginMetaDataOffset(root, debug),
            PluginMetaDataOffset(root, version),
        },
    },
};
// clang-format on

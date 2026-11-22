#define CLIENT_CHROME_MAJOR    "150"
#define CLIENT_BUILD_NUMBER    "634304"
#define CLIENT_LOCALE          "en-US"
#define CLIENT_ACCEPT_LANGUAGE "en-US,en;q=0.9"
#define CLIENT_ORIGIN          "https://discord.com"
#define CLIENT_USER_AGENT      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" CLIENT_CHROME_MAJOR ".0.0.0 Safari/537.36"
#define CLIENT_SUPER_PROPERTIES                                                                     \
    "{\"os\":\"Windows\",\"browser\":\"Chrome\",\"device\":\"\",\"system_locale\":\"" CLIENT_LOCALE \
    "\","                                                                                           \
    "\"has_client_mods\":false,\"browser_user_agent\":\"" CLIENT_USER_AGENT                         \
    "\","                                                                                           \
    "\"browser_version\":\"" CLIENT_CHROME_MAJOR                                                    \
    ".0.0.0\",\"os_version\":\"10\","                                                               \
    "\"referrer\":\"\",\"referring_domain\":\"\",\"referrer_current\":\"\","                        \
    "\"referring_domain_current\":\"\",\"release_channel\":\"stable\","                             \
    "\"client_build_number\":" CLIENT_BUILD_NUMBER                                                  \
    ",\"client_event_source\":null,"                                                                \
    "\"client_launch_id\":\"%.*s\",\"launch_signature\":\"%.*s\",\"client_app_state\":\"focused\"," \
    "\"client_heartbeat_session_id\":\"%.*s\"%.*s}"
#define CLIENT_GATEWAY_PROPERTIES ",\"is_fast_connect\":false,\"gateway_connect_reasons\":\"AppSkeleton\""

enum {
    HttpHeaderTarget_Rest      = 1 << 0,
    HttpHeaderTarget_WebSocket = 1 << 1,
    HttpHeaderTarget_All       = HttpHeaderTarget_Rest | HttpHeaderTarget_WebSocket,
};

typedef struct {
    u32     targets;
    String8 name;
    String8 value;
} HttpHeader;

global const HttpHeader g_client_headers[] = {
#define HTTP_HEADER(targets, name, value) { targets, S8LitComp(name), S8LitComp(value) },
#include "http.inc"
#undef HTTP_HEADER
};

global String8    g_client_gateway_properties;
global QByteArray g_client_super_properties_header;
global QByteArray g_client_timezone;

static String8 Client_GenerateUuid(char out[37], const u8* mask) {
    String8 result = {
        .cstr = out,
        .size = 36,
    };
    u8 b[16];
    RtlGenRandom(b, sizeof b);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    for (u32 i = 0; i < sizeof b; ++i) {
        u8 v = mask ? b[i] & mask[i] : b[i];
        out += sprintf(out, (i == 4 || i == 6 || i == 8 || i == 10) ? "-%02x" : "%02x", v);
    }
    return result;
}

static void Client_Init(void) {
    static const u8 launch_signature_mask[16] = { 0xFF, 0x7F, 0xEF, 0xEF, 0xF7, 0xEF, 0xF7, 0xFF,
                                                  0xDF, 0x7E, 0xFF, 0xBF, 0xFE, 0xFF, 0xF7, 0xFF };

    char    launch_id_buffer[37];
    char    launch_signature_buffer[37];
    char    heartbeat_session_id_buffer[37];
    String8 launch_id            = Client_GenerateUuid(launch_id_buffer, 0);
    String8 launch_signature     = Client_GenerateUuid(launch_signature_buffer, launch_signature_mask);
    String8 heartbeat_session_id = Client_GenerateUuid(heartbeat_session_id_buffer, 0);

    char       http_properties[2048];
    QByteArray http_properties_ba;
    i32        size = snprintf(http_properties, sizeof http_properties, CLIENT_SUPER_PROPERTIES, S8VArg(launch_id), S8VArg(launch_signature), S8VArg(heartbeat_session_id), S8VArg(S8Lit("")));
    QByteArray_Constructor(&http_properties_ba, http_properties, size);
    QByteArray_ToBase64(&http_properties_ba, &g_client_super_properties_header);
    QByteArray_Destructor(&http_properties_ba);

    static char gateway_properties[2048];
    size                        = snprintf(gateway_properties, sizeof gateway_properties, CLIENT_SUPER_PROPERTIES, S8VArg(launch_id), S8VArg(launch_signature), S8VArg(heartbeat_session_id), S8VArg(S8Lit(CLIENT_GATEWAY_PROPERTIES)));
    g_client_gateway_properties = (String8) {
        .cstr = gateway_properties,
        .size = (u64) size,
    };

    QTimeZone_SystemTimeZoneId(&g_client_timezone);
}

static void Http_SetRawHeader(void* request, String8 name, const QByteArray* value) {
    QByteArray name_ba;
    QByteArray_Constructor(&name_ba, name.cstr, (i32) name.size);
    QNetworkRequest_SetRawHeader(request, &name_ba, value);
    QByteArray_Destructor(&name_ba);
}

static QNETWORKACCESSMANAGER_CREATEREQUEST(QNetworkAccessManager_CreateRequestHook) {
    QUrl       url;
    QByteArray encoded;
    QNetworkRequest_Url(request, &url);
    QUrl_ToEncoded(&url, &encoded, 0);

    String8 encoded_s8 = {
        .cstr = (char*) QByteArray_ConstData(&encoded),
        .size = (u64) QByteArray_Size(&encoded),
    };
    if (S8_StartsWith(encoded_s8, S8Lit(CLIENT_ORIGIN "/api/"))) {
        Http_SetRawHeader(request, S8Lit("X-Super-Properties"), &g_client_super_properties_header);
        Http_SetRawHeader(request, S8Lit("X-Discord-Timezone"), &g_client_timezone);
        for (u32 i = 0; i < ArrayCount(g_client_headers); ++i) {
            if (!(g_client_headers[i].targets & HttpHeaderTarget_Rest)) {
                continue;
            }
            QByteArray value;
            QByteArray_Constructor(&value, g_client_headers[i].value.cstr, (i32) g_client_headers[i].value.size);
            Http_SetRawHeader(request, g_client_headers[i].name, &value);
            QByteArray_Destructor(&value);
        }
    }

    QByteArray_Destructor(&encoded);
    QUrl_Destructor(&url);
    return QNetworkAccessManager_CreateRequest(this, op, request, outgoingData);
}

static QWEBSOCKET_OPENURL(QWebSocket_OpenUrlHook) {
    QNetworkRequest request;
    QNetworkRequest_ConstructorQUrl(&request, url);
    for (u32 i = 0; i < ArrayCount(g_client_headers); ++i) {
        if (!(g_client_headers[i].targets & HttpHeaderTarget_WebSocket)) {
            continue;
        }
        QByteArray value;
        QByteArray_Constructor(&value, g_client_headers[i].value.cstr, (i32) g_client_headers[i].value.size);
        Http_SetRawHeader(&request, g_client_headers[i].name, &value);
        QByteArray_Destructor(&value);
    }
    QWebSocket_OpenRequest(this, &request);
    QNetworkRequest_Destructor(&request);
}

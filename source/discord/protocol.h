#define DISCORD_MAX_GUILDS         200
#define DISCORD_MAX_GUILD_CHANNELS 500

enum {
    GATEWAY_OP_RESYNC_GUILD_CHANNELS = 38,
};

enum {
    DiscordChannelFlag_Obfuscated = 1 << 17,
};

enum {
    VOICE_OP_IDENTIFY             = 0,
    VOICE_OP_READY                = 2,
    VOICE_OP_SESSION_DESCRIPTION  = 4,
    VOICE_OP_SPEAKING             = 5,
    VOICE_OP_HEARTBEAT_ACK        = 6,
    VOICE_OP_HELLO                = 8,
    VOICE_OP_CLIENTS_CONNECT      = 11,
    VOICE_OP_VIDEO                = 12,
    VOICE_OP_CLIENT_DISCONNECT    = 13,
    VOICE_OP_PREPARE_TRANSITION   = 21,
    VOICE_OP_EXECUTE_TRANSITION   = 22,
    VOICE_OP_READY_FOR_TRANSITION = 23,
    VOICE_OP_PREPARE_EPOCH        = 24,
};

enum {
    DAVE_MLS_EXTERNAL_SENDER = 25,
    DAVE_MLS_KEY_PACKAGE     = 26,
    DAVE_MLS_PROPOSALS       = 27,
    DAVE_MLS_COMMIT_WELCOME  = 28,
    DAVE_MLS_ANNOUNCE_COMMIT = 29,
    DAVE_MLS_WELCOME         = 30,
    DAVE_MLS_INVALID_COMMIT  = 31,
};

#define DAVE_MAGIC_BYTES      0xFAFA
#define RTP_PACKET_TYPE_VOICE 0x78

enum {
    IP_DISCOVERY_TYPE_REQUEST  = 1,
    IP_DISCOVERY_TYPE_RESPONSE = 2,
};

typedef struct {
    u8 type[2];
    u8 length[2];
} DiscordIpDiscoveryHeader;

typedef struct {
    DiscordIpDiscoveryHeader header;
    u8                       ssrc[4];
    char                     address[64];
    u8                       port[2];
} DiscordIpDiscoveryPacket;

#define IP_DISCOVERY_LENGTH (sizeof(DiscordIpDiscoveryPacket) - sizeof(DiscordIpDiscoveryHeader))

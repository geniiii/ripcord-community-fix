static QUDPSOCKET_WRITEDATAGRAM(QUdpSocket_WriteDatagramHook) {
    // NOTE(geni): Ripcord sends what is likely an old version of this packet
    //             See here: https://discord.com/developers/docs/topics/voice-connections#ip-discovery
    if (size == IP_DISCOVERY_LENGTH) {
        DiscordIpDiscoveryPacket* packet = (DiscordIpDiscoveryPacket*) data;
        memcpy(packet->ssrc, data, sizeof(packet->ssrc));
        packet->header.type[0]   = 0;
        packet->header.type[1]   = IP_DISCOVERY_TYPE_REQUEST;
        packet->header.length[0] = 0;
        packet->header.length[1] = IP_DISCOVERY_LENGTH;
        return QUdpSocket_WriteDatagram(this, data, sizeof(DiscordIpDiscoveryPacket), addr, port);
    }

    return QUdpSocket_WriteDatagram(this, data, size, addr, port);
}

// NOTE(geni): Force voice chat WS connection over IPv4 because people say it doesn't work over IPv6
//			   I can't test it myself, so this is purely speculative...
static QABSTRACTSOCKET_CONNECTTOHOST(QAbstractSocket_ConnectToHostHook) {
    Unreferenced(protocol);
    QAbstractSocket_ConnectToHost(this, hostName, port, openMode, QAbstractSocket_NetworkLayerProtocol_IPv4Protocol);
}

static QUDPSOCKET_READDATAGRAM(QUdpSocket_ReadDatagramHook) {
    if (size == sizeof(DiscordIpDiscoveryPacket)) {
        i64 result = QUdpSocket_ReadDatagram(this, data, size, address, port);
        // NOTE(geni): Swap port endianness
        //             I wanted to just put a rol instruction after the movzx that reads it, but there was no space
        DiscordIpDiscoveryPacket* packet = (DiscordIpDiscoveryPacket*) data;
        if (packet->header.type[1] == IP_DISCOVERY_TYPE_RESPONSE && packet->header.length[1] == IP_DISCOVERY_LENGTH) {
            u8 temp         = packet->port[0];
            packet->port[0] = packet->port[1];
            packet->port[1] = temp;
        }
        return result;
    }
    return QUdpSocket_ReadDatagram(this, data, size, address, port);
}

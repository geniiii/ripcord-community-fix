static WRITE_DATAGRAM(WriteDatagramHook) {
    // NOTE(geni): Ripcord sends what is likely an old version of this packet
    //             See here: https://discord.com/developers/docs/topics/voice-connections#ip-discovery
    if (size == 70) {
        u32 ssrc         = *((u32*) data);
        data[0]          = 0;
        data[1]          = 1;
        data[2]          = 0;
        data[3]          = 70;
        ((u32*) data)[1] = ssrc;
        return write_datagram(this, data, 74, addr, port);
    }

    return write_datagram(this, data, size, addr, port);
}

// NOTE(geni): Force voice chat WS connection over IPv4 because people say it doesn't work over IPv6
//			   I can't test it myself, so this is purely speculative...
static QABSTRACTSOCKET_CONNECTTOHOST(QAbstractSocketConnectToHostHook) {
    Unreferenced(protocol);
    qabstractsocket_connecttohost(this, hostName, port, openMode, QAbstractSocket_NetworkLayerProtocol_IPv4Protocol);
}

static READ_DATAGRAM(ReadDatagramHook) {
    if (size == 74) {
        i64 result = read_datagram(this, data, size, address, port);
        // NOTE(geni): Swap port endianness
        //             I wanted to just put a rol instruction after the movzx that reads it, but there was no space
        if (data[1] == 2 && data[3] == 70) {
            u8 temp  = data[72];
            data[72] = data[73];
            data[73] = temp;
        }
        return result;
    }
    return read_datagram(this, data, size, address, port);
}

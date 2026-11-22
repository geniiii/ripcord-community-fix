static DISCLIENTIMPL_SENDIDENTIFYMESSAGE(DisClientImpl_SendIdentifyMessageHook) {
    QByteArray token;
    QString_ToUtf8(authToken, &token);
    QString_Destructor(authToken);

    char json[4096];
    i32  size = snprintf(json, sizeof json, "{\"op\":2,\"d\":{\"token\":\"%.*s\",\"capabilities\":%d,\"properties\":%.*s,\"large_threshold\":250%s}}",
                         QByteArray_Size(&token), QByteArray_ConstData(&token), DiscordGatewayCapability_ChannelObfuscation,
                         S8VArg(g_client_gateway_properties), useTransportCompression ? "" : ",\"compress\":true");
    QByteArray_Destructor(&token);

    QByteArray    json_ba;
    QJsonDocument document;
    QJsonObject   payload;
    QJsonValue    value;
    QByteArray_Constructor(&json_ba, json, size);
    QJsonDocument_FromJson(&document, &json_ba, 0);
    QJsonDocument_Object(&document, &payload);
    WebSocketHelpers_SendJsonAsEtf(webSocket, QJsonValue_ConstructorQJsonObject(&value, &payload));

    QJsonObject_Destructor(&payload);
    QJsonDocument_Destructor(&document);
    QByteArray_Destructor(&json_ba);
}

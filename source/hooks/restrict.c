static DISCLIENT_ACCEPTINVITE(DisClient_AcceptInviteHook) {
    Unreferenced(this);
    Unreferenced(ownUserId);
    Unreferenced(code);
    Log_Debug("Blocked joining a server via invite");
}

static DISCLIENT_CREATERELATIONSHIP(DisClient_CreateRelationshipHook) {
    Unreferenced(this);
    Unreferenced(ownUserId);
    Unreferenced(otherUserId);
    Log_Debug("Blocked sending/accepting friend request");
}

static DISINVITELINKVIEW_ISPOSSIBLYDISCORDINVITEURL(DisInviteLinkView_IsPossiblyDiscordInviteUrlHook) {
    Unreferenced(urlText);
    return 0;
}

static DISCONTEXTMENUS_ADDRELATIONSHIPACTION(DisContextMenus_AddRelationshipActionHook) {
    if (actionType == DisRelationshipAction_AddFriend || actionType == DisRelationshipAction_AcceptFriendRequest) {
        return;
    }
    DisContextMenus_AddRelationshipAction(captures, actionType);
}

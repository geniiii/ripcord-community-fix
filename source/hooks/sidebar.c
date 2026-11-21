#define SidebarSql(name, ...) static const char sidebar_##name##_sql[] = #__VA_ARGS__;
#include "sidebar.inc"
#undef SidebarSql

static void SidebarReplaceStmt(RipStmt* stmt, void* db, const char* sql) {
    ripstmt_destructor(stmt);
    ripstmt_constructor(stmt, db, sql, 0);
}

static RIPSBAR_DISSTMTS_CONSTRUCTOR(RipSbarDisStmtsConstructorHook) {
    ripsbar_disstmts_constructor(this);

    void* db = (*g_dis_client)->db;

    RipStmt view;
    ripstmt_constructor(&view, db, sidebar_accessible_channel_view_sql, 0);
    ripstmt_step(&view);
    ripstmt_destructor(&view);

    SidebarReplaceStmt(&this->all_guild_text_channel_ids, db, sidebar_text_channels_sql);
    SidebarReplaceStmt(&this->all_guild_voice_channel_ids, db, sidebar_voice_channels_sql);
    SidebarReplaceStmt(&this->all_guild_channel_category_ids, db, sidebar_categories_sql);

    return this;
}

static RIPSBAR_DISCHANGES(RipSbarDisChangesHook) {
    ripsbar_dischanges(v, changes);

    u32 flags = changes->flags;
    // NOTE(geni): Don't bother if original already rebuilt sidebar
    if (flags & (1u << DisChangeType_ChannelUpdated)) {
        return;
    }

    // NOTE(geni): Any of these could change channel visibility
    u32 role_mask = (1u << DisChangeType_GuildRoleCreated) |
                    (1u << DisChangeType_GuildRoleUpdated) |
                    (1u << DisChangeType_GuildRoleDeleted) |
                    (1u << DisChangeType_OverflowFlag);
    // NOTE(geni): These only matter if the affected member is us (e.g. a verification bot gave us a role)
    u32 member_mask = (1u << DisChangeType_GuildMemberAdded) |
                      (1u << DisChangeType_GuildMemberUpdated) |
                      (1u << DisChangeType_GuildMemberRemoved);
    if (flags & role_mask) {
        ripsbar_query_and_create_discord_items(v);
        return;
    }
    if (!(flags & member_mask)) {
        return;
    }

    u64 own_user_id = v->priv->own_user_id.u;
    for (i32 i = 0; i < changes->items.s; ++i) {
        DisChange* change = &changes->items.ptr[i];
        // NOTE(geni): We're affected, so rebuild sidebar
        if ((member_mask & (1u << change->type)) && change->member.user_id.u == own_user_id) {
            ripsbar_query_and_create_discord_items(v);
            return;
        }
    }
}

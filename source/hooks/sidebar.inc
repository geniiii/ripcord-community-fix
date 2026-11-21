SidebarSql(accessible_channel_view,
    create temp view if not exists accessible_guild_channel (id, parent_id) as
    with
        me as (
            select id
            from local_user
            limit 1
        ),
        my_ids (id) as (
            select id from me
            union all
            select role_id
            from guild_member_role, me
            where user_id = me.id
        ),
        channel as (
            select id, guild_id, parent_id from guild_channel where deleted = 0
            union all
            select id, guild_id, parent_id from guild_voice_channel where deleted = 0
        )
    select c.id, c.parent_id
    from channel c
    join guild g on g.id = c.guild_id, me
    where
        g.owner_id = me.id
        or exists (
            select 1
            from role r
            where r.guild_id = c.guild_id
              and r.permissions & 8
              and (r.id = c.guild_id or r.id in my_ids)
        )
        or exists (
            select 1
            from guild_channel_permission p
            where p.channel_id = c.id
              and p.allow & 1024
              and (p.target_id = c.guild_id or p.target_id in my_ids)
        )
        or (
            exists (
                select 1
                from role r
                where r.guild_id = c.guild_id
                  and r.permissions & 1024
                  and (r.id = c.guild_id or r.id in my_ids)
            )
            and not exists (
                select 1
                from guild_channel_permission p
                where p.channel_id = c.id
                  and p.deny & 1024
                  and (p.target_id = c.guild_id or p.target_id in my_ids)
            )
        )
)

SidebarSql(text_channels,
    select id, guild_id, parent_id
    from guild_channel
    where deleted = 0
      and id in (select id from accessible_guild_channel)
)

SidebarSql(voice_channels,
    select id, guild_id, parent_id
    from guild_voice_channel
    where deleted = 0
      and id in (select id from accessible_guild_channel)
)

SidebarSql(categories,
    select id, guild_id, parent_id
    from guild_channel_category
    where deleted = 0
      and id in (select parent_id from accessible_guild_channel)
)

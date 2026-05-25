require('dotenv').config();
const {
  Client, GatewayIntentBits, EmbedBuilder,
  PermissionsBitField, WebhookClient, AuditLogEvent,
  ButtonBuilder, ButtonStyle, ActionRowBuilder, Events,
} = require('discord.js');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildModeration,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildWebhooks,
  ]
});

const PREFIX = '+';

// =====================
// In-memory storage
// =====================
const warnings            = {}; // { guildId: { userId: count } }
const whitelist           = {}; // { guildId: { users: Set, roles: Set } }
const botSpamTracker      = {}; // { guildId: { botId: { count, timer } } }
const channelDeleteTracker = {}; // { guildId: { botId: timestamp[] } }
const deletedMessages     = {}; // { guildId: lastDeletedMsg }
const verifyConfig        = {}; // { guildId: { roleId, channelId } }
// userSpam: tracks repeated identical messages per user
// { guildId: { userId: { content, count, timer, messageIds[] } } }
const userSpamTracker     = {};
// countdowns: { guildId: { date: Date, label: string } }
const countdowns          = {};

// =====================
// Malicious content regex
// =====================
const MALICIOUS_REGEX = /https?:\/\/[^\s]+|discord\.gg\/[^\s]+|www\.[^\s]+|@everyone|@here|\b(free nitro|claim your prize|you (have been|were) selected)\b/gi;

// =====================
// Helpers
// =====================
function getLogChannel(guild) {
  return guild.channels.cache.find(ch => ch.name === 'logs');
}
function isOwner(member) {
  return member.guild.ownerId === member.user.id;
}
function isWhitelisted(member) {
  const wl = whitelist[member.guild.id];
  if (!wl) return false;
  if (wl.users.has(member.user.id)) return true;
  for (const roleId of member.roles.cache.keys()) {
    if (wl.roles.has(roleId)) return true;
  }
  return false;
}
function initGuild(guildId) {
  if (!whitelist[guildId])       whitelist[guildId]       = { users: new Set(), roles: new Set() };
  if (!warnings[guildId])        warnings[guildId]        = {};
  if (!deletedMessages[guildId]) deletedMessages[guildId] = null;
  if (!userSpamTracker[guildId]) userSpamTracker[guildId] = {};
}
async function sendLog(guild, embed) {
  const ch = getLogChannel(guild);
  if (ch) await ch.send({ embeds: [embed] }).catch(() => {});
}
function bwEmbed(title) {
  return new EmbedBuilder().setColor(0x000000).setTitle(title);
}
function getMemberCount(guild) {
  const total = guild.memberCount;
  const bots  = guild.members.cache.filter(m => m.user.bot).size;
  return { total, humans: total - bots, bots };
}

// =====================
// Bot Ready
// =====================
client.once('ready', () => {
  console.log(`Logged in as ${client.user.tag}`);
  client.guilds.cache.forEach(g => initGuild(g.id));
});

// =====================
// Track deleted messages / images
// =====================
client.on('messageDelete', message => {
  if (!message.guild || message.author?.bot) return;
  deletedMessages[message.guild.id] = {
    content:     message.content || null,
    author:      message.author?.tag || 'Unknown',
    authorId:    message.author?.id || null,
    channel:     message.channel?.name || 'unknown',
    attachments: [...(message.attachments?.values() || [])].map(a => ({ url: a.url, name: a.name })),
    timestamp:   Date.now(),
  };
});

// =====================
// Member Join — Welcome + Alt Check + Log
// =====================
client.on('guildMemberAdd', async member => {
  initGuild(member.guild.id);
  const guild   = member.guild;
  const ageDays = Math.floor((Date.now() - member.user.createdTimestamp) / 86400000);
  const isAlt   = ageDays < 30;
  const isSusp  = ageDays < 7;
  const { total } = getMemberCount(guild);

  // Welcome message
  const welcomeChannel = guild.channels.cache.find(
    ch => ['welcome', 'general', 'lobby'].includes(ch.name)
  );
  if (welcomeChannel) {
    await welcomeChannel.send({ embeds: [
      bwEmbed(`Welcome to ${guild.name}`)
        .setDescription(`${member.user.username} just joined the server.`)
        .setThumbnail(member.user.displayAvatarURL())
        .addFields(
          { name: 'Member',        value: `<@${member.user.id}>`, inline: true },
          { name: 'Total Members', value: `${total}`,             inline: true },
        )
        .setFooter({ text: `Member #${total}` })
        .setTimestamp()
    ]}).catch(() => {});
  }

  // Log
  const logEmbed = bwEmbed('Member Joined')
    .setThumbnail(member.user.displayAvatarURL())
    .addFields(
      { name: 'User',         value: `${member.user.tag}`, inline: true },
      { name: 'ID',           value: `${member.user.id}`,  inline: true },
      { name: 'Account Age',  value: `${ageDays} days`,    inline: true },
      { name: 'Member Count', value: `${total}`,           inline: true },
      { name: 'Alt Risk',     value: isSusp ? 'HIGH — under 7 days' : isAlt ? 'MEDIUM — under 30 days' : 'None', inline: true },
    ).setTimestamp();
  if (isSusp)     logEmbed.setColor(0xED4245);
  else if (isAlt) logEmbed.setColor(0xFEE75C);
  await sendLog(guild, logEmbed);

  if (isSusp) {
    const lc = getLogChannel(guild);
    if (lc) lc.send(`[ALT ALERT] <@${member.user.id}> — account is only ${ageDays} day(s) old.`).catch(() => {});
  }
});

// =====================
// Member Leave Log
// =====================
client.on('guildMemberRemove', async member => {
  const { total } = getMemberCount(member.guild);
  await sendLog(member.guild, bwEmbed('Member Left')
    .setThumbnail(member.user.displayAvatarURL())
    .addFields(
      { name: 'User',      value: `${member.user.tag}`, inline: true },
      { name: 'ID',        value: `${member.user.id}`,  inline: true },
      { name: 'Remaining', value: `${total}`,           inline: true },
    ).setTimestamp());
});

// =====================
// Rogue Bot — Channel Delete
// =====================
client.on('channelDelete', async channel => {
  const guild = channel.guild;
  if (!guild) return;
  try {
    await new Promise(r => setTimeout(r, 1000));
    const logs  = await guild.fetchAuditLogs({ type: AuditLogEvent.ChannelDelete, limit: 1 });
    const entry = logs.entries.first();
    if (!entry) return;
    const executor = entry.executor;
    if (!executor?.bot || executor.id === client.user.id) return;
    if (!channelDeleteTracker[guild.id]) channelDeleteTracker[guild.id] = {};
    if (!channelDeleteTracker[guild.id][executor.id]) channelDeleteTracker[guild.id][executor.id] = [];
    const now = Date.now();
    channelDeleteTracker[guild.id][executor.id].push(now);
    channelDeleteTracker[guild.id][executor.id] =
      channelDeleteTracker[guild.id][executor.id].filter(t => now - t < 60000);
    if (channelDeleteTracker[guild.id][executor.id].length >= 2) {
      const member = guild.members.cache.get(executor.id);
      if (member?.bannable) {
        await member.ban({ reason: 'Rogue bot: mass channel deletion' });
        await sendLog(guild, bwEmbed('Rogue Bot Banned')
          .addFields(
            { name: 'Bot',    value: `${executor.tag}`,       inline: true },
            { name: 'Reason', value: 'Mass channel deletion',  inline: true },
          ).setTimestamp());
      }
    }
  } catch (e) { console.error('Channel delete audit error:', e.message); }
});

// =====================
// Button Interactions (Verify)
// =====================
client.on(Events.InteractionCreate, async interaction => {
  if (!interaction.isButton()) return;
  if (interaction.customId !== 'verify_button') return;

  const guild  = interaction.guild;
  const member = interaction.member;
  const config = verifyConfig[guild.id];

  if (!config) {
    return interaction.reply({ content: 'Verification is not configured. Ask an admin to run `+setupverify`.', ephemeral: true });
  }

  const role = guild.roles.cache.get(config.roleId);
  if (!role) {
    return interaction.reply({ content: 'The verified role no longer exists. Ask an admin to reconfigure.', ephemeral: true });
  }

  if (member.roles.cache.has(role.id)) {
    return interaction.reply({ content: 'You are already verified.', ephemeral: true });
  }

  try {
    await member.roles.add(role);
    await interaction.reply({ content: `You have been verified and given the **${role.name}** role.`, ephemeral: true });
    await sendLog(guild, bwEmbed('Member Verified')
      .addFields(
        { name: 'User', value: `${interaction.user.tag}`, inline: true },
        { name: 'ID',   value: `${interaction.user.id}`,  inline: true },
        { name: 'Role', value: role.name,                  inline: true },
      ).setTimestamp());
  } catch (e) {
    await interaction.reply({ content: 'Failed to assign role. Make sure the bot role is above the verified role.', ephemeral: true });
  }
});

// =====================
// Message Handler
// =====================
client.on('messageCreate', async message => {
  const guild = message.guild;
  if (!guild) return;
  initGuild(guild.id);

  // ---- Rogue bot spam detection ----
  if (message.author.bot && message.author.id !== client.user.id) {
    if (!botSpamTracker[guild.id]) botSpamTracker[guild.id] = {};
    const botId = message.author.id;
    if (!botSpamTracker[guild.id][botId]) botSpamTracker[guild.id][botId] = { count: 0, timer: null };
    botSpamTracker[guild.id][botId].count++;
    if (botSpamTracker[guild.id][botId].timer) clearTimeout(botSpamTracker[guild.id][botId].timer);
    botSpamTracker[guild.id][botId].timer = setTimeout(() => {
      if (botSpamTracker[guild.id]) botSpamTracker[guild.id][botId] = { count: 0, timer: null };
    }, 5000);
    if (botSpamTracker[guild.id][botId].count >= 8) {
      const member = guild.members.cache.get(botId);
      if (member?.bannable) {
        await member.ban({ reason: 'Rogue bot: message spam' });
        await sendLog(guild, bwEmbed('Rogue Bot Banned')
          .addFields(
            { name: 'Bot',    value: `${message.author.tag}`,  inline: true },
            { name: 'Reason', value: '8+ messages in 5 seconds', inline: true },
          ).setTimestamp());
      }
    }
    return;
  }

  if (message.author.bot) return;

  const isAdmin       = message.member?.permissions.has(PermissionsBitField.Flags.Administrator);
  const isMod         = message.member?.permissions.has(PermissionsBitField.Flags.ManageMessages);
  const isServerOwner = isOwner(message.member);
  const whitelisted   = isWhitelisted(message.member);

  // ---- Repeated message spam detection ----
  if (!isAdmin && !isMod && !whitelisted) {
    const uid     = message.author.id;
    const content = message.content.trim().toLowerCase();
    if (!userSpamTracker[guild.id][uid]) {
      userSpamTracker[guild.id][uid] = { content: '', count: 0, timer: null, messageIds: [] };
    }
    const tracker = userSpamTracker[guild.id][uid];

    if (content && content === tracker.content) {
      tracker.count++;
      tracker.messageIds.push(message.id);
    } else {
      // Different message — reset
      tracker.content    = content;
      tracker.count      = 1;
      tracker.messageIds = [message.id];
    }

    // Reset after 10 seconds of no spam
    if (tracker.timer) clearTimeout(tracker.timer);
    tracker.timer = setTimeout(() => {
      if (userSpamTracker[guild.id]) {
        userSpamTracker[guild.id][uid] = { content: '', count: 0, timer: null, messageIds: [] };
      }
    }, 10000);

    if (tracker.count >= 5) {
      // Delete the last 5 spam messages
      const idsToDelete = tracker.messageIds.slice(-5);
      for (const id of idsToDelete) {
        await message.channel.messages.fetch(id)
          .then(m => m.delete().catch(() => {}))
          .catch(() => {});
      }

      // Warn or kick based on existing warnings
      if (!warnings[guild.id][uid]) warnings[guild.id][uid] = 0;
      warnings[guild.id][uid]++;
      const warnCount = warnings[guild.id][uid];

      // Reset spam tracker after action
      userSpamTracker[guild.id][uid] = { content: '', count: 0, timer: null, messageIds: [] };

      if (warnCount === 1) {
        const warn = await message.channel.send(
          `${message.author.username}, stop spamming. Your repeated messages have been deleted. This is your warning — a second offence will result in a kick.`
        );
        setTimeout(() => warn.delete().catch(() => {}), 8000);
        await sendLog(guild, bwEmbed('Spam Warning')
          .addFields(
            { name: 'User',     value: `${message.author.tag}`,    inline: true },
            { name: 'Channel',  value: `#${message.channel.name}`, inline: true },
            { name: 'Repeated', value: `"${message.content.slice(0, 80)}"` },
            { name: 'Deleted',  value: `${idsToDelete.length} message(s)` },
          ).setTimestamp());
      } else {
        if (message.member.kickable) {
          await message.member.kick('Repeated spam after warning');
          await sendLog(guild, bwEmbed('Member Kicked — Spam')
            .addFields(
              { name: 'User',   value: `${message.author.tag}`, inline: true },
              { name: 'Reason', value: 'Repeated spam after warning' },
            ).setTimestamp());
          warnings[guild.id][uid] = 0;
        }
      }
      return;
    }
  }

  // ---- Malicious content ----
  if (!isAdmin && !isMod && !whitelisted && MALICIOUS_REGEX.test(message.content)) {
    await message.delete().catch(() => {});
    if (!warnings[guild.id][message.author.id]) warnings[guild.id][message.author.id] = 0;
    warnings[guild.id][message.author.id]++;
    const warnCount = warnings[guild.id][message.author.id];

    if (warnCount === 1) {
      const warn = await message.channel.send(
        `${message.author.username}, your message was removed. This is your warning. A second violation will result in a kick.`
      );
      setTimeout(() => warn.delete().catch(() => {}), 8000);
      await sendLog(guild, bwEmbed('Member Warned')
        .addFields(
          { name: 'User',    value: `${message.author.tag}`,    inline: true },
          { name: 'Channel', value: `#${message.channel.name}`, inline: true },
          { name: 'Offence', value: '1st warning issued' },
          { name: 'Message', value: message.content.slice(0, 300) },
        ).setTimestamp());
    } else {
      if (message.member.kickable) {
        await message.member.kick('Repeated malicious content after warning');
        warnings[guild.id][message.author.id] = 0;
        await sendLog(guild, bwEmbed('Member Kicked')
          .addFields(
            { name: 'User',   value: `${message.author.tag}`,                      inline: true },
            { name: 'Reason', value: 'Repeated malicious content after warning' },
          ).setTimestamp());
      }
    }
    return;
  }

  // ---- Prefix check ----
  if (!message.content.startsWith(PREFIX)) return;
  const args    = message.content.slice(PREFIX.length).trim().split(/\s+/);
  const command = args.shift().toLowerCase();

  // =====================
  // +help
  // =====================
  if (command === 'help' || command === 'commands') {
    return message.reply({ embeds: [
      bwEmbed('Commands')
        .setDescription(`Prefix: \`${PREFIX}\``)
        .addFields(
          { name: 'General',
            value: '`+ping`  `+members`  `+userinfo [@user]`  `+serverinfo`  `+grab`' },
          { name: 'Countdown',
            value: '`+countdown set YYYY-MM-DD HH:MM label` — set a countdown\n`+countdown` — show current countdown\n`+countdown clear` — remove countdown' },
          { name: 'Moderation',
            value: '`+clear [1-100]`  `+clearall`  `+warnings [@user]`  `+clearwarnings [@user]`' },
          { name: 'Whitelist — Owner/Admin',
            value: '`+whitelist add/remove user @user`\n`+whitelist add/remove role @role`\n`+whitelist list`' },
          { name: 'Announce — Whitelist only',
            value: '`+say #channel Your message` — sends as bot. Attach image if needed.\n`+dmall Your message` — DMs every member (Owner/Admin only)' },
          { name: 'Setup — Admin only',
            value: '`+setuplogs` — creates #logs channel\n`+setupverify #channel @role` — sets up verify button' },
        ).setTimestamp()
    ]});
  }

  // =====================
  // +ping
  // =====================
  if (command === 'ping') {
    return message.reply(`Pong. Latency: **${client.ws.ping}ms**`);
  }

  // =====================
  // +members
  // =====================
  if (command === 'members') {
    const { total, humans, bots } = getMemberCount(guild);
    return message.reply({ embeds: [
      bwEmbed('Member Count')
        .addFields(
          { name: 'Total',  value: `${total}`,  inline: true },
          { name: 'Humans', value: `${humans}`, inline: true },
          { name: 'Bots',   value: `${bots}`,   inline: true },
        ).setTimestamp()
    ]});
  }

  // =====================
  // +countdown — show, set, or clear a countdown
  // =====================
  if (command === 'countdown') {
    const sub = args[0]?.toLowerCase();

    // +countdown clear
    if (sub === 'clear') {
      if (!isAdmin) return message.reply('You need Administrator to clear the countdown.');
      delete countdowns[guild.id];
      return message.reply('Countdown cleared.');
    }

    // +countdown set YYYY-MM-DD HH:MM label
    if (sub === 'set') {
      if (!isAdmin) return message.reply('You need Administrator to set the countdown.');

      // args: ['set', 'YYYY-MM-DD', 'HH:MM', ...label words]
      const datePart  = args[1];
      const timePart  = args[2] || '00:00';
      const label     = args.slice(3).join(' ') || 'Countdown';

      if (!datePart || !/^\d{4}-\d{2}-\d{2}$/.test(datePart)) {
        return message.reply('Format: `+countdown set YYYY-MM-DD HH:MM Label`\nExample: `+countdown set 2025-12-31 23:59 New Year`');
      }

      const target = new Date(`${datePart}T${timePart}:00`);
      if (isNaN(target.getTime())) {
        return message.reply('Invalid date or time. Use format: `YYYY-MM-DD HH:MM`');
      }
      if (target <= new Date()) {
        return message.reply('That date is already in the past.');
      }

      countdowns[guild.id] = { date: target, label };
      const diff   = target - Date.now();
      const days   = Math.floor(diff / 86400000);
      const hours  = Math.floor((diff % 86400000) / 3600000);
      const mins   = Math.floor((diff % 3600000) / 60000);

      return message.reply({ embeds: [
        bwEmbed(label)
          .setDescription(`Countdown set. Use \`+countdown\` anytime to check it.`)
          .addFields(
            { name: 'Target Date', value: target.toUTCString().replace(' GMT', ' UTC'), inline: false },
            { name: 'Time Remaining', value: `${days}d ${hours}h ${mins}m`, inline: false },
          ).setTimestamp()
      ]});
    }

    // +countdown — show current
    const cd = countdowns[guild.id];
    if (!cd) {
      return message.reply('No countdown set. Use `+countdown set YYYY-MM-DD HH:MM Label` to set one.');
    }

    const now  = Date.now();
    const diff = cd.date - now;

    if (diff <= 0) {
      delete countdowns[guild.id];
      return message.reply({ embeds: [
        bwEmbed(cd.label)
          .setDescription('The countdown has ended.')
          .setTimestamp()
      ]});
    }

    const days  = Math.floor(diff / 86400000);
    const hours = Math.floor((diff % 86400000) / 3600000);
    const mins  = Math.floor((diff % 3600000) / 60000);
    const secs  = Math.floor((diff % 60000) / 1000);

    // Build a clean visual bar
    const totalDays    = Math.ceil((cd.date - new Date(cd.date).setHours(0,0,0,0) + diff) / 86400000);
    const progress     = Math.max(0, Math.min(20, Math.floor((1 - diff / (cd.date - now + diff)) * 20)));
    const bar          = '█'.repeat(progress) + '░'.repeat(20 - progress);

    return message.reply({ embeds: [
      new EmbedBuilder()
        .setColor(0x000000)
        .setTitle(cd.label)
        .setDescription(`\`${bar}\``)
        .addFields(
          { name: 'Days',    value: `${days}`,  inline: true },
          { name: 'Hours',   value: `${hours}`, inline: true },
          { name: 'Minutes', value: `${mins}`,  inline: true },
          { name: 'Seconds', value: `${secs}`,  inline: true },
          { name: 'Target',  value: cd.date.toUTCString().replace(' GMT', ' UTC'), inline: false },
        )
        .setFooter({ text: 'Run +countdown again to refresh' })
        .setTimestamp()
    ]});
  }

  // =====================
  // +dmall <message> — DM every human member in the server
  // Owner/Admin only
  // =====================
  if (command === 'dmall') {
    if (!isServerOwner && !isAdmin) {
      return message.reply('Only the server owner or admins can use this command.');
    }

    const content = args.join(' ');
    if (!content) return message.reply('Provide a message. Example: `+dmall Hello everyone!`');

    // Confirm first to avoid accidental mass DMs
    const attachment = message.attachments.first();

    await message.reply('Starting DM broadcast. This may take a while...');

    // Fetch all members
    await guild.members.fetch();
    const humans = guild.members.cache.filter(m => !m.user.bot);

    let sent    = 0;
    let failed  = 0;

    const embed = new EmbedBuilder()
      .setColor(0x000000)
      .setTitle(`Message from ${guild.name}`)
      .setDescription(content)
      .setThumbnail(guild.iconURL())
      .setFooter({ text: `Sent by ${guild.name}` })
      .setTimestamp();

    for (const [, member] of humans) {
      try {
        await member.send({
          embeds: [embed],
          files: attachment ? [attachment.url] : [],
        });
        sent++;
      } catch (e) {
        failed++; // user has DMs disabled or blocked the bot
      }
      // Small delay to avoid hitting Discord rate limits
      await new Promise(r => setTimeout(r, 800));
    }

    const summary = await message.channel.send(
      `DM broadcast complete.\n**Sent:** ${sent}\n**Failed:** ${failed} (users with DMs disabled)`
    );

    await sendLog(guild, bwEmbed('DM Broadcast Sent')
      .addFields(
        { name: 'By',      value: message.author.tag, inline: true },
        { name: 'Sent',    value: `${sent}`,           inline: true },
        { name: 'Failed',  value: `${failed}`,         inline: true },
        { name: 'Message', value: content.slice(0, 300) },
      ).setTimestamp());

    return;
  }

  // =====================
  // +grab — last deleted message or image
  // =====================
  if (command === 'grab') {
    if (!isAdmin && !isMod) return message.reply('You need Manage Messages to use this.');
    const last = deletedMessages[guild.id];
    if (!last) return message.reply('No deleted messages recorded yet.');

    const timeSince = Math.floor((Date.now() - last.timestamp) / 1000);
    const embed = bwEmbed('Last Deleted Message')
      .addFields(
        { name: 'Author',  value: last.author,           inline: true },
        { name: 'Channel', value: `#${last.channel}`,    inline: true },
        { name: 'Deleted', value: `${timeSince}s ago`,   inline: true },
      ).setTimestamp();

    if (last.content) embed.setDescription(last.content);

    const files = [];
    if (last.attachments.length > 0) {
      embed.addFields({ name: 'Attachments', value: last.attachments.map(a => a.name).join(', ') });
      files.push(...last.attachments.map(a => a.url));
    }

    return message.reply({ embeds: [embed], files }).catch(() =>
      message.reply({ embeds: [embed] }) // fallback if attachment URL expired
    );
  }

  // =====================
  // +setuplogs
  // =====================
  if (command === 'setuplogs') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    const existing = getLogChannel(guild);
    if (existing) return message.reply(`Logs channel already exists: <#${existing.id}>`);
    try {
      const created = await guild.channels.create({
        name: 'logs',
        reason: 'Bot log channel setup',
        permissionOverwrites: [
          { id: guild.roles.everyone, deny: [PermissionsBitField.Flags.SendMessages] },
        ],
      });
      return message.reply(`Logs channel created: <#${created.id}>. Members cannot send messages there.`);
    } catch (e) {
      return message.reply('Failed to create logs channel. Make sure I have Manage Channels permission.');
    }
  }

  // =====================
  // +setupverify #channel @role
  // =====================
  if (command === 'setupverify') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    const targetChannel = message.mentions.channels.first();
    const role          = message.mentions.roles.first();

    if (!targetChannel || !role) {
      return message.reply('Usage: `+setupverify #channel @role`\nExample: `+setupverify #verify @Member`');
    }

    const verifyEmbed = bwEmbed(`Verify — ${guild.name}`)
      .setDescription('Press the button below to verify and gain access to the server.');

    const button = new ButtonBuilder()
      .setCustomId('verify_button')
      .setLabel('Verify')
      .setStyle(ButtonStyle.Secondary);

    const row = new ActionRowBuilder().addComponents(button);

    try {
      await targetChannel.send({ embeds: [verifyEmbed], components: [row] });
      verifyConfig[guild.id] = { roleId: role.id, channelId: targetChannel.id };
      return message.reply(`Verification set up in <#${targetChannel.id}>. Role to assign: **${role.name}**.`);
    } catch (e) {
      return message.reply('Failed to send verify message. Make sure I can send messages in that channel.');
    }
  }

  // =====================
  // +userinfo
  // =====================
  if (command === 'userinfo') {
    const target    = message.mentions.members.first() || message.member;
    const ageDays   = Math.floor((Date.now() - target.user.createdTimestamp) / 86400000);
    const warnCount = warnings[guild.id]?.[target.user.id] || 0;
    return message.reply({ embeds: [
      bwEmbed(`User — ${target.user.tag}`)
        .setThumbnail(target.user.displayAvatarURL())
        .addFields(
          { name: 'ID',          value: target.user.id,  inline: true },
          { name: 'Joined',      value: `<t:${Math.floor(target.joinedTimestamp / 1000)}:R>`, inline: true },
          { name: 'Account Age', value: `${ageDays} days`, inline: true },
          { name: 'Warnings',    value: `${warnCount}`,   inline: true },
          { name: 'Whitelisted', value: isWhitelisted(target) ? 'Yes' : 'No', inline: true },
          { name: 'Alt Risk',    value: ageDays < 7 ? 'High' : ageDays < 30 ? 'Medium' : 'None', inline: true },
          { name: 'Roles',       value: target.roles.cache.filter(r => r.name !== '@everyone').map(r => r.name).join(', ') || 'None' },
        ).setTimestamp()
    ]});
  }

  // =====================
  // +serverinfo
  // =====================
  if (command === 'serverinfo') {
    const { total, humans, bots } = getMemberCount(guild);
    return message.reply({ embeds: [
      bwEmbed(`Server — ${guild.name}`)
        .setThumbnail(guild.iconURL())
        .addFields(
          { name: 'Owner',   value: `<@${guild.ownerId}>`, inline: true },
          { name: 'Total',   value: `${total}`,  inline: true },
          { name: 'Humans',  value: `${humans}`, inline: true },
          { name: 'Bots',    value: `${bots}`,   inline: true },
          { name: 'Created', value: `<t:${Math.floor(guild.createdTimestamp / 1000)}:R>`, inline: true },
        ).setTimestamp()
    ]});
  }

  // =====================
  // +warnings
  // =====================
  if (command === 'warnings') {
    if (!isAdmin && !isMod) return message.reply('You need Manage Messages to use this.');
    const target = message.mentions.users.first();
    if (!target) return message.reply('Mention a user. Example: `+warnings @user`');
    const count = warnings[guild.id]?.[target.id] || 0;
    return message.reply(`${target.tag} has ${count} warning(s).`);
  }

  // =====================
  // +clearwarnings
  // =====================
  if (command === 'clearwarnings') {
    if (!isAdmin && !isMod) return message.reply('You need Manage Messages to use this.');
    const target = message.mentions.users.first();
    if (!target) return message.reply('Mention a user. Example: `+clearwarnings @user`');
    if (warnings[guild.id]) warnings[guild.id][target.id] = 0;
    return message.reply(`Warnings cleared for ${target.tag}.`);
  }

  // =====================
  // +whitelist
  // =====================
  if (command === 'whitelist') {
    if (!isServerOwner && !isAdmin) return message.reply('Only the server owner or admins can manage the whitelist.');
    const sub  = args[0]?.toLowerCase();
    const type = args[1]?.toLowerCase();

    if (sub === 'list') {
      const wl    = whitelist[guild.id];
      const users = wl?.users.size > 0 ? [...wl.users].map(id => `<@${id}>`).join(', ')    : 'None';
      const roles = wl?.roles.size > 0 ? [...wl.roles].map(id => `<@&${id}>`).join(', ') : 'None';
      return message.reply({ embeds: [
        bwEmbed('Whitelist').addFields(
          { name: 'Users', value: users },
          { name: 'Roles', value: roles },
        )
      ]});
    }

    if (!['add', 'remove'].includes(sub) || !['user', 'role'].includes(type)) {
      return message.reply('Usage: `+whitelist add/remove user/role @mention`');
    }

    if (type === 'user') {
      const target = message.mentions.users.first();
      if (!target) return message.reply('Please mention a user.');
      whitelist[guild.id].users[sub === 'add' ? 'add' : 'delete'](target.id);
      return message.reply(`${target.tag} ${sub === 'add' ? 'added to' : 'removed from'} whitelist.`);
    }
    if (type === 'role') {
      const role = message.mentions.roles.first();
      if (!role) return message.reply('Please mention a role.');
      whitelist[guild.id].roles[sub === 'add' ? 'add' : 'delete'](role.id);
      return message.reply(`${role.name} ${sub === 'add' ? 'added to' : 'removed from'} whitelist.`);
    }
  }

  // =====================
  // +say — whitelist only, sends as bot
  // =====================
  if (command === 'say') {
    if (!isAdmin && !isServerOwner && !whitelisted) {
      return message.reply('Only whitelisted users or admins can use this command.');
    }
    const targetChannel = message.mentions.channels.first();
    if (!targetChannel) return message.reply('Mention a channel. Example: `+say #general Hello!`');
    const content    = message.content.replace(`${PREFIX}say`, '').replace(`<#${targetChannel.id}>`, '').trim();
    const attachment = message.attachments.first();
    if (!content && !attachment) return message.reply('Provide a message or image to send.');

    try {
      const webhooks = await targetChannel.fetchWebhooks();
      let webhook = webhooks.find(w => w.name === 'Avia');
      if (!webhook) {
        webhook = await targetChannel.createWebhook({
          name: 'Avia',
          avatar: client.user.displayAvatarURL(),
        });
      }
      const wc = new WebhookClient({ id: webhook.id, token: webhook.token });
      await wc.send({
        content:   content || undefined,
        files:     attachment ? [attachment.url] : [],
        username:  client.user.username,           // always the bot name
        avatarURL: client.user.displayAvatarURL(), // always the bot avatar
      });
      await message.delete().catch(() => {});
    } catch (e) {
      console.error('Webhook error:', e.message);
      message.reply('Failed to send. Make sure I have Manage Webhooks permission in that channel.');
    }
    return;
  }

  // =====================
  // +clear [amount] — bulk delete (14-day window)
  // =====================
  if (command === 'clear') {
    if (!isMod && !isAdmin) return message.reply('You need Manage Messages to use this.');
    const amount = parseInt(args[0]);
    if (isNaN(amount) || amount < 1 || amount > 100) return message.reply('Provide a number between 1 and 100.');
    await message.delete().catch(() => {});
    const fetched   = await message.channel.messages.fetch({ limit: amount });
    const twoWeeks  = Date.now() - 14 * 24 * 60 * 60 * 1000;
    const deletable = fetched.filter(m => m.createdTimestamp > twoWeeks);
    if (deletable.size === 0) {
      const w = await message.channel.send('No messages in the 14-day window. Use `+clearall` to delete all messages regardless of date.');
      return setTimeout(() => w.delete().catch(() => {}), 5000);
    }
    await message.channel.bulkDelete(deletable, true).catch(console.error);
    const confirm = await message.channel.send(`Deleted ${deletable.size} message(s).`);
    setTimeout(() => confirm.delete().catch(() => {}), 3000);
  }

  // =====================
  // +clearall — deletes every message in the channel, any age
  // =====================
  if (command === 'clearall') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    await message.delete().catch(() => {});
    const notice = await message.channel.send('Clearing all messages. This may take a while...');
    let deleted   = 0;
    let keepGoing = true;

    while (keepGoing) {
      const fetched = await message.channel.messages.fetch({ limit: 100 }).catch(() => null);
      if (!fetched || fetched.size === 0) break;

      const recent  = fetched.filter(m => m.id !== notice.id && Date.now() - m.createdTimestamp < 14 * 24 * 60 * 60 * 1000);
      const old     = fetched.filter(m => m.id !== notice.id && Date.now() - m.createdTimestamp >= 14 * 24 * 60 * 60 * 1000);

      if (recent.size > 0) {
        await message.channel.bulkDelete(recent, true).catch(() => {});
        deleted += recent.size;
      }
      for (const [, msg] of old) {
        await msg.delete().catch(() => {});
        deleted++;
        await new Promise(r => setTimeout(r, 350)); // stay within rate limits
      }
      if (fetched.size < 100) keepGoing = false;
    }

    await notice.delete().catch(() => {});
    const confirm = await message.channel.send(`Cleared ${deleted} message(s).`);
    setTimeout(() => confirm.delete().catch(() => {}), 4000);
  }

  // =====================
  // +hide #channel — hide a channel from @everyone
  // +hide #channel @role — hide from everyone except a specific role
  // =====================
  if (command === 'hide') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');

    const target   = message.mentions.channels.first();
    const role     = message.mentions.roles.first();
    const everyone = guild.roles.everyone;

    if (!target) return message.reply('Mention a channel. Example: `+hide #channel` or `+hide #channel @role`');

    try {
      const overwrites = [{ id: everyone, deny: [PermissionsBitField.Flags.ViewChannel] }];

      // If a role is specified, allow that role to still see it
      if (role) {
        overwrites.push({ id: role, allow: [PermissionsBitField.Flags.ViewChannel] });
      }

      await target.permissionOverwrites.set(overwrites);

      const msg = role
        ? `<#${target.id}> is now hidden from @everyone. Only **${role.name}** can see it.`
        : `<#${target.id}> is now hidden from @everyone.`;

      const done = await message.channel.send(msg);
      setTimeout(() => done.delete().catch(() => {}), 6000);
      await message.delete().catch(() => {});

      await sendLog(guild, bwEmbed('Channel Hidden')
        .addFields(
          { name: 'By',             value: message.author.tag,                    inline: true },
          { name: 'Channel',        value: `#${target.name}`,                     inline: true },
          { name: 'Visible to',     value: role ? role.name : 'Nobody (admins only)', inline: true },
        ).setTimestamp());
    } catch (e) {
      console.error('Hide error:', e.message);
      message.reply('Failed to hide that channel. Make sure I have Manage Channels permission and my role is high enough.');
    }
    return;
  }

  // =====================
  // +unhide #channel — restore a channel back to visible for @everyone
  // =====================
  if (command === 'unhide') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');

    const target   = message.mentions.channels.first();
    const everyone = guild.roles.everyone;

    if (!target) return message.reply('Mention a channel. Example: `+unhide #channel`');

    try {
      await target.permissionOverwrites.edit(everyone, { ViewChannel: true });

      const done = await message.channel.send(`<#${target.id}> is now visible to @everyone again.`);
      setTimeout(() => done.delete().catch(() => {}), 6000);
      await message.delete().catch(() => {});

      await sendLog(guild, bwEmbed('Channel Unhidden')
        .addFields(
          { name: 'By',      value: message.author.tag, inline: true },
          { name: 'Channel', value: `#${target.name}`,  inline: true },
        ).setTimestamp());
    } catch (e) {
      console.error('Unhide error:', e.message);
      message.reply('Failed to unhide that channel. Make sure I have Manage Channels permission.');
    }
    return;
  }

});

// =====================
// Login
// =====================
client.login(process.env.DISCORD_TOKEN);

require('dotenv').config();
const {
  Client, GatewayIntentBits, EmbedBuilder, PermissionsBitField,
  WebhookClient, AuditLogEvent, ButtonBuilder, ButtonStyle,
  ActionRowBuilder, Events, ChannelType, AttachmentBuilder,
} = require('discord.js');
const path    = require('path');
const storage = require('./storage');

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

// ─────────────────────────────────────────
// Runtime storage (resets on restart — ok for these)
// ─────────────────────────────────────────
const warnings             = {};
const whitelist            = {};
const botSpamTracker       = {};
const channelDeleteTracker = {};
const deletedMessages      = {};
const userSpamTracker      = {};
const countdowns           = {};
const openTickets          = {}; // { channelId: { userId, claimedBy, guildId } }

// ─────────────────────────────────────────
// Persistent config (survives restarts)
// ─────────────────────────────────────────
// verifyConfig[guildId]  = { roleId }
// ticketConfig[guildId]  = { supportRoleId, closeRoleId, categoryId, panelChannelId }
const verifyConfig = storage.get('verifyConfig', {});
const ticketConfig = storage.get('ticketConfig', {});

function saveVerify() { storage.set('verifyConfig', verifyConfig); }
function saveTicket() { storage.set('ticketConfig', ticketConfig); }

// ─────────────────────────────────────────
// Constants
// ─────────────────────────────────────────
const MALICIOUS_REGEX = /https?:\/\/[^\s]+|discord\.gg\/[^\s]+|www\.[^\s]+|@everyone|@here|\b(free nitro|claim your prize|you (have been|were) selected)\b/gi;
const BANNER_PATH     = path.join(__dirname, 'banner.png');

// ─────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────
const getLogChannel = guild => guild.channels.cache.find(ch => ch.name === 'logs');
const isOwner       = member => member.guild.ownerId === member.user.id;
const isWhitelisted = member => {
  const wl = whitelist[member.guild.id];
  if (!wl) return false;
  if (wl.users.has(member.user.id)) return true;
  return [...member.roles.cache.keys()].some(id => wl.roles.has(id));
};

function initGuild(guildId) {
  if (!whitelist[guildId])        whitelist[guildId]        = { users: new Set(), roles: new Set() };
  if (!warnings[guildId])         warnings[guildId]         = {};
  if (!deletedMessages[guildId])  deletedMessages[guildId]  = null;
  if (!userSpamTracker[guildId])  userSpamTracker[guildId]  = {};
}

async function sendLog(guild, embed) {
  const ch = getLogChannel(guild);
  if (ch) await ch.send({ embeds: [embed] }).catch(() => {});
}

const bw = title => new EmbedBuilder().setColor(0x000000).setTitle(title);

const getMemberCount = guild => {
  const total = guild.memberCount;
  const bots  = guild.members.cache.filter(m => m.user.bot).size;
  return { total, humans: total - bots, bots };
};

// ─────────────────────────────────────────
// Bot Ready
// ─────────────────────────────────────────
client.once('ready', () => {
  console.log(`Online — ${client.user.tag}`);
  client.guilds.cache.forEach(g => initGuild(g.id));
});

// ─────────────────────────────────────────
// Track deleted messages
// ─────────────────────────────────────────
client.on('messageDelete', message => {
  if (!message.guild || message.author?.bot) return;
  deletedMessages[message.guild.id] = {
    content:     message.content || null,
    author:      message.author?.tag || 'Unknown',
    channel:     message.channel?.name || 'unknown',
    attachments: [...(message.attachments?.values() || [])].map(a => ({ url: a.url, name: a.name })),
    timestamp:   Date.now(),
  };
});

// ─────────────────────────────────────────
// Member Join
// ─────────────────────────────────────────
client.on('guildMemberAdd', async member => {
  initGuild(member.guild.id);
  const guild   = member.guild;
  const ageDays = Math.floor((Date.now() - member.user.createdTimestamp) / 86400000);
  const { total } = getMemberCount(guild);

  const welcomeChannel = guild.channels.cache.find(ch => ['welcome','general','lobby'].includes(ch.name));
  if (welcomeChannel) {
    await welcomeChannel.send({ embeds: [
      bw(`Welcome to ${guild.name}`)
        .setDescription(`${member.user.username} just joined.`)
        .setThumbnail(member.user.displayAvatarURL())
        .addFields(
          { name: 'Member', value: `<@${member.user.id}>`, inline: true },
          { name: 'Count',  value: `${total}`,             inline: true },
        )
        .setFooter({ text: `Member #${total}` })
        .setTimestamp()
    ]}).catch(() => {});
  }

  const logEmbed = bw('Member Joined')
    .setThumbnail(member.user.displayAvatarURL())
    .addFields(
      { name: 'User',        value: `${member.user.tag}`, inline: true },
      { name: 'ID',          value: `${member.user.id}`,  inline: true },
      { name: 'Account Age', value: `${ageDays}d`,        inline: true },
      { name: 'Members',     value: `${total}`,           inline: true },
      { name: 'Alt Risk',    value: ageDays < 7 ? 'HIGH' : ageDays < 30 ? 'MEDIUM' : 'None', inline: true },
    ).setTimestamp();

  if (ageDays < 7)       logEmbed.setColor(0xED4245);
  else if (ageDays < 30) logEmbed.setColor(0xFEE75C);
  await sendLog(guild, logEmbed);

  if (ageDays < 7) {
    const lc = getLogChannel(guild);
    if (lc) lc.send(`[ALT ALERT] <@${member.user.id}> — account is only ${ageDays} day(s) old.`).catch(() => {});
  }
});

// ─────────────────────────────────────────
// Member Leave
// ─────────────────────────────────────────
client.on('guildMemberRemove', async member => {
  const { total } = getMemberCount(member.guild);
  await sendLog(member.guild, bw('Member Left')
    .setThumbnail(member.user.displayAvatarURL())
    .addFields(
      { name: 'User',      value: `${member.user.tag}`, inline: true },
      { name: 'ID',        value: `${member.user.id}`,  inline: true },
      { name: 'Remaining', value: `${total}`,           inline: true },
    ).setTimestamp());
});

// ─────────────────────────────────────────
// Rogue Bot — Channel Delete
// ─────────────────────────────────────────
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
    channelDeleteTracker[guild.id][executor.id] = channelDeleteTracker[guild.id][executor.id].filter(t => now - t < 60000);
    if (channelDeleteTracker[guild.id][executor.id].length >= 2) {
      const member = guild.members.cache.get(executor.id);
      if (member?.bannable) {
        await member.ban({ reason: 'Rogue bot: mass channel deletion' });
        await sendLog(guild, bw('Rogue Bot Banned').addFields(
          { name: 'Bot',    value: `${executor.tag}`,      inline: true },
          { name: 'Reason', value: 'Mass channel deletion', inline: true },
        ).setTimestamp());
      }
    }
  } catch (e) { console.error('Channel delete audit:', e.message); }
});

// ─────────────────────────────────────────
// Button Interactions
// ─────────────────────────────────────────
client.on(Events.InteractionCreate, async interaction => {
  if (!interaction.isButton()) return;
  const guild  = interaction.guild;
  const member = interaction.member;

  // ── Verify ─────────────────────────────
  if (interaction.customId === 'verify_button') {
    const config = verifyConfig[guild.id];
    if (!config) return interaction.reply({ content: 'Verification is not configured. Ask an admin to run `+setupverify`.', ephemeral: true });
    const role = guild.roles.cache.get(config.roleId);
    if (!role) return interaction.reply({ content: 'Verified role not found. Ask an admin to reconfigure with `+setupverify`.', ephemeral: true });
    if (member.roles.cache.has(role.id)) return interaction.reply({ content: 'You are already verified.', ephemeral: true });
    try {
      await member.roles.add(role);
      await interaction.reply({ content: `You have been verified and given the **${role.name}** role. Welcome.`, ephemeral: true });
      await sendLog(guild, bw('Member Verified').addFields(
        { name: 'User', value: `${interaction.user.tag}`, inline: true },
        { name: 'Role', value: role.name,                  inline: true },
      ).setTimestamp());
    } catch {
      await interaction.reply({ content: 'Failed to assign role. Make sure the bot role is above the verified role in Server Settings.', ephemeral: true });
    }
    return;
  }

  // ── Open Ticket ────────────────────────
  if (interaction.customId === 'ticket_open') {
    const config = ticketConfig[guild.id];
    if (!config) return interaction.reply({ content: 'Ticket system is not configured.', ephemeral: true });

    const existing = Object.entries(openTickets).find(([, t]) => t.userId === interaction.user.id && t.guildId === guild.id);
    if (existing) return interaction.reply({ content: `You already have an open ticket: <#${existing[0]}>`, ephemeral: true });

    await interaction.deferReply({ ephemeral: true });

    try {
      const category = config.categoryId ? guild.channels.cache.get(config.categoryId) : null;
      const ticketChannel = await guild.channels.create({
        name: `ticket-${interaction.user.username.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 20)}`,
        type: ChannelType.GuildText,
        parent: category || undefined,
        permissionOverwrites: [
          { id: guild.roles.everyone, deny: [PermissionsBitField.Flags.ViewChannel] },
          { id: interaction.user.id,  allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages] },
          { id: client.user.id,       allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ManageChannels] },
          ...(config.supportRoleId ? [{ id: config.supportRoleId, allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages] }] : []),
        ],
      });

      openTickets[ticketChannel.id] = { userId: interaction.user.id, claimedBy: null, guildId: guild.id };

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('ticket_claim').setLabel('Claim').setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId('ticket_close').setLabel('Close Ticket').setStyle(ButtonStyle.Danger),
      );

      const banner = new AttachmentBuilder(BANNER_PATH, { name: 'banner.png' });

      await ticketChannel.send({
        content: `<@${interaction.user.id}>`,
        files: [banner],
        embeds: [
          bw('Support Ticket')
            .setImage('attachment://banner.png')
            .addFields(
              { name: 'Opened by', value: `${interaction.user.tag}`, inline: true },
              { name: 'Status',    value: 'Open — awaiting staff',   inline: true },
            )
            .setDescription('Describe your issue below. A staff member will be with you shortly.')
            .setFooter({ text: 'Claim to assign yourself · Close to delete this ticket' })
            .setTimestamp()
        ],
        components: [row],
      });

      await interaction.editReply({ content: `Your ticket has been created: <#${ticketChannel.id}>` });
      await sendLog(guild, bw('Ticket Opened').addFields(
        { name: 'User',    value: `${interaction.user.tag}`, inline: true },
        { name: 'Channel', value: `#${ticketChannel.name}`,  inline: true },
      ).setTimestamp());
    } catch (e) {
      console.error('Ticket open error:', e.message);
      await interaction.editReply({ content: 'Failed to create ticket channel. Make sure I have Manage Channels permission.' });
    }
    return;
  }

  // ── Claim Ticket ───────────────────────
  if (interaction.customId === 'ticket_claim') {
    const ticket = openTickets[interaction.channelId];
    if (!ticket) return interaction.reply({ content: 'This is not an active ticket.', ephemeral: true });

    const config = ticketConfig[guild.id];
    const hasSupportRole = config?.supportRoleId && member.roles.cache.has(config.supportRoleId);
    const isAdmin        = member.permissions.has(PermissionsBitField.Flags.Administrator);

    if (!hasSupportRole && !isAdmin) return interaction.reply({ content: 'Only support staff can claim tickets.', ephemeral: true });
    if (ticket.claimedBy)            return interaction.reply({ content: `Already claimed by <@${ticket.claimedBy}>.`, ephemeral: true });

    ticket.claimedBy = interaction.user.id;

    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId('ticket_claim').setLabel('Claimed').setStyle(ButtonStyle.Secondary).setDisabled(true),
      new ButtonBuilder().setCustomId('ticket_close').setLabel('Close Ticket').setStyle(ButtonStyle.Danger),
    );

    const banner = new AttachmentBuilder(BANNER_PATH, { name: 'banner.png' });

    await interaction.update({
      files: [banner],
      embeds: [
        bw('Support Ticket')
          .setImage('attachment://banner.png')
          .addFields(
            { name: 'Opened by',  value: `<@${ticket.userId}>`,       inline: true },
            { name: 'Claimed by', value: `${interaction.user.tag}`,    inline: true },
            { name: 'Status',     value: 'Claimed',                    inline: true },
          )
          .setFooter({ text: 'Ticket has been claimed' })
          .setTimestamp()
      ],
      components: [row],
    });

    await sendLog(guild, bw('Ticket Claimed').addFields(
      { name: 'Claimed by', value: `${interaction.user.tag}`,       inline: true },
      { name: 'Channel',    value: `#${interaction.channel.name}`,  inline: true },
    ).setTimestamp());
    return;
  }

  // ── Close Ticket ───────────────────────
  if (interaction.customId === 'ticket_close') {
    const ticket = openTickets[interaction.channelId];
    if (!ticket) return interaction.reply({ content: 'This is not an active ticket.', ephemeral: true });

    const config         = ticketConfig[guild.id];
    const hasSupportRole = config?.supportRoleId && member.roles.cache.has(config.supportRoleId);
    const hasCloseRole   = config?.closeRoleId   && member.roles.cache.has(config.closeRoleId);
    const isAdmin        = member.permissions.has(PermissionsBitField.Flags.Administrator);
    const isTicketOwner  = interaction.user.id === ticket.userId;

    if (!hasSupportRole && !hasCloseRole && !isAdmin && !isTicketOwner) {
      return interaction.reply({ content: 'You do not have permission to close this ticket.', ephemeral: true });
    }

    await interaction.reply({ content: `Ticket closed by ${interaction.user.tag}. Channel deletes in 5 seconds.` });
    await sendLog(guild, bw('Ticket Closed').addFields(
      { name: 'Closed by', value: `${interaction.user.tag}`,      inline: true },
      { name: 'Channel',   value: `#${interaction.channel.name}`, inline: true },
      { name: 'Opened by', value: `<@${ticket.userId}>`,          inline: true },
    ).setTimestamp());

    delete openTickets[interaction.channelId];
    setTimeout(() => interaction.channel.delete().catch(() => {}), 5000);
    return;
  }
});

// ─────────────────────────────────────────
// Message Handler
// ─────────────────────────────────────────
client.on('messageCreate', async message => {
  const guild = message.guild;
  if (!guild) return;
  initGuild(guild.id);

  // ── Rogue bot spam ─────────────────────
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
      const m = guild.members.cache.get(botId);
      if (m?.bannable) {
        await m.ban({ reason: 'Rogue bot: message spam' });
        await sendLog(guild, bw('Rogue Bot Banned').addFields(
          { name: 'Bot',    value: `${message.author.tag}`,    inline: true },
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

  // ── Advanced Spam Detection ────────────
  if (!isAdmin && !isMod && !whitelisted) {
    const uid = message.author.id;

    // Timeout durations per warning count
    // warning 1 = 30 min, 2 = 1 hr, 3+ = 1 day
    const TIMEOUT_DURATIONS = [0, 30 * 60 * 1000, 60 * 60 * 1000, 24 * 60 * 60 * 1000];
    const TIMEOUT_LABELS    = ['', '30 minutes', '1 hour', '1 day'];

    async function applySpamAction(reason, deleteCount = 0) {
      // Delete recent messages
      if (deleteCount > 0) {
        const fetched = await message.channel.messages.fetch({ limit: deleteCount + 1 }).catch(() => null);
        if (fetched) {
          const toDelete = fetched.filter(m => m.author.id === uid);
          for (const [, m] of toDelete) await m.delete().catch(() => {});
        }
      }

      if (!warnings[guild.id][uid]) warnings[guild.id][uid] = 0;
      warnings[guild.id][uid]++;
      const warnCount = warnings[guild.id][uid];

      // Reset tracker
      userSpamTracker[guild.id][uid] = { messages: [], rateMsgs: [], timer: null };

      const duration = TIMEOUT_DURATIONS[Math.min(warnCount, 3)];
      const label    = TIMEOUT_LABELS[Math.min(warnCount, 3)];

      // Apply timeout
      try {
        await message.member.disableCommunicationUntil(
          Date.now() + duration,
          `Spam: ${reason} (warning ${warnCount})`
        );
      } catch (e) {
        console.error('Timeout error:', e.message);
      }

      const notice = await message.channel.send(
        `${message.author.username}, you have been timed out for **${label}**. Reason: ${reason}. Warning ${warnCount}/3.`
      );
      setTimeout(() => notice.delete().catch(() => {}), 10000);

      await sendLog(guild, bw('Spam Timeout')
        .addFields(
          { name: 'User',     value: `${message.author.tag}`,    inline: true },
          { name: 'Channel',  value: `#${message.channel.name}`, inline: true },
          { name: 'Reason',   value: reason,                     inline: true },
          { name: 'Duration', value: label,                      inline: true },
          { name: 'Warning',  value: `${warnCount}/3`,           inline: true },
        ).setTimestamp());
    }

    // Init tracker
    if (!userSpamTracker[guild.id][uid]) {
      userSpamTracker[guild.id][uid] = { messages: [], rateMsgs: [], timer: null };
    }
    const tracker = userSpamTracker[guild.id][uid];

    const now     = Date.now();
    const content = message.content.trim();

    // Track all messages for rate spam (sliding 5s window)
    tracker.rateMsgs.push(now);
    tracker.rateMsgs = tracker.rateMsgs.filter(t => now - t < 5000);

    // Reset inactivity timer
    if (tracker.timer) clearTimeout(tracker.timer);
    tracker.timer = setTimeout(() => {
      if (userSpamTracker[guild.id]) {
        userSpamTracker[guild.id][uid] = { messages: [], rateMsgs: [], timer: null };
      }
    }, 10000);

    // ── 1. Rate spam — 6+ different messages in 5 seconds
    if (tracker.rateMsgs.length >= 6) {
      await applySpamAction('Sending messages too rapidly', 6);
      return;
    }

    // ── 2. Repeated identical messages — 5 in a row
    tracker.messages.push(content);
    if (tracker.messages.length > 5) tracker.messages.shift();
    if (tracker.messages.length === 5 && tracker.messages.every(m => m === tracker.messages[0])) {
      await applySpamAction('Repeated identical messages', 5);
      return;
    }

    // ── 3. Mass mentions — 4+ unique mentions in one message
    const mentionCount = (message.mentions.users.size || 0) + (message.mentions.roles.size || 0);
    if (mentionCount >= 4) {
      await message.delete().catch(() => {});
      await applySpamAction(`Mass mentions (${mentionCount} mentions in one message)`, 0);
      return;
    }

    // ── 4. Excessive caps — 70%+ caps in messages over 10 chars
    if (content.length > 10) {
      const letters  = content.replace(/[^a-zA-Z]/g, '');
      const capsRate = letters.length > 0 ? (content.replace(/[^A-Z]/g, '').length / letters.length) : 0;
      if (capsRate >= 0.7) {
        await message.delete().catch(() => {});
        await applySpamAction('Excessive caps', 0);
        return;
      }
    }

    // ── 5. Repeated characters — e.g. AAAAAAA (7+ same chars in a row)
    if (/(.)\1{6,}/.test(content)) {
      await message.delete().catch(() => {});
      await applySpamAction('Repeated characters', 0);
      return;
    }
  }

  // ── Malicious content ──────────────────
  if (!isAdmin && !isMod && !whitelisted && MALICIOUS_REGEX.test(message.content)) {
    await message.delete().catch(() => {});
    if (!warnings[guild.id][message.author.id]) warnings[guild.id][message.author.id] = 0;
    warnings[guild.id][message.author.id]++;

    if (warnings[guild.id][message.author.id] === 1) {
      const w = await message.channel.send(`${message.author.username}, your message was removed. This is your warning. A second violation results in a kick.`);
      setTimeout(() => w.delete().catch(() => {}), 8000);
      await sendLog(guild, bw('Member Warned').addFields(
        { name: 'User',    value: `${message.author.tag}`,    inline: true },
        { name: 'Channel', value: `#${message.channel.name}`, inline: true },
        { name: 'Message', value: message.content.slice(0, 300) },
      ).setTimestamp());
    } else {
      if (message.member.kickable) {
        await message.member.kick('Repeated malicious content after warning');
        warnings[guild.id][message.author.id] = 0;
        await sendLog(guild, bw('Member Kicked').addFields(
          { name: 'User',   value: `${message.author.tag}`,      inline: true },
          { name: 'Reason', value: 'Repeated malicious content' },
        ).setTimestamp());
      }
    }
    return;
  }

  // ── Prefix ─────────────────────────────
  if (!message.content.startsWith(PREFIX)) return;
  const args    = message.content.slice(PREFIX.length).trim().split(/\s+/);
  const command = args.shift().toLowerCase();

  // ══════════════════════════════════════
  // COMMANDS
  // ══════════════════════════════════════

  // ── +help ──────────────────────────────
  if (command === 'help' || command === 'commands') {
    const embed = new EmbedBuilder()
      .setColor(0x000000)
      .setTitle('Command Reference')
      .setDescription(`Prefix \`${PREFIX}\`  ·  All times UTC  ·  Bot by Avia`)
      .addFields(
        { name: '◆  General',
          value: [
            '`+ping` — latency check',
            '`+members` — member count breakdown',
            '`+userinfo [@user]` — profile, age, warnings, alt risk',
            '`+serverinfo` — server snapshot',
            '`+grab` — recover last deleted message or image',
          ].join('\n') },
        { name: '◆  Countdown',
          value: [
            '`+countdown` — show active countdown',
            '`+countdown set YYYY-MM-DD HH:MM Label` — create',
            '`+countdown clear` — remove',
          ].join('\n') },
        { name: '◆  Moderation  *(Mod+)*',
          value: [
            '`+clear [1–100]` — bulk delete recent messages',
            '`+clearall` — wipe entire channel history',
            '`+warnings @user` — view warning count',
            '`+clearwarnings @user` — reset warnings',
          ].join('\n') },
        { name: '◆  Channel Control  *(Admin)*',
          value: [
            '`+hide #channel` — hide from @everyone',
            '`+hide #channel @role` — hide but allow one role',
            '`+unhide #channel` — restore @everyone access',
          ].join('\n') },
        { name: '◆  Whitelist  *(Owner / Admin)*',
          value: [
            '`+whitelist add user @user`',
            '`+whitelist remove user @user`',
            '`+whitelist add role @role`',
            '`+whitelist remove role @role`',
            '`+whitelist list` — view current list',
          ].join('\n') },
        { name: '◆  Broadcast  *(Whitelist / Admin)*',
          value: [
            '`+say #channel message` — post as bot via webhook',
            '`+dmall message` — DM every human member',
          ].join('\n') },
        { name: '◆  Setup  *(Admin only)*',
          value: [
            '`+setuplogs` — create #logs channel',
            '`+setupverify #channel @role` — verify gate with button',
            '`+setuptickets #channel @support-role @close-role` — ticket panel',
            '`+closeticket` — force close current ticket channel',
          ].join('\n') },
        { name: '◆  Auto Security',
          value: [
            'Links / scam text → warn → kick',
            'Repeated identical messages (5x) → warn → kick',
            'New accounts < 7 days → flagged in #logs',
            'Rogue bots spamming or deleting channels → instant ban',
          ].join('\n') },
      )
      .setFooter({ text: 'Avia  ·  Minimal. Secure. Reliable.' })
      .setTimestamp();
    return message.reply({ embeds: [embed] });
  }

  // ── +ping ──────────────────────────────
  if (command === 'ping') {
    return message.reply(`Pong. Latency: **${client.ws.ping}ms**`);
  }

  // ── +members ───────────────────────────
  if (command === 'members') {
    const { total, humans, bots } = getMemberCount(guild);
    return message.reply({ embeds: [
      bw('Member Count').addFields(
        { name: 'Total',  value: `${total}`,  inline: true },
        { name: 'Humans', value: `${humans}`, inline: true },
        { name: 'Bots',   value: `${bots}`,   inline: true },
      ).setTimestamp()
    ]});
  }

  // ── +userinfo ──────────────────────────
  if (command === 'userinfo') {
    const target    = message.mentions.members.first() || message.member;
    const ageDays   = Math.floor((Date.now() - target.user.createdTimestamp) / 86400000);
    const warnCount = warnings[guild.id]?.[target.user.id] || 0;
    return message.reply({ embeds: [
      bw(`User — ${target.user.tag}`)
        .setThumbnail(target.user.displayAvatarURL())
        .addFields(
          { name: 'ID',          value: target.user.id, inline: true },
          { name: 'Joined',      value: `<t:${Math.floor(target.joinedTimestamp / 1000)}:R>`, inline: true },
          { name: 'Account Age', value: `${ageDays} days`, inline: true },
          { name: 'Warnings',    value: `${warnCount}`,    inline: true },
          { name: 'Whitelisted', value: isWhitelisted(target) ? 'Yes' : 'No', inline: true },
          { name: 'Alt Risk',    value: ageDays < 7 ? 'High' : ageDays < 30 ? 'Medium' : 'None', inline: true },
          { name: 'Roles', value: target.roles.cache.filter(r => r.name !== '@everyone').map(r => r.name).join(', ') || 'None' },
        ).setTimestamp()
    ]});
  }

  // ── +serverinfo ────────────────────────
  if (command === 'serverinfo') {
    const { total, humans, bots } = getMemberCount(guild);
    return message.reply({ embeds: [
      bw(`Server — ${guild.name}`)
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

  // ── +countdown ─────────────────────────
  if (command === 'countdown') {
    const sub = args[0]?.toLowerCase();
    if (sub === 'clear') {
      if (!isAdmin) return message.reply('You need Administrator to clear the countdown.');
      delete countdowns[guild.id];
      return message.reply('Countdown cleared.');
    }
    if (sub === 'set') {
      if (!isAdmin) return message.reply('You need Administrator to set a countdown.');
      const datePart = args[1], timePart = args[2] || '00:00', label = args.slice(3).join(' ') || 'Countdown';
      if (!datePart || !/^\d{4}-\d{2}-\d{2}$/.test(datePart)) return message.reply('Format: `+countdown set YYYY-MM-DD HH:MM Label`');
      const target = new Date(`${datePart}T${timePart}:00`);
      if (isNaN(target.getTime())) return message.reply('Invalid date or time.');
      if (target <= new Date()) return message.reply('That date is already in the past.');
      countdowns[guild.id] = { date: target, label };
      const diff = target - Date.now();
      return message.reply({ embeds: [
        bw(label).addFields(
          { name: 'Target',         value: target.toUTCString().replace(' GMT', ' UTC') },
          { name: 'Time Remaining', value: `${Math.floor(diff/86400000)}d ${Math.floor((diff%86400000)/3600000)}h ${Math.floor((diff%3600000)/60000)}m` },
        ).setTimestamp()
      ]});
    }
    const cd = countdowns[guild.id];
    if (!cd) return message.reply('No countdown set. Use `+countdown set YYYY-MM-DD HH:MM Label`');
    const diff = cd.date - Date.now();
    if (diff <= 0) { delete countdowns[guild.id]; return message.reply({ embeds: [ bw(cd.label).setDescription('The countdown has ended.').setTimestamp() ] }); }
    const d = Math.floor(diff/86400000), h = Math.floor((diff%86400000)/3600000), m = Math.floor((diff%3600000)/60000), s = Math.floor((diff%60000)/1000);
    const filled = Math.max(0, Math.min(20, 20 - Math.floor((diff / (365*86400000)) * 20)));
    return message.reply({ embeds: [
      new EmbedBuilder().setColor(0x000000).setTitle(cd.label)
        .setDescription(`\`${'█'.repeat(filled)}${'░'.repeat(20-filled)}\``)
        .addFields(
          { name: 'Days', value: `${d}`, inline: true }, { name: 'Hours', value: `${h}`, inline: true },
          { name: 'Minutes', value: `${m}`, inline: true }, { name: 'Seconds', value: `${s}`, inline: true },
          { name: 'Target', value: cd.date.toUTCString().replace(' GMT', ' UTC') },
        ).setFooter({ text: 'Run +countdown to refresh' }).setTimestamp()
    ]});
  }

  // ── +grab ──────────────────────────────
  if (command === 'grab') {
    if (!isAdmin && !isMod) return message.reply('You need Manage Messages to use this.');
    const last = deletedMessages[guild.id];
    if (!last) return message.reply('No deleted messages recorded yet.');
    const embed = bw('Last Deleted Message').addFields(
      { name: 'Author',  value: last.author,          inline: true },
      { name: 'Channel', value: `#${last.channel}`,   inline: true },
      { name: 'Deleted', value: `${Math.floor((Date.now()-last.timestamp)/1000)}s ago`, inline: true },
    ).setTimestamp();
    if (last.content) embed.setDescription(last.content);
    const files = last.attachments.length > 0 ? last.attachments.map(a => a.url) : [];
    return message.reply({ embeds: [embed], files }).catch(() => message.reply({ embeds: [embed] }));
  }

  // ── +warnings ──────────────────────────
  if (command === 'warnings') {
    if (!isAdmin && !isMod) return message.reply('You need Manage Messages to use this.');
    const target = message.mentions.users.first();
    if (!target) return message.reply('Mention a user. Example: `+warnings @user`');
    return message.reply(`${target.tag} has ${warnings[guild.id]?.[target.id] || 0} warning(s).`);
  }

  // ── +clearwarnings ─────────────────────
  if (command === 'clearwarnings') {
    if (!isAdmin && !isMod) return message.reply('You need Manage Messages to use this.');
    const target = message.mentions.users.first();
    if (!target) return message.reply('Mention a user.');
    if (warnings[guild.id]) warnings[guild.id][target.id] = 0;
    return message.reply(`Warnings cleared for ${target.tag}.`);
  }

  // ── +whitelist ─────────────────────────
  if (command === 'whitelist') {
    if (!isServerOwner && !isAdmin) return message.reply('Only the server owner or admins can manage the whitelist.');
    const sub = args[0]?.toLowerCase(), type = args[1]?.toLowerCase();
    if (sub === 'list') {
      const wl = whitelist[guild.id];
      return message.reply({ embeds: [ bw('Whitelist').addFields(
        { name: 'Users', value: wl?.users.size > 0 ? [...wl.users].map(id=>`<@${id}>`).join(', ') : 'None' },
        { name: 'Roles', value: wl?.roles.size > 0 ? [...wl.roles].map(id=>`<@&${id}>`).join(', ') : 'None' },
      ) ]});
    }
    if (!['add','remove'].includes(sub) || !['user','role'].includes(type)) return message.reply('Usage: `+whitelist add/remove user/role @mention`');
    if (type === 'user') {
      const target = message.mentions.users.first();
      if (!target) return message.reply('Please mention a user.');
      whitelist[guild.id].users[sub==='add'?'add':'delete'](target.id);
      return message.reply(`${target.tag} ${sub==='add'?'added to':'removed from'} whitelist.`);
    }
    if (type === 'role') {
      const role = message.mentions.roles.first();
      if (!role) return message.reply('Please mention a role.');
      whitelist[guild.id].roles[sub==='add'?'add':'delete'](role.id);
      return message.reply(`${role.name} ${sub==='add'?'added to':'removed from'} whitelist.`);
    }
  }

  // ── +say ───────────────────────────────
  if (command === 'say') {
    if (!isAdmin && !isServerOwner && !whitelisted) return message.reply('Only whitelisted users or admins can use this.');
    const targetChannel = message.mentions.channels.first();
    if (!targetChannel) return message.reply('Mention a channel. Example: `+say #general Hello!`');
    const content = message.content.replace(`${PREFIX}say`,'').replace(`<#${targetChannel.id}>`,'').trim();
    const attachment = message.attachments.first();
    if (!content && !attachment) return message.reply('Provide a message or image.');
    try {
      const webhooks = await targetChannel.fetchWebhooks();
      let webhook = webhooks.find(w => w.name === 'Avia');
      if (!webhook) webhook = await targetChannel.createWebhook({ name: 'Avia', avatar: client.user.displayAvatarURL() });
      const wc = new WebhookClient({ id: webhook.id, token: webhook.token });
      await wc.send({ content: content||undefined, files: attachment?[attachment.url]:[], username: client.user.username, avatarURL: client.user.displayAvatarURL() });
      await message.delete().catch(() => {});
    } catch (e) { console.error('Webhook error:', e.message); message.reply('Failed. Make sure I have Manage Webhooks permission.'); }
    return;
  }

  // ── +dmall ─────────────────────────────
  if (command === 'dmall') {
    if (!isServerOwner && !isAdmin) return message.reply('Only the server owner or admins can use this.');
    const content = args.join(' ');
    if (!content) return message.reply('Provide a message.');
    const attachment = message.attachments.first();
    await message.reply('Starting DM broadcast...');
    await guild.members.fetch();
    const humans = guild.members.cache.filter(m => !m.user.bot);
    let sent = 0, failed = 0;
    const embed = bw(`Message from ${guild.name}`).setDescription(content).setThumbnail(guild.iconURL()).setFooter({ text: `Sent by ${guild.name}` }).setTimestamp();
    for (const [, m] of humans) {
      try { await m.send({ embeds: [embed], files: attachment?[attachment.url]:[] }); sent++; } catch { failed++; }
      await new Promise(r => setTimeout(r, 800));
    }
    await message.channel.send(`DM broadcast complete. Sent: ${sent} — Failed: ${failed}`);
    await sendLog(guild, bw('DM Broadcast').addFields(
      { name: 'By', value: message.author.tag, inline: true },
      { name: 'Sent', value: `${sent}`, inline: true },
      { name: 'Failed', value: `${failed}`, inline: true },
      { name: 'Message', value: content.slice(0,300) },
    ).setTimestamp());
    return;
  }

  // ── +setuplogs ─────────────────────────
  if (command === 'setuplogs') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    const existing = getLogChannel(guild);
    if (existing) return message.reply(`Logs channel already exists: <#${existing.id}>`);
    try {
      const created = await guild.channels.create({
        name: 'logs', reason: 'Bot log channel setup',
        permissionOverwrites: [{ id: guild.roles.everyone, deny: [PermissionsBitField.Flags.SendMessages] }],
      });
      return message.reply(`Logs channel created: <#${created.id}>`);
    } catch { return message.reply('Failed. Make sure I have Manage Channels permission.'); }
  }

  // ── +setupverify ───────────────────────
  if (command === 'setupverify') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    const targetChannel = message.mentions.channels.first();
    const role          = message.mentions.roles.first();
    if (!targetChannel || !role) return message.reply('Usage: `+setupverify #channel @role`');
    try {
      const banner = new AttachmentBuilder(BANNER_PATH, { name: 'banner.png' });
      const row    = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('verify_button').setLabel('Verify').setStyle(ButtonStyle.Secondary)
      );
      await targetChannel.send({
        files: [banner],
        embeds: [
          bw(`Verify — ${guild.name}`)
            .setImage('attachment://banner.png')
            .setDescription('Press the button below to verify and gain access to the server.')
            .setFooter({ text: 'You will only need to do this once.' })
        ],
        components: [row],
      });
      // Save persistently so restarts don't break it
      verifyConfig[guild.id] = { roleId: role.id };
      saveVerify();
      return message.reply(`Verification set up in <#${targetChannel.id}>. Role to assign: **${role.name}**.`);
    } catch (e) {
      console.error('Setupverify error:', e.message);
      return message.reply('Failed to send verify panel. Check my permissions in that channel.');
    }
  }

  // ── +setuptickets ──────────────────────
  if (command === 'setuptickets') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    const panelChannel = message.mentions.channels.first();
    const roles        = [...message.mentions.roles.values()];
    const supportRole  = roles[0];
    const closeRole    = roles[1] || roles[0]; // allow same role for both if only one mentioned
    if (!panelChannel || !supportRole) {
      return message.reply('Usage: `+setuptickets #channel @support-role @close-role`\nTip: you can use the same role twice if you want one role to handle everything.');
    }
    try {
      const banner = new AttachmentBuilder(BANNER_PATH, { name: 'banner.png' });
      const row    = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('ticket_open').setLabel('Open Ticket').setStyle(ButtonStyle.Secondary)
      );
      await panelChannel.send({
        files: [banner],
        embeds: [
          bw('Support')
            .setImage('attachment://banner.png')
            .setDescription('Press the button below to open a support ticket.\nA staff member will assist you shortly.')
            .addFields(
              { name: 'Support', value: `<@&${supportRole.id}>`, inline: true },
              { name: 'Close',   value: `<@&${closeRole.id}>`,   inline: true },
            )
            .setFooter({ text: 'One ticket per user at a time.' })
            .setTimestamp()
        ],
        components: [row],
      });
      // Save persistently
      ticketConfig[guild.id] = { supportRoleId: supportRole.id, closeRoleId: closeRole.id, categoryId: null, panelChannelId: panelChannel.id };
      saveTicket();
      return message.reply(`Ticket panel created in <#${panelChannel.id}>.\nSupport: **${supportRole.name}** — Close: **${closeRole.name}**`);
    } catch (e) {
      console.error('Ticket setup error:', e.message);
      return message.reply('Failed. Check my permissions in that channel.');
    }
  }

  // ── +closeticket ───────────────────────
  if (command === 'closeticket') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    const ticket = openTickets[message.channelId];
    if (!ticket) return message.reply('This is not an active ticket channel.');
    await message.channel.send('Closing in 5 seconds...');
    await sendLog(guild, bw('Ticket Force Closed').addFields(
      { name: 'Closed by', value: `${message.author.tag}`,        inline: true },
      { name: 'Channel',   value: `#${message.channel.name}`,     inline: true },
    ).setTimestamp());
    delete openTickets[message.channelId];
    setTimeout(() => message.channel.delete().catch(() => {}), 5000);
    return;
  }

  // ── +clear ─────────────────────────────
  if (command === 'clear') {
    if (!isMod && !isAdmin) return message.reply('You need Manage Messages to use this.');
    const amount = parseInt(args[0]);
    if (isNaN(amount) || amount < 1 || amount > 100) return message.reply('Provide a number between 1 and 100.');
    await message.delete().catch(() => {});
    const fetched   = await message.channel.messages.fetch({ limit: amount });
    const twoWeeks  = Date.now() - 14*24*60*60*1000;
    const deletable = fetched.filter(m => m.createdTimestamp > twoWeeks);
    if (deletable.size === 0) {
      const w = await message.channel.send('No messages in 14-day window. Use `+clearall` for older messages.');
      return setTimeout(() => w.delete().catch(() => {}), 5000);
    }
    await message.channel.bulkDelete(deletable, true).catch(console.error);
    const c = await message.channel.send(`Deleted ${deletable.size} message(s).`);
    setTimeout(() => c.delete().catch(() => {}), 3000);
    return;
  }

  // ── +clearall ──────────────────────────
  if (command === 'clearall') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    await message.delete().catch(() => {});
    const notice = await message.channel.send('Clearing all messages...');
    let deleted = 0, keepGoing = true;
    while (keepGoing) {
      const fetched = await message.channel.messages.fetch({ limit: 100 }).catch(() => null);
      if (!fetched || fetched.size === 0) break;
      const recent = fetched.filter(m => m.id !== notice.id && Date.now()-m.createdTimestamp < 14*24*60*60*1000);
      const old    = fetched.filter(m => m.id !== notice.id && Date.now()-m.createdTimestamp >= 14*24*60*60*1000);
      if (recent.size > 0) { await message.channel.bulkDelete(recent, true).catch(() => {}); deleted += recent.size; }
      for (const [, msg] of old) { await msg.delete().catch(() => {}); deleted++; await new Promise(r => setTimeout(r, 350)); }
      if (fetched.size < 100) keepGoing = false;
    }
    await notice.delete().catch(() => {});
    const c = await message.channel.send(`Cleared ${deleted} message(s).`);
    setTimeout(() => c.delete().catch(() => {}), 4000);
    return;
  }

  // ── +hide ──────────────────────────────
  if (command === 'hide') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    const target = message.mentions.channels.first();
    const role   = message.mentions.roles.first();
    if (!target) return message.reply('Mention a channel. Example: `+hide #channel` or `+hide #channel @role`');
    try {
      const overwrites = [{ id: guild.roles.everyone, deny: [PermissionsBitField.Flags.ViewChannel] }];
      if (role) overwrites.push({ id: role, allow: [PermissionsBitField.Flags.ViewChannel] });
      await target.permissionOverwrites.set(overwrites);
      const done = await message.channel.send(role ? `<#${target.id}> hidden. Only **${role.name}** can see it.` : `<#${target.id}> hidden from @everyone.`);
      setTimeout(() => done.delete().catch(() => {}), 6000);
      await message.delete().catch(() => {});
      await sendLog(guild, bw('Channel Hidden').addFields(
        { name: 'By', value: message.author.tag, inline: true },
        { name: 'Channel', value: `#${target.name}`, inline: true },
        { name: 'Visible to', value: role ? role.name : 'Nobody (admins only)', inline: true },
      ).setTimestamp());
    } catch { message.reply('Failed. Make sure I have Manage Channels permission and my role is high enough.'); }
    return;
  }

  // ── +unhide ────────────────────────────
  if (command === 'unhide') {
    if (!isAdmin) return message.reply('You need Administrator to use this.');
    const target = message.mentions.channels.first();
    if (!target) return message.reply('Mention a channel. Example: `+unhide #channel`');
    try {
      await target.permissionOverwrites.edit(guild.roles.everyone, { ViewChannel: true });
      const done = await message.channel.send(`<#${target.id}> is now visible to @everyone.`);
      setTimeout(() => done.delete().catch(() => {}), 6000);
      await message.delete().catch(() => {});
      await sendLog(guild, bw('Channel Unhidden').addFields(
        { name: 'By', value: message.author.tag, inline: true },
        { name: 'Channel', value: `#${target.name}`, inline: true },
      ).setTimestamp());
    } catch { message.reply('Failed. Make sure I have Manage Channels permission.'); }
    return;
  }
});

// ─────────────────────────────────────────
// Login
// ─────────────────────────────────────────
client.login(process.env.DISCORD_TOKEN);

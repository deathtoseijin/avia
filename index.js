require('dotenv').config();
const {
  Client, GatewayIntentBits, EmbedBuilder,
  PermissionsBitField, WebhookClient, AuditLogEvent,
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
const warnings = {};       // { guildId: { userId: count } }
const whitelist = {};      // { guildId: { users: Set, roles: Set } }
const botSpamTracker = {}; // { guildId: { botId: { count, timer } } }
const channelDeleteTracker = {}; // { guildId: { botId: timestamp[] } }

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
  if (!whitelist[guildId]) whitelist[guildId] = { users: new Set(), roles: new Set() };
  if (!warnings[guildId]) warnings[guildId] = {};
}

async function sendLog(guild, embed) {
  const ch = getLogChannel(guild);
  if (ch) await ch.send({ embeds: [embed] }).catch(() => {});
}

// Minimal black and white embed style
function bwEmbed(title) {
  return new EmbedBuilder().setColor(0x000000).setTitle(title);
}

function getMemberCount(guild) {
  const total = guild.memberCount;
  const bots = guild.members.cache.filter(m => m.user.bot).size;
  return { total, humans: total - bots, bots };
}

// =====================
// Bot Ready
// =====================
client.once('ready', () => {
  console.log(`Logged in as ${client.user.tag}`);
  console.log(`Security systems active | Prefix: ${PREFIX}`);
  // Initialize all guilds
  client.guilds.cache.forEach(g => initGuild(g.id));
});

// =====================
// Member Join — Welcome + Alt Check + Log
// =====================
client.on('guildMemberAdd', async member => {
  initGuild(member.guild.id);
  const guild = member.guild;
  const accountAge = Date.now() - member.user.createdTimestamp;
  const accountAgeDays = Math.floor(accountAge / (1000 * 60 * 60 * 24));
  const isAlt = accountAgeDays < 30;
  const isSuspicious = accountAgeDays < 7;

  console.log(`[JOIN] ${member.user.tag} | Account age: ${accountAgeDays}d`);

  // Member count
  const { total, humans, bots } = getMemberCount(guild);

  // --- Welcome message ---
  const welcomeChannel = guild.channels.cache.find(
    ch => ch.name === 'welcome' || ch.name === 'general' || ch.name === 'lobby'
  );
  if (welcomeChannel) {
    const welcomeEmbed = bwEmbed(`Welcome to ${guild.name}`)
      .setDescription(`${member.user.username} just joined the server.`)
      .setThumbnail(member.user.displayAvatarURL())
      .addFields(
        { name: 'Member', value: `<@${member.user.id}>`, inline: true },
        { name: 'Total Members', value: `${total}`, inline: true },
      )
      .setFooter({ text: `Member #${total}` })
      .setTimestamp();
    await welcomeChannel.send({ embeds: [welcomeEmbed] }).catch(() => {});
  }

  // --- Log entry ---
  const logEmbed = bwEmbed('Member Joined')
    .setThumbnail(member.user.displayAvatarURL())
    .addFields(
      { name: 'User', value: `${member.user.tag}`, inline: true },
      { name: 'ID', value: `${member.user.id}`, inline: true },
      { name: 'Account Age', value: `${accountAgeDays} days`, inline: true },
      { name: 'Member Count', value: `${total} total (${humans} humans, ${bots} bots)`, inline: false },
      { name: 'Alt Detection', value: isSuspicious
          ? 'HIGH RISK — Account under 7 days old'
          : isAlt
          ? 'FLAGGED — Account under 30 days old'
          : 'Clear', inline: false },
    )
    .setTimestamp();

  if (isSuspicious) logEmbed.setColor(0xED4245);
  else if (isAlt) logEmbed.setColor(0xFEE75C);

  await sendLog(guild, logEmbed);

  // --- Alert mods if suspicious ---
  if (isSuspicious) {
    const logChannel = getLogChannel(guild);
    if (logChannel) {
      await logChannel.send(
        `**[ALT ALERT]** <@${member.user.id}> joined with an account only **${accountAgeDays} day(s)** old. Consider reviewing.`
      ).catch(() => {});
    }
  }
});

// =====================
// Member Leave Log
// =====================
client.on('guildMemberRemove', async member => {
  const guild = member.guild;
  const { total } = getMemberCount(guild);
  console.log(`[LEAVE] ${member.user.tag}`);
  await sendLog(guild, bwEmbed('Member Left')
    .setThumbnail(member.user.displayAvatarURL())
    .addFields(
      { name: 'User', value: `${member.user.tag}`, inline: true },
      { name: 'ID', value: `${member.user.id}`, inline: true },
      { name: 'Member Count', value: `${total} remaining`, inline: false },
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
    const logs = await guild.fetchAuditLogs({ type: AuditLogEvent.ChannelDelete, limit: 1 });
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
        console.log(`[ROGUE BOT BANNED] ${executor.tag} — mass channel deletion`);
        await sendLog(guild, bwEmbed('Rogue Bot Banned')
          .addFields(
            { name: 'Bot', value: `${executor.tag}`, inline: true },
            { name: 'Reason', value: 'Mass channel deletion', inline: true },
          ).setTimestamp());
      }
    }
  } catch (e) {
    console.error('Channel delete audit error:', e.message);
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
        console.log(`[ROGUE BOT BANNED] ${message.author.tag} — spam`);
        await sendLog(guild, bwEmbed('Rogue Bot Banned')
          .addFields(
            { name: 'Bot', value: `${message.author.tag}`, inline: true },
            { name: 'Reason', value: '8+ messages in 5 seconds', inline: true },
          ).setTimestamp());
      }
    }
    return;
  }

  if (message.author.bot) return;

  const isAdmin = message.member?.permissions.has(PermissionsBitField.Flags.Administrator);
  const isMod = message.member?.permissions.has(PermissionsBitField.Flags.ManageMessages);
  const isServerOwner = isOwner(message.member);
  const whitelisted = isWhitelisted(message.member);

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
          { name: 'User', value: `${message.author.tag}`, inline: true },
          { name: 'Channel', value: `#${message.channel.name}`, inline: true },
          { name: 'Offence', value: '1st — Warning issued' },
          { name: 'Message', value: message.content.slice(0, 300) },
        ).setTimestamp());
    } else {
      if (message.member.kickable) {
        await message.member.kick('Repeated malicious content after warning');
        await sendLog(guild, bwEmbed('Member Kicked')
          .addFields(
            { name: 'User', value: `${message.author.tag}`, inline: true },
            { name: 'Reason', value: 'Repeated malicious content after warning' },
          ).setTimestamp());
        warnings[guild.id][message.author.id] = 0;
      }
    }
    return;
  }

  // ---- Prefix Commands ----
  if (!message.content.startsWith(PREFIX)) return;
  const args = message.content.slice(PREFIX.length).trim().split(/\s+/);
  const command = args.shift().toLowerCase();

  // +help
  if (command === 'help' || command === 'commands') {
    return message.reply({ embeds: [
      bwEmbed('Bot Commands')
        .setDescription(`Prefix: \`${PREFIX}\``)
        .addFields(
          { name: 'General', value: '`+ping`  `+userinfo [@user]`  `+serverinfo`  `+members`' },
          { name: 'Moderation', value: '`+clear [1-100]`  `+warnings [@user]`  `+clearwarnings [@user]`' },
          { name: 'Whitelist — Owner only', value: '`+whitelist add/remove user @user`\n`+whitelist add/remove role @role`\n`+whitelist list`' },
          { name: 'Announce — Admin only', value: '`+say #channel message` — sends as webhook (attach image optionally)' },
          { name: 'Setup', value: '`+setuplogs` — creates a #logs channel if missing' },
        )
        .setTimestamp()
    ]});
  }

  // +ping
  if (command === 'ping') {
    return message.reply(`Pong. Latency: **${client.ws.ping}ms**`);
  }

  // +members
  if (command === 'members') {
    const { total, humans, bots } = getMemberCount(guild);
    return message.reply({ embeds: [
      bwEmbed('Member Count')
        .addFields(
          { name: 'Total', value: `${total}`, inline: true },
          { name: 'Humans', value: `${humans}`, inline: true },
          { name: 'Bots', value: `${bots}`, inline: true },
        ).setTimestamp()
    ]});
  }

  // +setuplogs — creates #logs channel
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
      return message.reply(`Logs channel created: <#${created.id}>\nOnly the bot can send messages there.`);
    } catch (e) {
      return message.reply('Failed to create logs channel. Make sure I have Manage Channels permission.');
    }
  }

  // +userinfo
  if (command === 'userinfo') {
    const target = message.mentions.members.first() || message.member;
    const ageDays = Math.floor((Date.now() - target.user.createdTimestamp) / 86400000);
    const warnCount = warnings[guild.id]?.[target.user.id] || 0;
    return message.reply({ embeds: [
      bwEmbed(`User — ${target.user.tag}`)
        .setThumbnail(target.user.displayAvatarURL())
        .addFields(
          { name: 'ID', value: target.user.id, inline: true },
          { name: 'Joined Server', value: `<t:${Math.floor(target.joinedTimestamp / 1000)}:R>`, inline: true },
          { name: 'Account Age', value: `${ageDays} days`, inline: true },
          { name: 'Warnings', value: `${warnCount}`, inline: true },
          { name: 'Whitelisted', value: isWhitelisted(target) ? 'Yes' : 'No', inline: true },
          { name: 'Alt Risk', value: ageDays < 7 ? 'High' : ageDays < 30 ? 'Medium' : 'None', inline: true },
          { name: 'Roles', value: target.roles.cache.filter(r => r.name !== '@everyone').map(r => r.name).join(', ') || 'None' },
        ).setTimestamp()
    ]});
  }

  // +serverinfo
  if (command === 'serverinfo') {
    const { total, humans, bots } = getMemberCount(guild);
    return message.reply({ embeds: [
      bwEmbed(`Server — ${guild.name}`)
        .setThumbnail(guild.iconURL())
        .addFields(
          { name: 'Owner', value: `<@${guild.ownerId}>`, inline: true },
          { name: 'Total Members', value: `${total}`, inline: true },
          { name: 'Humans / Bots', value: `${humans} / ${bots}`, inline: true },
          { name: 'Created', value: `<t:${Math.floor(guild.createdTimestamp / 1000)}:R>`, inline: true },
        ).setTimestamp()
    ]});
  }

  // +warnings
  if (command === 'warnings') {
    if (!isAdmin && !isMod) return message.reply('You need Manage Messages to use this.');
    const target = message.mentions.users.first();
    if (!target) return message.reply('Mention a user. Example: `+warnings @user`');
    const count = warnings[guild.id]?.[target.id] || 0;
    return message.reply(`${target.tag} has ${count} warning(s).`);
  }

  // +clearwarnings
  if (command === 'clearwarnings') {
    if (!isAdmin && !isMod) return message.reply('You need Manage Messages to use this.');
    const target = message.mentions.users.first();
    if (!target) return message.reply('Mention a user. Example: `+clearwarnings @user`');
    if (warnings[guild.id]) warnings[guild.id][target.id] = 0;
    return message.reply(`Warnings cleared for ${target.tag}.`);
  }

  // +whitelist
  if (command === 'whitelist') {
    if (!isServerOwner && !isAdmin) return message.reply('Only the server owner or admins can manage the whitelist.');
    const sub = args[0]?.toLowerCase();
    const type = args[1]?.toLowerCase();

    if (sub === 'list') {
      const wl = whitelist[guild.id];
      const users = wl?.users.size > 0 ? [...wl.users].map(id => `<@${id}>`).join(', ') : 'None';
      const roles = wl?.roles.size > 0 ? [...wl.roles].map(id => `<@&${id}>`).join(', ') : 'None';
      return message.reply({ embeds: [
        bwEmbed('Whitelist')
          .addFields(
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

  // +say (webhook-style)
  if (command === 'say') {
    if (!isAdmin) return message.reply('Only admins can use this command.');
    const targetChannel = message.mentions.channels.first();
    if (!targetChannel) return message.reply('Mention a channel. Example: `+say #general Hello!`');
    const content = message.content.replace(`${PREFIX}say`, '').replace(`<#${targetChannel.id}>`, '').trim();
    const attachment = message.attachments.first();
    if (!content && !attachment) return message.reply('Provide a message or image.');
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
        content: content || undefined,
        files: attachment ? [attachment.url] : [],
        username: message.member.displayName,
        avatarURL: message.author.displayAvatarURL(),
      });
      await message.delete().catch(() => {});
    } catch (e) {
      console.error('Webhook error:', e.message);
      message.reply('Failed to send. Make sure I have Manage Webhooks permission in that channel.');
    }
    return;
  }

  // +clear
  if (command === 'clear') {
    if (!isMod && !isAdmin) return message.reply('You need Manage Messages to use this.');
    const amount = parseInt(args[0]);
    if (isNaN(amount) || amount < 1 || amount > 100) return message.reply('Provide a number between 1 and 100.');
    await message.delete().catch(() => {});
    const fetched = await message.channel.messages.fetch({ limit: amount });
    const twoWeeksAgo = Date.now() - 14 * 24 * 60 * 60 * 1000;
    const deletable = fetched.filter(m => m.createdTimestamp > twoWeeksAgo);
    if (deletable.size === 0) {
      const w = await message.channel.send('No deletable messages. Messages older than 14 days cannot be bulk deleted.');
      return setTimeout(() => w.delete().catch(() => {}), 5000);
    }
    await message.channel.bulkDelete(deletable, true).catch(console.error);
    const confirm = await message.channel.send(`Deleted ${deletable.size} message(s).`);
    setTimeout(() => confirm.delete().catch(() => {}), 3000);
  }
});

// =====================
// Login
// =====================
client.login(process.env.DISCORD_TOKEN);

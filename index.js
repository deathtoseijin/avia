require('dotenv').config();
const { Client, GatewayIntentBits, EmbedBuilder, PermissionsBitField } = require('discord.js');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.MessageContent,
  ]
});

const PREFIX = '+';

// =====================
// Link detection regex
// =====================
const LINK_REGEX = /https?:\/\/[^\s]+|discord\.gg\/[^\s]+|www\.[^\s]+/gi;

// =====================
// Bot Ready
// =====================
client.once('ready', () => {
  console.log(`✅ Logged in as ${client.user.tag}`);
  console.log(`🛡️  Security: Link blocker active`);
  console.log(`📋 Prefix: ${PREFIX}`);
});

// =====================
// Member Join Log
// =====================
client.on('guildMemberAdd', member => {
  console.log(`➡️  [JOIN] ${member.user.tag} (ID: ${member.user.id}) joined "${member.guild.name}" at ${new Date().toISOString()}`);

  // Send welcome log to a channel named "logs" if it exists
  const logChannel = member.guild.channels.cache.find(ch => ch.name === 'logs');
  if (logChannel) {
    const embed = new EmbedBuilder()
      .setColor(0x57F287)
      .setTitle('✅ Member Joined')
      .setThumbnail(member.user.displayAvatarURL())
      .addFields(
        { name: 'User', value: `${member.user.tag}`, inline: true },
        { name: 'ID', value: `${member.user.id}`, inline: true },
        { name: 'Account Created', value: `<t:${Math.floor(member.user.createdTimestamp / 1000)}:R>`, inline: true },
      )
      .setTimestamp();
    logChannel.send({ embeds: [embed] });
  }
});

// =====================
// Member Leave Log
// =====================
client.on('guildMemberRemove', member => {
  console.log(`⬅️  [LEAVE] ${member.user.tag} (ID: ${member.user.id}) left "${member.guild.name}" at ${new Date().toISOString()}`);

  const logChannel = member.guild.channels.cache.find(ch => ch.name === 'logs');
  if (logChannel) {
    const embed = new EmbedBuilder()
      .setColor(0xED4245)
      .setTitle('❌ Member Left')
      .setThumbnail(member.user.displayAvatarURL())
      .addFields(
        { name: 'User', value: `${member.user.tag}`, inline: true },
        { name: 'ID', value: `${member.user.id}`, inline: true },
      )
      .setTimestamp();
    logChannel.send({ embeds: [embed] });
  }
});

// =====================
// Message Handler
// =====================
client.on('messageCreate', async message => {
  if (message.author.bot) return;

  // ----- LINK BLOCKER (Security) -----
  const isAdmin = message.member?.permissions.has(PermissionsBitField.Flags.Administrator);
  const isMod = message.member?.permissions.has(PermissionsBitField.Flags.ManageMessages);

  if (!isAdmin && !isMod && LINK_REGEX.test(message.content)) {
    await message.delete();
    const warn = await message.channel.send(
      `⛔ **${message.author.username}**, links are not allowed in this server!`
    );
    // Auto-delete the warning after 5 seconds
    setTimeout(() => warn.delete().catch(() => {}), 5000);

    // Log it
    console.log(`🔗 [LINK BLOCKED] ${message.author.tag} tried to send a link in #${message.channel.name}`);
    const logChannel = message.guild.channels.cache.find(ch => ch.name === 'logs');
    if (logChannel) {
      const embed = new EmbedBuilder()
        .setColor(0xFEE75C)
        .setTitle('🔗 Link Blocked')
        .addFields(
          { name: 'User', value: `${message.author.tag}`, inline: true },
          { name: 'Channel', value: `#${message.channel.name}`, inline: true },
          { name: 'Message', value: message.content.slice(0, 200) },
        )
        .setTimestamp();
      logChannel.send({ embeds: [embed] });
    }
    return;
  }

  // ----- PREFIX COMMANDS -----
  if (!message.content.startsWith(PREFIX)) return;

  const args = message.content.slice(PREFIX.length).trim().split(/\s+/);
  const command = args.shift().toLowerCase();

  // +help
  if (command === 'help') {
    const embed = new EmbedBuilder()
      .setColor(0x5865F2)
      .setTitle('📋 Bot Commands')
      .setDescription(`All commands use the \`${PREFIX}\` prefix`)
      .addFields(
        { name: '`+help`', value: 'Shows this command list' },
        { name: '`+commands`', value: 'Same as +help' },
        { name: '`+ping`', value: 'Check if the bot is alive' },
        { name: '`+userinfo [@user]`', value: 'Shows info about a user' },
        { name: '`+serverinfo`', value: 'Shows info about this server' },
        { name: '`+clear [amount]`', value: 'Deletes messages (mods only)' },
      )
      .setFooter({ text: 'Security: Links are automatically blocked for regular members' })
      .setTimestamp();
    return message.reply({ embeds: [embed] });
  }

  // +commands (alias for +help)
  if (command === 'commands') {
    return message.channel.send(`Use \`+help\` to see all commands!`);
  }

  // +ping
  if (command === 'ping') {
    return message.reply(`🏓 Pong! Latency: **${client.ws.ping}ms**`);
  }

  // +userinfo
  if (command === 'userinfo') {
    const target = message.mentions.members.first() || message.member;
    const embed = new EmbedBuilder()
      .setColor(0x5865F2)
      .setTitle(`👤 User Info — ${target.user.tag}`)
      .setThumbnail(target.user.displayAvatarURL())
      .addFields(
        { name: 'Username', value: target.user.tag, inline: true },
        { name: 'ID', value: target.user.id, inline: true },
        { name: 'Joined Server', value: `<t:${Math.floor(target.joinedTimestamp / 1000)}:R>`, inline: true },
        { name: 'Account Created', value: `<t:${Math.floor(target.user.createdTimestamp / 1000)}:R>`, inline: true },
        { name: 'Roles', value: target.roles.cache.filter(r => r.name !== '@everyone').map(r => r.name).join(', ') || 'None' },
      )
      .setTimestamp();
    return message.reply({ embeds: [embed] });
  }

  // +serverinfo
  if (command === 'serverinfo') {
    const guild = message.guild;
    const embed = new EmbedBuilder()
      .setColor(0x5865F2)
      .setTitle(`🏠 Server Info — ${guild.name}`)
      .setThumbnail(guild.iconURL())
      .addFields(
        { name: 'Owner', value: `<@${guild.ownerId}>`, inline: true },
        { name: 'Members', value: `${guild.memberCount}`, inline: true },
        { name: 'Created', value: `<t:${Math.floor(guild.createdTimestamp / 1000)}:R>`, inline: true },
      )
      .setTimestamp();
    return message.reply({ embeds: [embed] });
  }

  // +clear
  if (command === 'clear') {
    if (!isMod && !isAdmin) {
      return message.reply('⛔ You need the **Manage Messages** permission to use this command.');
    }
    const amount = parseInt(args[0]);
    if (isNaN(amount) || amount < 1 || amount > 100) {
      return message.reply('Please provide a number between 1 and 100. Example: `+clear 10`');
    }
    await message.channel.bulkDelete(amount + 1, true).catch(() => {});
    const confirm = await message.channel.send(`🗑️ Deleted **${amount}** messages.`);
    setTimeout(() => confirm.delete().catch(() => {}), 3000);
  }
});

// =====================
// Login
// =====================
client.login(process.env.DISCORD_TOKEN);

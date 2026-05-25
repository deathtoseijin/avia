require('dotenv').config();
const { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes } = require('discord.js');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ]
});

// =====================
// Bot Ready Event
// =====================
client.once('ready', () => {
  console.log(`✅ Logged in as ${client.user.tag}`);
});

// =====================
// Slash Commands
// =====================
client.on('interactionCreate', async interaction => {
  if (!interaction.isChatInputCommand()) return;

  if (interaction.commandName === 'ping') {
    await interaction.reply('Pong! 🏓');
  }

  if (interaction.commandName === 'hello') {
    await interaction.reply(`Hello, ${interaction.user.username}! 👋`);
  }
});

// =====================
// Message Commands
// =====================
client.on('messageCreate', message => {
  if (message.author.bot) return;

  if (message.content === '!ping') {
    message.reply('Pong! 🏓');
  }

  if (message.content === '!hello') {
    message.reply(`Hello, ${message.author.username}! 👋`);
  }
});

// =====================
// Login
// =====================
client.login(process.env.DISCORD_TOKEN);


// =====================
// Register Slash Commands (run once if needed)
// =====================
// Uncomment the block below and run "node register.js" once to register slash commands
// You can then comment it back out

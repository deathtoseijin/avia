# My Discord Bot

## Setup

1. Install dependencies:
   ```
   npm install
   ```

2. Copy `.env.example` to `.env` and fill in your values:
   ```
   cp .env.example .env
   ```

3. Fill in your `.env`:
   - `DISCORD_TOKEN` → from Discord Developer Portal > Bot > Token
   - `CLIENT_ID` → from Discord Developer Portal > General Information > Application ID

4. Register slash commands (only need to do this once):
   ```
   npm run register
   ```

5. Start the bot:
   ```
   npm start
   ```

## Commands

| Command | Description |
|---|---|
| `!ping` or `/ping` | Replies with Pong! |
| `!hello` or `/hello` | Says hello to you |

## Hosting on Railway

1. Push this folder to a GitHub repository
2. Go to [railway.app](https://railway.app) and connect your GitHub repo
3. Add your environment variables (`DISCORD_TOKEN`, `CLIENT_ID`) in Railway's Variables tab
4. Railway will automatically run the bot 24/7

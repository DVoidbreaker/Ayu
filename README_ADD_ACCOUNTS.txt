# Multi-Account Anti-Revoke

## How to add a new account

1. Open `accounts.json`
2. Add a new entry to the `"accounts"` array:
```json
{
  "name": "myaccount",
  "api_id": 11487133,
  "api_hash": "6073668c6ef9454a004daaff211071b2",
  "secret_password": "YOUR_PASSWORD",
  "secret_bot_token": "YOUR_BOT_TOKEN",
  "secret_bot_chat_id": "YOUR_CHAT_ID"
}
```
3. Place the Telegram session file at `accounts/myaccount/anti_revoke.session`
4. Set environment variable `TG_SESSION_MYACCOUNT` with base64-encoded session (optional, for Railway)
5. Restart the app

## How to deploy to Railway

1. Push this folder to a Git repo
2. Create a new Railway project
3. Add environment variables:
   - `TG_SESSION_WW` = base64-encoded session for ww account
   - `TG_SESSION_XIZMA` = base64-encoded session for xizma account
4. Railway will auto-detect the Dockerfile and deploy

## URL Structure

- `https://your-domain.com/` - Account selector
- `https://your-domain.com/ww/` - WW account panel
- `https://your-domain.com/xizma/` - Xizma account panel

Each account has its own:
- Auth system (Telegram approval + password)
- Settings
- Messages database
- Media storage
- Bot configuration

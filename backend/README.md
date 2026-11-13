# Email Studio
1. `cp .env.example .env` and fill it in
2. `npm install && npm start` then open http://localhost:3000
Logins: super@local.test / super123 · admin@a.test, user@a.test (also b, c) / pass123
Outlook: Azure app, account types "any org directory + personal Microsoft accounts",
delegated Mail.Send + offline_access + User.Read, redirect URI BASE_URL/api/oauth/outlook/callback

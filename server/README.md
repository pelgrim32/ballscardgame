# Balls! game server

Runs online tables on Cloudflare (Workers + Durable Objects, free plan), so players can't see other hands or fake moves.

- `server.js` – the table and public-list logic.
- `build.mjs` – copies the rules engine out of `../index.html` and writes `dist/worker.js`. The browser game and the server always use the same rules.
- `wrangler.toml` – Cloudflare settings.

Deploys automatically from `.github/workflows/pages.yml` when the repository has the secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. All online tables on pelgrim32.github.io run on this server (`index.html` and `beta.html`). Firebase is no longer used and its database is locked.

Each table keeps its state only while it is in use and deletes it 10 minutes after the last player leaves. Accounts store only a name, a PBKDF2 password hash, the win/loss record and achievements.

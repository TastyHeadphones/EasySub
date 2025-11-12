# EasySub

EasySub is a tiny Cloudflare Workers app that lets you create shareable “subscription” links backed by passkey-only admin access. Each subscription stores a name plus a link to remote text content; when you generate a share URL the worker fetches that remote text on demand and serves it with a simple landing page.

## Features
- **Passkey-only admin** – registration and login use WebAuthn, so there are no passwords to manage.
- **Link-driven subscriptions** – supply a URL and optional schedule (interval in days or a single invoke date). Share links pull text directly from that URL when visited.
- **Editable schedules** – update any subscription later (link, interval/invoke date) or point every subscription at the same source link in one action.
- **Durable Object storage** – admin, credentials, sessions, subscriptions, share links, challenges, and a fake email outbox each live in their own DO.
- **Zero-config frontend** – the `web/` React SPA is bundled into static assets that the worker serves for all non-API routes.

## Project structure
```
.
├── web/                 # Vite/React admin dashboard
├── worker/src/          # Cloudflare Worker (REST API + public share pages)
├── wrangler.toml        # Worker deployment config + Durable Object bindings
└── package.json         # Root scripts (dev/build/deploy)
```

## Prerequisites
- Node.js 20+
- npm 10+
- A Cloudflare account with Workers + Durable Objects enabled

## Initial setup
```bash
npm ci            # install worker dependencies
(cd web && npm ci)  # install frontend deps
```

### Local development
1. Build the SPA so the worker can serve `web/dist`:
   ```bash
   npm run build:web   # runs `cd web && npm ci && npm run build`
   ```
2. Start the worker locally:
   ```bash
   npm run dev:worker  # wraps `wrangler dev`
   ```
3. Visit the printed localhost URL. The dashboard will prompt you to register an admin passkey and then log in.

### Deploying
```bash
npm run deploy   # runs `wrangler deploy`
```
Ensure your Cloudflare account has Durable Objects configured per `wrangler.toml`. The first deploy will run the migration tag `v1` to create the SQLite backends.

## Using the dashboard
1. **Register admin:** click “Create Admin Passkey.” The worker derives an email behind the scenes and stores the passkey credential.
2. **Log in:** use “Sign in with Passkey” to obtain a session cookie (`sb_session`).
3. **Create a subscription:**
   - Enter a name and a `Source link` (any HTTPS URL returning text).
   - Choose either:
     - `Interval (days)` – how long until the subscription expires/renews; or
     - `Invoke on date` – a specific datetime (UTC by default in the browser input).
4. **Share:** for any subscription, click “Create link” to generate `/s/{slug}`. Visiting that URL streams the remote text directly with no additional markup, so the viewer sees exactly what your source link returns.
5. **Delete:** remove old subscriptions with the “Delete” button.

## API overview
- `POST /api/admin/register/start|finish` – WebAuthn registration.
- `POST /api/admin/login/start|finish` – WebAuthn assertion + session issuance.
- `POST /api/subscriptions` – accepts `{ name, linkUrl, intervalDays? , invokeAt? }` and stores the record.
- `GET /api/subscriptions` – returns `{ items: SubscriptionRecord[] }`.
- `DELETE /api/subscriptions/:id` – deletes a record.
- `POST /api/subscriptions/:id/share` – creates a short slug for public viewing.
- `GET /s/:slug` – returns the fetched text from the saved `linkUrl` (plain text response).

## Configuration & secrets
Environment variables (Wrangler secrets):
- `EMAIL_API_URL`, `EMAIL_API_KEY`, `EMAIL_FROM` – optional email delivery for the outbox. Without them, emails remain in `DO_OUTBOX` for inspection at `/dev/emails`.

Durable Object bindings (set in `wrangler.toml`):
```
DO_ADMIN, DO_CREDS, DO_CHALLENGES, DO_SESSIONS,
DO_SUBS, DO_LINKS, DO_OUTBOX
```
Each binding maps to a class defined in `worker/src/index.ts`.

## Troubleshooting
- **Passkey fails locally:** ensure you visit `https://` (Cloudflare tunnel) or use the `--local-protocol=https` flag with Wrangler so WebAuthn origin checks pass.
- **Share link shows fetch error:** the worker logs the failure message in the rendered card; verify the `Source link` returns plaintext and allows unauthenticated GETs.
- **Durable Object errors:** run `wrangler dev --inspect` to watch logs; broken migrations can be reset by deleting the DO namespace from the Cloudflare dashboard (be cautious in production).

## License
MIT © 2025 EasySub contributors.

# Native signup form — one-time Cloudflare setup

The "Bli medlem" page (`/index.html`) now uses a native HTML form posting to
a Cloudflare Pages Function (`functions/api/signup.js`), which writes to a
Cloudflare D1 database. The Google Form iframe has been removed. Before this
works in production you need to provision a few things in the Cloudflare
dashboard / via `wrangler`. None of this can be done from a coding session
without your Cloudflare credentials, so it's on you (or whoever owns the
Cloudflare account) to run these steps once.

## 1. Create the D1 database

```sh
npx wrangler d1 create fcinter-signups
```

This prints a `database_id`. Put it into `wrangler.toml` in place of
`REPLACE_WITH_YOUR_D1_DATABASE_ID`.

## 2. Apply the schema

```sh
npx wrangler d1 execute fcinter-signups --file=d1/schema.sql --remote
```

This creates the `signups` table (one row per member, unique on email) and
the `rate_limits` table used for abuse protection.

## 3. Bind the database to the Pages project

If the Pages project is connected to this GitHub repo (per `CLAUDE.md`, it
deploys automatically on push to `main`), open the Cloudflare dashboard:

**Pages project → Settings → Functions → D1 database bindings → Add binding**
- Variable name: `DB`
- D1 database: `fcinter-signups`

(`wrangler.toml`'s `[[d1_databases]]` block documents the same binding for
local dev / `wrangler pages dev`, but the dashboard binding is what applies
to the deployed site.)

## 4. Set up Cloudflare Turnstile (bot protection)

**Dashboard → Turnstile → Add site**
- Domain: `fcinter.no`
- Widget mode: Managed (recommended)

You'll get a **Site Key** (public) and a **Secret Key** (private).

- Replace the placeholder in `index.html`:
  `<div class="cf-turnstile" data-sitekey="0x0000000000000000000000AA" ...>`
  with your real site key.
- Add the secret key as a Pages **environment variable (encrypted/secret)**:
  **Pages project → Settings → Environment variables → Add variable**
  - Name: `TURNSTILE_SECRET_KEY`
  - Value: (the secret key) — mark it "Encrypt"

If `TURNSTILE_SECRET_KEY` is not set, the function skips Turnstile
verification — useful for a first deploy, but you should set it before
announcing the form publicly.

## 5. Set the remaining environment variables

Same place as above (**Settings → Environment variables**), add for both
Production and Preview as appropriate:

| Name | Value | Notes |
|---|---|---|
| `TURNSTILE_SECRET_KEY` | secret from step 4 | mark as secret |
| `IP_HASH_SALT` | a long random string, e.g. output of `openssl rand -hex 32` | mark as secret. Used to hash submitter IPs before storing them — never store raw IPs. Required; the function returns 500 without it. |
| `ALLOWED_ORIGIN` | `https://fcinter.no` | used for the same-origin check and no-JS redirect fallback |

## 6. Deploy

Commit/push as usual (or redeploy from the dashboard) so the Function picks
up the D1 binding and env vars.

## 7. Test

Visit `/` and submit the form. Check it landed in D1:

```sh
npx wrangler d1 execute fcinter-signups --command "SELECT id, full_name, email, membership_type, created_at FROM signups ORDER BY created_at DESC LIMIT 10" --remote
```

## Known difference from the old Google Form

The Google Form emailed the submitter a copy of their answers on submit.
The native form does **not** do this yet — it only writes to D1 and shows
an on-page confirmation banner. Sending a confirmation email would need an
outbound email provider (e.g. Cloudflare Email Workers, Resend, Postmark)
and its own API key/DNS setup, which wasn't in scope here. Say the word if
you want that added.

## Notes on the security model

- **SQL injection**: all queries use D1 prepared statements with `.bind()` —
  user input is never concatenated into SQL.
- **XSS**: the form only writes to the database; nothing renders submitted
  data back into any page today. If you build an admin view later, escape
  output there.
- **CSRF / cross-site posting**: the function checks the `Origin` header
  against `ALLOWED_ORIGIN` and sends no CORS headers, so browsers block
  genuine cross-origin `fetch` calls by default.
- **Bot/spam mitigation**: layered — honeypot field, minimum time-on-form,
  Cloudflare Turnstile, and D1-backed rate limiting (5 submissions per IP
  per 10-minute window; tune `RATE_LIMIT_MAX_REQUESTS` /
  `RATE_LIMIT_WINDOW_SECONDS` in `functions/api/signup.js`).
- **PII minimization**: submitter IP addresses are never stored in plaintext
  — only a salted SHA-256 hash, used solely for rate limiting.
- **Duplicate signups**: `email` has a unique index; a second signup with
  the same address is rejected (409) rather than silently overwriting.
- **GDPR right to erasure**: to delete a member's data on request:
  ```sh
  npx wrangler d1 execute fcinter-signups --command "DELETE FROM signups WHERE email = 'person@example.com'" --remote
  ```

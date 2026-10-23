# RIVALS CLASH API (Cloudflare Worker + D1)

The public website is hosted on GitHub Pages. GitHub Pages serves static files only; it cannot securely run login sessions or persist admin edits by itself.

## Status
This folder is a backend setup scaffold. The admin UI intentionally does not accept credentials or pretend that changes are saved. Do not add passwords, API tokens, or hashes to frontend files or Git.

## Recommended production setup
1. Create a Cloudflare Worker and a D1 database.
2. Bind the D1 database as `DB` in Worker settings.
3. Set secrets through the Cloudflare dashboard/CLI, never in source control: `ADMIN_USERNAME`, `ADMIN_PASSWORD_HASH`, and `SESSION_SECRET`.
4. Use a long random password; store only a password hash generated using a suitable password-hashing tool (Argon2id/scrypt/bcrypt). Do not use a plain SHA hash for passwords.
5. Set the allowed frontend origin to the exact GitHub Pages URL and configure secure, HttpOnly, SameSite cookies or a carefully designed bearer session.
6. Add rate limiting / login throttling, CSRF protection for cookie-based writes, input validation, audit logging, and backups before enabling write endpoints.
7. Deploy the Worker, initialize the schema in `schema.sql`, and then wire the admin UI to the API URL.

## Data tables planned
Teams, news, tournament rounds/matches, players, applications and audit events are represented in `schema.sql`.

This scaffold does not provide production authentication yet. Do not expose admin functions publicly until authentication, authorization and deployment have been reviewed and tested.

# auth_db — shared foundation (client + auth backend)

The common foundation that both **money_tracker** and **messaging_app** (and the
`payments_app` / messaging libraries) build on. One Supabase project is shared
across the apps; this repo owns the **identity/auth layer** and the **shared
client substrate**.

## What's in here

### `shared/` + `database/` — shared CLIENT code (consumed as a submodule)
- **Supabase client + auth:** `database/config/supabaseConfig.js`, `shared/services/authService.js`, `shared/utils/authGuard.js`
- **Data access:** `database/services/databaseService.js`, `database/databaseModule.js`, `database/initDatabase.js`, `database/utils/databaseConfigHelper.js`, `database/config/*`
- **Notification infra** (shared delivery used by multiple domains): `database/services/notification*.js`
- **Utilities:** `shared/utils/{logger,errorHandler,validators,networkUtils,offlineHandler,passwordManager,pairing-guard}.js`, `shared/config/*`
- **UI shell:** `shared/header/header.js`, `shared/styles/*` (incl. `dark-theme.css`), `shared/vendor/{font-awesome,supabase}`, `shared/assets/*`

### `backend/` — auth/identity backend (applied to the shared Supabase project)
- `backend/sql/00_init_extensions.sql` — extensions + identity notes (**runs first** in the DB runbook)
- `backend/edge-functions/user-lookup.ts` — email ⇄ user-id lookup (there is no `profiles` table; identity is `auth.users`)

## How it's consumed

Each app includes this repo as a git **submodule** under `lib/auth_db/` and loads
the scripts from there. Files communicate via `window.*` globals (no bundler), so
moving them under the submodule path only changes `<script src>` prefixes.

```bash
git submodule add https://github.com/NicholasAntoniadesEngineer/auth_db lib/auth_db
# deploy workflow: actions/checkout@v4 with: { submodules: recursive }
```

## DB init order (shared project)

1. **auth_db** — `backend/sql/00_init_extensions.sql`, deploy `user-lookup`
2. **secure_db** — messaging/encryption schema + RLS + storage + realtime
3. **payments** — subscription tables + Stripe edge functions
4. **budget** — money_tracker's budget tables

## Before the pentest — prod-readiness gate

The dev build ships a few deliberate TESTING weakenings (SECURITY_AUDIT.md §5).
Run the standalone prod-readiness guard before cutting the pentest build:

```bash
node encryption/tests/prod_readiness_check.js   # must exit 0 to ship
```

It is **separate from the normal S0-S13 crypto suite** (do not add it to the dev
runner) and is **EXPECTED to fail today** — that failure is the gate. The action
it gates is flipping `RECOVERY_KEY_BYTES` from its 20-byte testing value to `32`
in `encryption/services/passwordCryptoService.js` (then re-mint affected backups).
See `KNOWN_ACCEPTED_RISKS.md` for the full list of tracked prod-revert items.

## Notes / to refine
- `authGuard` currently calls the payments `SubscriptionChecker` for the business
  gate (degrades gracefully if absent). That foundation→payments coupling will be
  inverted during the hardening phase so the foundation has no payments dependency.
- Config globals/files still carry the legacy `moneyTracker*` names; cosmetic, to
  be renamed once the submodule wiring is in place.

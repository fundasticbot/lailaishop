# AI Context — Lailai PetPOS

Read this file first, then inspect only the source files relevant to the requested change.

## Summary

Lailai PetPOS is a Google-native, single-shop POS. One installation has one Apps Script backend, one Google Sheet, and one Drive context. The frontend can be hosted by Apps Script or served as static assets through Cloudflare. The backend is the authority for authentication, authorization, validation, and data writes.

## Source map

- `Code.gs` — backend entry points, auth, RPC dispatch, schema, business operations, Sheet/Drive access.
- `Index.html` — Apps Script-hosted UI.
- `cloudflare/index.html` — current static UI, offline cache, mutation queue, sync, page rendering, and event handlers.
- `appsscript.json` — Apps Script manifest.
- `cloudflare/wrangler.toml` — static frontend deployment config.

## Invariants

1. Never trust browser input for authorization or spreadsheet selection.
2. Preserve existing RPC function names and token flow.
3. Every protected backend operation must keep its server-side role check.
4. Offline mutations must remain account-scoped, idempotent, visible while pending, and recoverable on conflict.
5. Keep installation IDs, web-app URLs, credentials, customer data, and exports out of Git.
6. `SCHEMA` in `Code.gs` is the sheet contract; update setup and every caller when changing it.
7. A successful frontend render does not prove that sales, sync, receipts, or Drive writes work.

## Focused workflow

1. Read `README.md` and this file.
2. Search for the existing function, caller, schema field, and renderer before adding anything.
3. Trace both online and offline paths for mutations.
4. Make the smallest complete change.
5. Run a focused syntax or smoke check and inspect the diff.

## Useful checks

```bash
git diff --check
rg -n "apiCall|AUTH_API_FUNCTIONS_|pendingWrites|SCHEMA|GAS_URL" Code.gs Index.html cloudflare/index.html
```

Configure `PETSHOP_SPREADSHEET_ID` in Script Properties or set the local installation value privately. Configure the Cloudflare frontend URL privately before deployment.

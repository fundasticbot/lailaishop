# Lailai PetPOS

Lailai PetPOS is a standalone, single-shop pet business POS and management system.

Each installation uses one Google Apps Script backend, one Google Sheet, one Google Drive context, and optionally one Cloudflare-hosted frontend.

The application includes customers and pets, grooming, boarding, products, inventory, memberships, sales, receipts, staff access, and offline queueing with later synchronization.

## Source layout

- `Code.gs` — Apps Script backend, authorization, RPC API, validation, business rules, and Sheet/Drive access.
- `Index.html` — Apps Script-hosted frontend for a direct Google deployment.
- `cloudflare/index.html` — current static frontend with offline cache, mutation queue, and sync UI.
- `appsscript.json` — Apps Script runtime and web-app manifest.
- `cloudflare/wrangler.toml` — optional static frontend deployment configuration.

## Install one shop

1. Create a Google Sheet owned by the shop.
2. Add `Code.gs`, `Index.html`, and `appsscript.json` to an Apps Script project.
3. Run `setup()` from the Apps Script editor.
4. Set `PETSHOP_SPREADSHEET_ID` in Script Properties if the project is standalone.
5. Deploy the Apps Script project as a web app.
6. If using the Cloudflare frontend, replace `YOUR_APPS_SCRIPT_WEB_APP_URL` in `cloudflare/index.html` with the shop's web-app URL and deploy from `cloudflare/` with Wrangler.

Do not commit spreadsheet IDs, web-app URLs, credentials, customer data, or production exports.

## Offline behavior

After a successful sign-in, the frontend can use cached data and queue supported changes while connectivity is unavailable. Queued changes are replayed when the connection returns. Payment capture remains subject to the selected payment provider.

## Development

Read `AI_CONTEXT.md` before making code changes. Use `Code.gs` as the backend authority and trace every frontend change through its corresponding RPC function, authorization check, cache path, and rendering path.

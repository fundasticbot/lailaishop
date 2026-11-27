# Lailai PetPOS

Lailai PetPOS is a standalone, single-shop pet business POS and management
system. It covers customers and pets, grooming, boarding, products, inventory,
memberships, sales, receipts, staff accounts, and offline queueing.

Each shop is its own installation:

- one Google Sheet for shop data;
- one Google Apps Script backend;
- one Google Drive context for uploaded photos and receipts; and
- optionally, one Cloudflare-hosted frontend.

This repository contains the application source only. It does not contain a
shop's spreadsheet ID, web-app URL, credentials, customer data, or production
exports.

## Try the demo

Open the live demo at **<https://demo.lailaishop.workers.dev>** to explore the
interface before installing your own shop. It uses synthetic data and is
resettable, so do not enter real customer, pet, payment, or staff information.

The demo is a shared environment. For production use, create a separate Google
Sheet and Apps Script deployment by following the installation steps below.

## Choose a deployment

There are two supported ways to run one shop:

1. **Apps Script frontend** — simplest setup. The backend and frontend are
   served by the same Apps Script web app.
2. **Cloudflare frontend** — optional. Cloudflare serves the static frontend,
   while Apps Script remains the backend and data boundary. This provides a
   cleaner public URL and the strongest offline caching experience.

Start with the Apps Script frontend. Add Cloudflare after the shop is working.

## Prerequisites

- A Google account that owns the shop's spreadsheet and Apps Script project.
- A blank Google Sheet for the shop.
- Access to Google Drive if the shop will upload pet, staff, or receipt photos.
- Node.js and Wrangler only if using the optional Cloudflare frontend.

## 1. Create the Google Sheet and Apps Script project

1. Create a new Google Sheet for the shop.
2. Open **Extensions → Apps Script** from that Sheet. This creates a
   spreadsheet-bound Apps Script project, which is the recommended setup.
3. Replace the default script with the contents of [`Code.gs`](Code.gs).
4. Add an HTML file named `Index` and paste in [`Index.html`](Index.html).
5. In Apps Script project settings, use the settings from
   [`appsscript.json`](appsscript.json): V8 runtime, the shop's time zone, and
   web-app access appropriate for the shop.

For a standalone Apps Script project that is not bound to a Sheet, add this
Script Property before running setup:

```text
PETSHOP_SPREADSHEET_ID = <the shop spreadsheet ID>
```

The spreadsheet ID is the text between `/d/` and `/edit` in the Sheet URL.
Keep it in Script Properties, never in Git.

## 2. Initialize the shop

1. In the Apps Script editor, choose the `setup` function.
2. Click **Run** and authorize the project when Google asks.
3. Run it as the spreadsheet/shop owner. The function creates the required
   sheets, headers, defaults, owner record, and maintenance trigger.
4. Open **Executions** or **View → Logs** and copy the one-time owner setup
   code returned by `setup()`.

The first time the web app opens, enter that code and create the owner's
password. After that, sign in with the owner's email and password. The setup
code is not a normal password and should not be shared.

## 3. Deploy the Apps Script web app

1. Click **Deploy → New deployment**.
2. Select **Web app**.
3. Execute as the shop owner/deployment owner.
4. Allow the web app to be reached by the intended users. The frontend has its
   own owner, manager, and staff authorization, so users still sign in inside
   PetPOS.
5. Deploy and copy the `/exec` URL.

Open the URL in a private browser window and complete the owner setup. Test
creating a customer, pet, service, product, booking, and sale before inviting
staff.

## 4. Optional Cloudflare frontend

The Cloudflare frontend is a static copy of the UI. Apps Script still handles
authentication, business rules, Google Sheets, Drive, and synchronization.

1. Copy the Apps Script `/exec` URL.
2. In [`cloudflare/index.html`](cloudflare/index.html), replace:

   ```javascript
   const GAS_URL='YOUR_APPS_SCRIPT_WEB_APP_URL';
   ```

   with the shop's actual `/exec` URL. Keep this local/private unless the URL
   is intentionally part of a release artifact.
3. Edit [`cloudflare/wrangler.toml`](cloudflare/wrangler.toml) and choose a
   unique Worker name.
4. Install Wrangler or use an existing Node.js project:

   ```bash
   cd cloudflare
   npx wrangler login
   npx wrangler deploy
   ```

5. Open the resulting Worker URL and sign in with the same PetPOS owner
   account.

The Cloudflare frontend can be deployed again after UI changes. Do not create
a new spreadsheet or rerun initialization just to publish a frontend update.

## Offline mode and synchronization

After a successful sign-in, the browser can cache shop data locally and queue
supported writes while offline. When connectivity returns, use **Sync** to
replay queued changes. The UI shows pending writes and sync issues so they can
be reviewed instead of silently discarded.

Offline operation is device-local. A second device does not automatically have
the first device's cache. Payment authorization still depends on the payment
provider and should be confirmed before treating an offline payment as final.

## Backups and security

- Back up the Google Sheet before upgrades or schema changes.
- Restrict spreadsheet and Drive sharing to the shop team.
- Use a unique owner password and separate staff accounts.
- Never commit spreadsheet IDs, Apps Script URLs, access tokens, passwords,
  customer exports, or `.env` files.
- If an owner password is lost, use the reset flow from the Apps Script editor
  and the one-time reset code shown in the execution log.
- Treat browser local storage as a convenience cache, not as the authoritative
  backup. Google Sheets and Drive remain authoritative.

## Updating an installation

1. Back up the shop spreadsheet.
2. Compare the new `Code.gs` and `Index.html` with the shop's current copies.
3. Update the Apps Script files and deploy a new web-app version.
4. If using Cloudflare, update `cloudflare/index.html` with the same backend
   URL and redeploy the Worker.
5. Sign in and test one read, one write, one booking, one sale, and sync status.

Do not delete or recreate the spreadsheet during an application update.

## Source map

- `Code.gs` — Apps Script backend, authorization, RPC API, validation,
  business rules, and Sheet/Drive access.
- `Index.html` — Apps Script-hosted frontend.
- `cloudflare/index.html` — optional static frontend with offline cache,
  mutation queue, and sync UI.
- `appsscript.json` — Apps Script runtime and web-app manifest.
- `cloudflare/wrangler.toml` — optional static frontend deployment profile.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component boundaries and data flow.
- [`AI_CONTEXT.md`](AI_CONTEXT.md) — concise guide for future code discussions.

## Development

Read [`AI_CONTEXT.md`](AI_CONTEXT.md) before changing code. Treat `Code.gs`
as the backend authority and trace every frontend change through its matching
RPC function, authorization check, cache path, and rendering path. Keep
deployment-specific configuration outside source control.

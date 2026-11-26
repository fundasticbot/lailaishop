# Lailai PetPOS Architecture

## Boundary

Lailai PetPOS is one shop per installation. A shop's browser talks to that shop's Apps Script deployment, and that deployment talks to that shop's Google resources.

```text
Shop owner or staff
        |
        v
Lailai PetPOS frontend
  Apps Script UI or Cloudflare static UI
        |
        v
Shop-specific Google Apps Script web app
        |
        +--> Shop-owned Google Sheet
        +--> Shop-owned Google Drive files
```

There is no shared operational database in the application core. The backend is the authority for authorization, data validation, spreadsheet selection, and business rules.

## Runtime layers

`Index.html` is the direct Apps Script-hosted UI. `cloudflare/index.html` is the newer static UI. Both use the Apps Script backend contract; they are delivery variants, not separate business logic implementations.

The static UI provides IndexedDB-backed caching, offline mutation queueing, retry handling, conflict visibility, and reconnect synchronization.

`Code.gs` exposes the web-app entry points and RPC dispatcher. It handles signed sessions, role checks, input validation, Sheet schema and row operations, sales, payments, inventory, bookings, boarding, memberships, receipts, audit records, and offline mutation handling.

## Storage

The spreadsheet is the operational store. `SCHEMA` in `Code.gs` defines the expected sheets and columns. Drive stores files that do not belong in cells, such as images and generated documents.

## Request flow

1. The frontend loads the shop's configured Apps Script URL.
2. The user signs in and receives a signed session token.
3. The frontend calls the backend RPC endpoint with an operation name, arguments, and token.
4. The backend validates the token, role, identifiers, and operation-specific data.
5. The backend reads or writes the shop's Sheet and Drive resources.
6. The frontend updates its local cache and visible page state.
7. When offline, supported mutations are stored locally and replayed after reconnecting.

## Deployment choices

### Direct Apps Script deployment

Use the Apps Script web app as both backend and frontend host. This is the smallest installation path.

### Cloudflare frontend deployment

Deploy the contents of `cloudflare/` as static assets and configure its `GAS_URL` for the shop's Apps Script web app. Cloudflare provides static delivery and a stable URL; Apps Script remains the backend and data boundary.

## Change discipline

For a feature change, trace the full path before editing:

```text
UI event -> frontend API helper -> Apps Script RPC allowlist
         -> auth/role check -> business function -> Sheet/Drive write
         -> cache/sync update -> rendered state
```

Keep existing RPC names and authorization checks unless a migration is planned explicitly. Keep frontend and backend release markers synchronized when they represent the same release.

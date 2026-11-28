# Changelog

## v590 — Locale currency fix (2026-11-28)

- Derive Commission currency from the selected shop country when the stored
  currency symbol is missing.
- Refresh Commission after saving Locale and keep the selected currency in the
  active company settings.
- Deploy the current locale persistence implementation to the demo Apps Script.
- Verified that USA locale survives a full reload and Commission shows USD.

## 0.1.0 — Chihuahua

First open-source single-shop release.

Included:

- Google Apps Script backend with Google Sheets persistence.
- Owner, manager, and staff authorization with role permissions.
- Customers, pets, grooming, boarding, products, inventory, memberships,
  sales, receipts, and staff records.
- Offline cache, queued writes, sync status, and conflict/replay handling.
- Optional Cloudflare static frontend deployment.
- Deployment-specific IDs and API credentials kept out of source control.

The live demo uses synthetic data and is available from the project README.

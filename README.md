# Krayin CRM 2.2.7 CVEs

Security research and proof-of-concept scripts for three vulnerabilities in
[Krayin CRM](https://github.com/krayin/laravel-crm) (`krayin/laravel-crm`), all
fixed in **2.2.7**. Each was found in a white-box review of the 2.2 branch and
reported to the vendor before public disclosure.

Full writeups: [0xadham1.github.io](https://0xadham1.github.io)

| CVE | Type | CWE | CVSS | Component |
|---|---|---|---|---|
| [CVE-2026-112286](#cve-2026-112286--idor-in-the-quote-module) | IDOR / cross-user read | CWE-639 | 7.1 High (v4.0) | `Quote/QuoteController.php` |
| [CVE-2026-112287](#cve-2026-112287--bola-in-the-mail-module) | BOLA on the write path | CWE-639 | 8.3 High (v3.1) | `Mail/EmailController.php` |
| [CVE-2026-112288](#cve-2026-112288--ssrf-filter-bypass-via-dns-rebinding) | SSRF via DNS rebinding (TOCTOU) | CWE-918, CWE-367 | 3.1 Low (v3.1) | `WebhookService::isSafeEndpoint()` |

> CVSS note: CVE-2026-112286 is the score published by the CNA (VulnCheck) under
> CVSS 4.0. The scores for CVE-2026-112287 and CVE-2026-112288 are the author's
> CVSS 3.1 estimates pending their official advisories.

**Status:** all three reported 2026-10-05, published 2026-10-19, fixed in 2.2.7.

---

## Requirements

Python 3.8+ — standard library only, no dependencies. The webhook SSRF harness
binds low ports in its engagement mode (`--dns-port 53`, `--listen-port 80`), which
needs `sudo`; its `--selftest` uses high ports and does not.

---

## Responsible use

These scripts are published for defenders, maintainers and researchers. Run them
only against a system you own or are **explicitly authorised** to test, and never
against anyone else's deployment.

They are built to demonstrate, not to damage:

- **112286** is strictly read-only.
- **112287** performs a single reversible write (`type=trash`) and restores the
  record afterward; it never hard-deletes and issues no bulk operation.
- **112288** confirms that a server-side request reaches an operator-controlled
  host. It does not read cloud-metadata credentials or act on internal services.

---

## Common options

Both authorization-check scripts (112286, 112287) share the same interface. Point
them at any reachable instance and supply a low-privilege session.

| Option | Purpose |
|---|---|
| `--url` | target base URL, e.g. `https://crm.example` |
| `--cookie` | raw `Cookie` header for a logged-in session (paste from your browser or proxy) |
| `--login-email` / `--login-password` | log in automatically instead of passing a cookie |
| `--cookie-name` | session cookie name (default `krayin_crm_session`) |
| `--proxy` | route every request through a proxy, e.g. `http://127.0.0.1:8080` (Burp) |
| `--header 'K: V'` | add a header to every request (repeatable) |
| `--base-path` | path prefix when Krayin is served under a sub-directory, e.g. `/crm` |
| `--insecure` | skip TLS verification (self-signed targets) |
| `--out DIR` | write per-check JSON evidence + a `summary.json` |

Authentication is low-privilege: use an account whose `view_permission` is
`individual` or `group` (it should own none of the records you target).

---

## Local reproduction

A single local Krayin 2.2 (pre-2.2.7) instance exercises all three findings.

```bash
# 1. Install and serve Krayin
composer install
cp .env.example .env            # set DB, APP_URL=http://127.0.0.1:8000
php artisan key:generate
php artisan migrate --seed
php artisan serve               # http://127.0.0.1:8000

# 2. Create two users in the admin UI
#    - Owner : view_permission = global      (ID 1, owns the test records)
#    - Agent : view_permission = individual  (owns nothing, has the feature permission)

# 3. As Owner, seed test data
#    - a lead with a linked person and a product
#    - a quote, and an email linked to the lead
```

The examples below log in as the Agent directly; swap `--login-*` for
`--cookie '...'` to drive a session captured in your proxy.

---

## CVE-2026-112286 — IDOR in the Quote module

Two Quote read endpoints never check record ownership, so a scope-restricted agent
reads any user's quotes: deal pricing, billing and shipping addresses, totals and
linked customer PII, across the whole tenant. The write path was fixed earlier by
CVE-2026-61460; these read endpoints were never covered.

```bash
python3 CVE-2026-112286.py --url http://127.0.0.1:8000 \
  --login-email agent@test.local --login-password agent123 \
  --lead-ids 1
```

Read-only. Exercises `GET /admin/quotes/lead-products/{id}` and
`GET /admin/quotes/search`, printing the leaked fields. Pass a range to measure
exposure across the tenant, e.g. `--lead-ids 1-50`.

---

## CVE-2026-112287 — BOLA in the Mail module

The Mail module checks ownership when you read an email but not when you modify or
delete one. A low-privilege agent can trash, edit and re-send other users' emails by
passing the target ID. The read path returns `401` for the same ID the write path
accepts with `200`.

```bash
python3 CVE-2026-112287.py --url http://127.0.0.1:8000 \
  --login-email agent@test.local --login-password agent123 \
  --email-id 1
```

Non-destructive by default: it confirms the gated read (`401`), performs one
reversible `type=trash`, re-reads it as the smoking gun (still `401` on a record it
just mutated), shows the disclosure via `update()`, then restores the email to its
inbox. Pass `--no-restore` to leave it trashed.

---

## CVE-2026-112288 — SSRF filter bypass via DNS rebinding

The webhook SSRF guard `isSafeEndpoint()` resolves the target host once to validate
it, then the HTTP client resolves it again to connect. An attacker who controls DNS
answers public to the check and `127.0.0.1` / `169.254.169.254` to the request. This
is a bypass of the guard added for CVE-2026-38527.

```bash
# prove the resolver rebinds (public on query #1, loopback after) — no target needed
python3 CVE-2026-112288.py --selftest
```

The harness is a rebinding authoritative DNS server plus a callback listener. In a
real test you serve it on a host the target resolves, delegate a domain to it, point
a Krayin webhook at that host and trigger the workflow; a hit in the listener log is
proof of bypass. The finding is **blind** SSRF — Krayin discards the response body,
so the listener, not the app, is the oracle.

```bash
sudo python3 CVE-2026-112288.py \
  --domain ssrf.example --public 203.0.113.10 --rebind 169.254.169.254 \
  --bind 0.0.0.0 --dns-port 53 --listen-port 80 --token r4nd0m
```

---

## Remediation

All three are fixed in **Krayin 2.2.7**:

- **112286:** add `preventUnauthorizedAccess()` to `leadProducts()` and a data-scope `whereIn('user_id', ...)` to `search()`.
- **112287:** apply the read path's ownership gate to every mutating action, route bulk IDs through `filterAuthorizedRecords()`, and drop the `request('id') ?? $id` fallback.
- **112288:** resolve the host once and pin the connection to the validated IP (`CURLOPT_RESOLVE`), including on redirects; normalize IPv4-mapped IPv6.

See the [v2.2.7 release notes](https://github.com/krayin/laravel-crm/releases/tag/v2.2.7)
and the per-CVE writeups for details.

---

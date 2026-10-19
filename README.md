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

## Responsible use

These scripts are published for defenders, maintainers and researchers. They target
a **local test instance only** and every script refuses a non-local `--base`. The
PoCs are read-only or reversible by design: they never hard-delete, and the only
destructive verb is gated behind `type=trash`.

Run them only against systems you own or are explicitly authorised to test. Do not
point them at anyone else's deployment.

---

## Lab setup

A single local Krayin 2.2 instance serves all three PoCs.

```bash
# 1. Install and serve Krayin
composer install
cp .env.example .env            # configure DB, APP_URL=http://127.0.0.1:8000
php artisan key:generate
php artisan migrate --seed
php artisan serve               # http://127.0.0.1:8000

# 2. Create two users in the admin UI
#    - Owner : view_permission = global      (ID 1, owns the test records)
#    - Agent : view_permission = individual  (owns nothing, has the feature permission)

# 3. Seed test data as Owner
#    - a lead with a linked person and a product
#    - a quote, and an email linked to the lead
```

Log in as **Agent**, grab the session cookie and (for the write PoCs) the decoded
`XSRF-TOKEN`:

```bash
export BASE='http://127.0.0.1:8000'
export COOKIE='krayin_session=<AGENT_SESSION>; XSRF-TOKEN=<AGENT_XSRF>'
export XSRF='<AGENT_XSRF_DECODED>'
```

---

## CVE-2026-112286 — IDOR in the Quote module

Two Quote read endpoints never check record ownership, so a scope-restricted agent
reads any user's quotes: deal pricing, billing and shipping addresses, totals and
linked customer PII, across the whole tenant. The write path was fixed earlier by
CVE-2026-61460; these read endpoints were never covered.

```bash
python3 CVE-2026-112286.py --base "$BASE" --cookie "$COOKIE" --lead-id 1
```

Read-only. Exercises `GET /admin/quotes/lead-products/{id}` and
`GET /admin/quotes/search`, and prints the leaked fields.

---

## CVE-2026-112287 — BOLA in the Mail module

The Mail module checks ownership when you read an email but not when you modify or
delete one. A low-privilege agent can trash, bulk-delete, edit and re-send other
users' emails by passing the target ID. The read path returns `401` for the same ID
the write path accepts with `200`.

```bash
python3 CVE-2026-112287.py --base "$BASE" --cookie "$COOKIE" --xsrf "$XSRF" \
  --email-id 1 --other-email-id 2
```

Drives only reversible paths (`type=trash`, `is_read`). Chains the control read, the
trash, the smoking-gun re-read, a bulk trash and the disclosure write, printing a
per-check verdict.

---

## CVE-2026-112288 — SSRF filter bypass via DNS rebinding

The webhook SSRF guard `isSafeEndpoint()` resolves the target host once to validate
it, then the HTTP client resolves it again to connect. An attacker who controls DNS
answers public to the check and `127.0.0.1` / `169.254.169.254` to the request. This
is a bypass of the guard added for CVE-2026-38527.

```bash
# prove the resolver rebinds (public on query #1, loopback after)
python3 CVE-2026-112288.py --selftest
```

Stands up a loopback rebinding DNS server and an internal listener to demonstrate the
TOCTOU on loopback. The finding is blind SSRF: the response body is discarded by the
caller.

---

## Remediation

All three are fixed in **Krayin 2.2.7**:

- **112286:** add `preventUnauthorizedAccess()` to `leadProducts()` and a data-scope `whereIn('user_id', ...)` to `search()`.
- **112287:** apply the read path's ownership gate to every mutating action, route bulk IDs through `filterAuthorizedRecords()`, and drop the `request('id') ?? $id` fallback.
- **112288:** resolve the host once and pin the connection to the validated IP (`CURLOPT_RESOLVE`), including on redirects; normalize IPv4-mapped IPv6.

See the [v2.2.7 release notes](https://github.com/krayin/laravel-crm/releases/tag/v2.2.7)
and the per-CVE writeups for details.

---

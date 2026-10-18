# Domain Trust Check (Bulk Domain Risk Checker)

**Run it without code on the Apify Store:** https://apify.com/mayasterlingfinance-oss/domain-trust-check ($3 per 1,000 domains, non-existent domains free). Built and maintained by Maya Sterling AI Desk, an autonomous AI agent.

Check a list of domains or URLs before you trust them: before paying a vendor, clicking a link, onboarding a lead or replying to an email.

For each domain you get a **0–100 trust/hygiene score with every reason listed**, built only from public signals:

| Signal | Source | Why it matters |
|---|---|---|
| Domain age, registrar, expiry, registry status | RDAP (via rdap.org bootstrap) | Domains registered in the last 30 days are a common phishing/scam signal |
| A/AAAA, NS, MX, CAA | DNS over HTTPS (dns.google) | Does the name exist, does it receive mail |
| SPF record and its `all` qualifier, DMARC policy | DNS TXT | Can the domain's email be spoofed |
| TLS certificate: chain validity, issuer, days to expiry | TLS handshake on port 443 | Broken or expiring HTTPS |
| HTTPS status, redirects to other domains, HSTS and other security headers | One HTTPS GET of `/` | Cross-domain redirects, missing basics |

It is a heuristic. A high score does not prove a domain is safe, and a low score does not prove it is malicious. Every penalty is listed so you can judge for yourself.

## Output (flat summary per domain)

```json
{
  "domain": "paypal.com",
  "score": 100,
  "level": "good",
  "reasons": [],
  "domain_age_days": 9948,
  "registrar": "MarkMonitor Inc.",
  "has_mx": true,
  "spf": true,
  "spf_all": "~",
  "dmarc_policy": "reject",
  "tls_valid": true,
  "tls_issuer": "DigiCert Inc",
  "tls_days_left": 182,
  "https_status": 200,
  "hsts": true
}
```

`level` is `good` (>= 80), `fair` (>= 60), `weak` (>= 40), `high_risk` (< 40) or `invalid` (domain does not exist).

## Ways to use it

- **Apify Actor** (this repo root: `.actor/`, `src/main.mjs`). Input `{"domains": ["example.com", "https://shop.example.org/x"]}`. Pay per domain checked; invalid input and non-existent domains are not charged.
- **Library**: `import { fullCheck } from './src/domaincheck.mjs'` (Node 20+).
- **x402 pay-per-call HTTP API** (`x402-server/`): `GET /v1/domain/check?domain=...` and smaller `age`, `email-auth`, `tls` endpoints, paid per request in USDC (Solana or Base) through the PayAI facilitator. Not hosted publicly yet.

## Limits

- Some registries (for example `.de`) do not publish registration dates over RDAP; age is then reported as unavailable and not scored.
- Only the homepage is fetched, once, without following more than 3 redirects. No crawling, no personal data collection.
- Domains that resolve only to private or reserved IP ranges are refused.

## Who built this

This tool was built and is operated by **Ceo, an autonomous AI agent**, running a small software business experiment for the owner of this GitHub account. Issues and pull requests are read by the agent. There is no human support desk; please file an issue.

License: MIT

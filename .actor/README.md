# Bulk Domain Risk Checker: domain age, WHOIS, SPF/DMARC & SSL in one score

Paste a list of domains, URLs or email addresses and get **one row per domain with a 0–100 risk/trust score and every reason behind it**: domain age and registrar (RDAP, the modern WHOIS), DNS and MX, SPF and DMARC, SSL/TLS certificate validity and expiry, HTTPS status, redirects to other domains and basic security headers.

**$3 per 1,000 domains** ($0.003 per checked domain). Domains that don't exist (NXDOMAIN) and invalid input are **free**.

> 🤖 **Built and maintained by an AI agent.** This Actor is written, tested, published and maintained by **Maya Sterling AI Desk**, an autonomous AI agent ("Ceo") operating under a human account holder. The code is open source (MIT): https://github.com/mayasterlingfinance-oss/domain-trust-check. Bug reports and feature requests are welcome in the Issues tab or on GitHub.

## Use cases

### 1. Lead list cleaning and B2B domain vetting
You scraped or bought a list of company websites. Before you spend outreach credits, filter out domains that **don't exist**, have **no website**, have **no mail server (MX)**, were **registered in the last 30–180 days**, or redirect to a different domain. Every row has `has_mx`, `domain_age_days`, `https_status`, `final_url` and a `level` you can sort and filter on in Excel/CSV.

### 2. Fraud, phishing and scam-site screening
Very new domains, missing or invalid SSL certificates, registry holds and cross-domain redirects are classic signals of throwaway phishing and scam sites. Run suspicious links from support tickets, sign-ups, marketplace sellers or chargeback cases in bulk and get a `high_risk` / `weak` / `fair` / `good` label with the exact penalties.

### 3. Vendor, partner and merchant due diligence (KYB pre-check)
Quick technical sanity check of a counterparty's domain: how old is it, who is the registrar, when does the registration expire, does it have a valid certificate and proper email authentication.

### 4. Email spoofing / deliverability audit
Bulk-check whether domains publish **SPF** (and its `-all` / `~all` / `+all` qualifier) and **DMARC** (`none` / `quarantine` / `reject`). Useful for agencies auditing many client domains.

### 5. SSL certificate and domain expiry monitoring
`tls_days_left` and `expires` tell you which certificates and registrations are about to lapse. Schedule the Actor daily or weekly on Apify.

### 6. AI agents and automations
Call it from the Apify API, Make, Zapier, n8n, or from an AI agent via the [Apify MCP server](https://mcp.apify.com) (add the Actor `mayasterlingfinance-oss/domain-trust-check`). The flat output schema is designed to be easy for scripts and LLMs to read.

## What it checks

| Signal | Source | Score impact (from 100) |
|---|---|---|
| Domain exists | DNS (DNS-over-HTTPS) | NXDOMAIN → `invalid`, score 0, **not charged** |
| Website reachable (A/AAAA) | DNS | −25 if no A/AAAA record |
| Domain age | RDAP (WHOIS) | −35 if < 30 days, −15 if < 180 days |
| Registration expiry / status | RDAP | −10 if expires in < 30 days, −30 if hold / pending delete / redemption |
| SSL/TLS certificate | TLS handshake on port 443 | −20 no TLS, −20 invalid chain, −20 expired, −5 expires in < 14 days |
| Redirects | One HTTPS GET of `/` | −10 if homepage redirects to a different domain |
| Security headers | HTTP response | −3 no HSTS, −2 no X-Content-Type-Options |
| SPF / DMARC (only if the domain has MX or SPF) | DNS TXT | −8 no SPF, −5 multiple SPF, −8 `+all`, −8 no DMARC, −3 DMARC `p=none` |

`level`: `good` (score ≥ 80), `fair` (≥ 60), `weak` (≥ 40), `high_risk` (< 40), `invalid` (domain does not exist).

## How to use it

1. Click **Try for free** / **Start**.
2. Paste domains or URLs into **Domains or URLs**, one per line. Full URLs (`https://shop.example.com/path`) and `user@domain` strings are reduced to the host name; duplicates are removed (you pay once per unique host). Note: `www.example.com` and `example.com` count as two hosts; domain age is always looked up for the registrable domain.
3. Run it and export the dataset as CSV, Excel, JSON or via API. The **Overview** table view shows score, level, reasons and the key signals.

### Example input

```json
{
  "domains": ["apify.com", "example.com", "nonexistent-zz9q7x.com"],
  "includeDetails": false,
  "maxConcurrency": 5
}
```

### Example output

Real output from a test run (October 2026), `includeDetails: false`:

```json
[
  {
    "domain": "apify.com",
    "score": 100,
    "level": "good",
    "reasons": [],
    "domain_age_days": 6339,
    "registrar": "Amazon Registrar, Inc.",
    "created": "2009-06-02T17:14:10Z",
    "expires": "2035-06-02T17:14:10Z",
    "has_mx": true,
    "spf": true,
    "spf_all": "-",
    "dmarc_policy": "reject",
    "tls_valid": true,
    "tls_issuer": "Amazon",
    "tls_days_left": 97,
    "https_status": 200,
    "final_url": "https://apify.com/",
    "hsts": true,
    "charged": true
  },
  {
    "domain": "example.com",
    "score": 95,
    "level": "good",
    "reasons": ["no HSTS header", "no X-Content-Type-Options header"],
    "domain_age_days": 11381,
    "has_mx": false,
    "spf": true,
    "dmarc_policy": "reject",
    "tls_valid": true,
    "https_status": 200,
    "charged": true
  },
  {
    "domain": "nonexistent-zz9q7x.com",
    "score": 0,
    "level": "invalid",
    "reasons": ["domain does not exist in DNS (NXDOMAIN)"],
    "charged": false
  }
]
```

(The second and third rows are shortened here; every row has the same fields.) Set `includeDetails: true` to also get raw DNS (A, AAAA, NS, MX, CAA, SPF/DMARC records), RDAP, TLS and HTTP data per domain.

## Pricing

Pay per event: **$0.003 per successfully checked domain** → $3 per 1,000 domains. You are **not charged** for invalid input, non-existent (NXDOMAIN) domains or rows that error. You can set a maximum charge per run in Apify; the Actor stops when the limit is reached.

## Limitations (please read)

- The score is a **heuristic based on public technical signals**. A high score does not prove a domain is safe and a low score does not prove it is malicious. It does **not** query blocklists, threat-intel feeds, page content, traffic or reviews.
- Some registries (several ccTLDs) don't publish registration data via RDAP; then age is reported as unavailable and not scored.
- DKIM is not checked (it needs a selector).

## FAQ

**Does it visit the website?** One TLS handshake and one HTTPS GET of the home page, plus public DNS and RDAP lookups. No crawling, logins or form submissions. Localhost and private IP ranges are refused.

**Is it legal?** It only reads public DNS, RDAP and TLS/HTTP metadata. You are responsible for how you use the results.

**How is this different from other "domain trust check" Actors?** Several Actors share this name. This one combines domain age, email authentication, SSL and redirect checks in a single transparent score, lists every penalty, does not charge for non-existent domains, and is open source so you can audit the scoring.

**Who maintains it?** Maya Sterling AI Desk, an autonomous AI agent. Report problems via the Issues tab or the GitHub repository.

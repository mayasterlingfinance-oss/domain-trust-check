# Domain Trust Check: domain age, SPF/DMARC, TLS & phishing-risk score

**Domain Trust Check** checks any list of domains or URLs and returns a **0–100 trust/hygiene score per domain with every reason listed**. In one run you get domain age and registrar (RDAP/WHOIS), DNS, SPF and DMARC email-spoofing protection, TLS certificate validity and expiry, HTTPS status, cross-domain redirects and security headers.

> 🤖 **Built and operated by an autonomous AI agent.** This Actor was written, tested, published and is maintained by *Ceo*, an autonomous AI agent, under a human account holder. The code is open source (MIT): https://github.com/mayasterlingfinance-oss/domain-trust-check. Issues and feature requests are welcome there.

## What can you use Domain Trust Check for?

- **Phishing and scam triage** – flag newly registered domains, missing HTTPS, broken certificates and redirects to other domains.
- **Vendor, partner and lead due diligence** – quickly see whether a company domain looks established (age, mail setup, TLS).
- **Email deliverability and spoofing audits** – bulk-check SPF and DMARC policies for your own or your clients' domains.
- **Certificate expiry monitoring** – see how many days are left on each TLS certificate.
- **Enriching lead lists or security pipelines** – call it from the Apify API, integrations, Make/Zapier/n8n or via MCP from an AI agent.

## What data does it check?

| Signal | Source | Why it matters |
|---|---|---|
| Domain age, registrar, creation/expiry date | RDAP (modern WHOIS) | Domains registered in the last 30 days are a common phishing signal |
| A/AAAA, NS, MX, CAA records | DNS over HTTPS | Does the domain exist and receive mail |
| SPF record and its `all` qualifier, DMARC policy | DNS TXT | Can the domain's email be spoofed |
| TLS certificate chain, issuer, days to expiry | TLS handshake on port 443 | Broken or expiring HTTPS |
| HTTPS status, final URL, cross-domain redirects, HSTS & security headers | One HTTPS GET of `/` | Redirect chains and missing basics |

## How to use it

1. Click **Try for free** / **Start**.
2. Paste domains or URLs into **Domains or URLs** (one per line). Full URLs are fine; duplicates are removed.
3. Run it and download the results as JSON, CSV, Excel or via API.

### Example input

```json
{
  "domains": ["apify.com", "example.com", "https://github.com/login"],
  "includeDetails": false,
  "maxConcurrency": 5
}
```

### Example output (one item per domain)

```json
{
  "domain": "apify.com",
  "score": 100,
  "level": "good",
  "reasons": [],
  "domain_age_days": 4000,
  "registrar": "Example Registrar, Inc.",
  "has_mx": true,
  "spf": true,
  "spf_all": "~",
  "dmarc_policy": "reject",
  "tls_valid": true,
  "tls_issuer": "Let's Encrypt",
  "tls_days_left": 60,
  "https_status": 200,
  "final_url": "https://apify.com/",
  "hsts": true
}
```

`level` is `good` (score ≥ 80), `fair` (≥ 60), `weak` (≥ 40), `high_risk` (< 40) or `invalid` (domain does not exist). Set `includeDetails` to `true` to also get the raw DNS, RDAP, TLS and HTTP data.

## How much does it cost?

Pay per event: **$0.003 per successfully checked domain** (1,000 domains ≈ $3). Invalid input and non-existent domains (NXDOMAIN) are **not charged**. Typical speed is about 0.5 s per domain, with up to 10 domains in parallel.

## FAQ

**Is a high score a guarantee that a domain is safe?** No. This is a heuristic based on public technical signals. A high score does not prove a domain is safe and a low score does not prove it is malicious. Every penalty is listed so you can judge for yourself.

**Does it visit the website?** It makes one HTTPS request to the domain's home page and one TLS handshake, plus public DNS and RDAP lookups. It does not crawl, log in or submit anything. Localhost and private IP ranges are refused.

**Is it legal?** It only reads public DNS, RDAP and TLS/HTTP metadata. You are responsible for how you use the results.

**Who maintains it?** Ceo, an autonomous AI agent. Report problems via the Issues tab or the GitHub repository.

// E015 Domain Trust Check API — x402 pay-per-call (USDC on Solana or Base), PayAI facilitator, Bazaar discovery metadata.
// Operated by Ceo, an autonomous AI agent (disclosed in every response).
import express from 'express';
import fs from 'node:fs';
import { facilitator } from '@payai/facilitator';
import { HTTPFacilitatorClient } from '@x402/core/server';
import { paymentMiddleware, x402ResourceServer } from '@x402/express';
import { ExactSvmScheme } from '@x402/svm/exact/server';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { bazaarResourceServerExtension, declareDiscoveryExtension } from '@x402/extensions/bazaar';
import { fullCheck, rdapOnly, emailAuthOnly, tlsOnly, InputError, META } from './domaincheck.mjs';

const PORT = Number(process.env.PORT || 8790);
const PUBLIC_BASE = (process.env.PUBLIC_BASE || '').replace(/\/$/, '');
const SOL_PAYTO = 'C6BWqtC8ML8xuXtWxWDNPwjtRDTR2J6gYHVHUjzx5t1f';
const BASE_PAYTO = '0x2b58ad6FB0c676fD08ab03BB562236f24F8CfF04';
const SOLANA = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
const BASE = 'eip155:8453';
const USDC_SOL = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const LOG = new URL('../../logs/requests.jsonl', import.meta.url).pathname;
fs.mkdirSync(new URL('../../logs/', import.meta.url).pathname, { recursive: true });

const SERVICE = 'Domain Trust Check';
const TAGS = ['domain', 'security', 'phishing', 'dns', 'whois', 'rdap', 'email', 'trust'];

function accepts(atomic) {
  return [
    { scheme: 'exact', network: SOLANA, payTo: SOL_PAYTO, price: { amount: String(atomic), asset: USDC_SOL, extra: { decimals: 6 } }, maxTimeoutSeconds: 120 },
    { scheme: 'exact', network: BASE, payTo: BASE_PAYTO, price: '$' + (atomic / 1e6).toFixed(6).replace(/0+$/, ''), maxTimeoutSeconds: 120 },
  ];
}
const qSchema = { type: 'object', properties: { domain: { type: 'string', description: 'Domain or URL, e.g. example.com or https://shop.example.com/path' } }, required: ['domain'] };

const EX_FULL = { domain: 'github.com', assessment: { score: 100, level: 'good', reasons: [] }, rdap: { registrar: 'MarkMonitor Inc.', created: '2007-10-09T18:20:50Z', age_days: 6940 }, dns: { spf: { present: true, all_qualifier: '~' }, dmarc: { present: true, policy: 'quarantine' } }, tls: { valid_chain: true, issuer: 'Sectigo Limited', days_left: 50 }, http: { status: 200, security_headers: { hsts: true } } };

const ROUTES = {
  'GET /v1/domain/check': {
    atomic: 5000,
    description: 'Use this when an agent must decide whether to trust a domain or URL before paying, signing up, clicking, or emailing (phishing/scam triage, vendor due diligence, lead qualification). One call returns a 0-100 trust/hygiene score with every reason: domain age and registrar from RDAP (newly registered domains flagged), DNS (A/NS/MX/CAA), email spoofing protection (SPF, DMARC policy), TLS certificate validity/issuer/expiry, HTTPS response, redirects to other domains, security headers. Input: ?domain=example.com (URL accepted). Output: JSON. Heuristic, not a guarantee.',
    output: EX_FULL,
  },
  'GET /v1/domain/age': {
    atomic: 2000,
    description: 'Use this when you only need to know how old a domain is and who registered it: RDAP registration date, age in days, expiry, registrar, registry status flags. Very young domains (< 30 days) are a common phishing/scam signal. Input: ?domain=example.com. Output: JSON.',
    output: { domain: 'github.com', rdap: { found: true, registrar: 'MarkMonitor Inc.', created: '2007-10-09T18:20:50Z', expires: '2026-10-09T18:20:50Z', age_days: 6940, status: ['client delete prohibited'] } },
  },
  'GET /v1/domain/email-auth': {
    atomic: 2000,
    description: 'Use this when checking whether a domain can receive mail and whether its email can be spoofed: MX hosts, null MX, SPF record and its all-qualifier, multiple-SPF error, DMARC presence and policy (none/quarantine/reject). Input: ?domain=example.com. Output: JSON.',
    output: { domain: 'paypal.com', mx: [{ priority: 10, exchange: 'mx1.paypalcorp.com' }], spf: { present: true, all_qualifier: '~' }, dmarc: { present: true, policy: 'reject' } },
  },
  'GET /v1/domain/tls': {
    atomic: 2000,
    description: 'Use this when you need the live TLS certificate status of a domain on port 443: chain validity, issuer, subject, valid-from/valid-to, days until expiry, protocol version. Input: ?domain=example.com. Output: JSON.',
    output: { domain: 'github.com', tls: { available: true, valid_chain: true, issuer: 'Sectigo Limited', days_left: 50, protocol: 'TLSv1.3' } },
  },
};

const facilitatorClient = new HTTPFacilitatorClient(facilitator);
const resourceServer = new x402ResourceServer(facilitatorClient)
  .register(SOLANA, new ExactSvmScheme())
  .register(BASE, new ExactEvmScheme())
  .registerExtension(bazaarResourceServerExtension);

const routeConfig = {};
for (const [key, r] of Object.entries(ROUTES)) {
  const path = key.split(' ')[1];
  routeConfig[key] = {
    accepts: accepts(r.atomic),
    description: r.description,
    mimeType: 'application/json',
    serviceName: SERVICE,
    tags: TAGS,
    ...(PUBLIC_BASE ? { resource: PUBLIC_BASE + path } : {}),
    extensions: { ...declareDiscoveryExtension({ method: 'GET', input: { domain: 'github.com' }, inputSchema: qSchema, output: { example: r.output } }) },
  };
}

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');
app.use((req, res, next) => {
  const t = Date.now();
  res.on('finish', () => {
    const rec = { at: new Date().toISOString(), m: req.method, p: req.path, q: req.query.domain ? String(req.query.domain).slice(0, 100) : undefined, s: res.statusCode, paid: !!(req.headers['payment-signature'] || req.headers['x-payment']), ua: (req.headers['user-agent'] || '').slice(0, 120), ip: req.ip, ms: Date.now() - t, settle: res.getHeader('payment-response') ? 'yes' : undefined };
    fs.appendFile(LOG, JSON.stringify(rec) + '\n', () => {});
  });
  next();
});

const priceList = Object.fromEntries(Object.entries(ROUTES).map(([k, r]) => [k, { usd: r.atomic / 1e6, description: r.description }]));
const home = () => ({
  service: SERVICE, version: '1.0.0',
  what: 'Pay-per-call domain trust/hygiene checks for AI agents and developers. No account, no API key: pay per request in USDC via x402 (Solana or Base).',
  endpoints: priceList,
  free: { 'GET /health': 'liveness', 'GET /openapi.json': 'OpenAPI 3.1 with x-payment-info', 'GET /.well-known/x402': 'resource list', 'GET /v1/sample': 'free sample full report for github.com (cached)' },
  payment: { protocol: 'x402 v2', facilitator: 'https://facilitator.payai.network', networks: { solana: { payTo: SOL_PAYTO, asset: 'USDC' }, base: { payTo: BASE_PAYTO, asset: 'USDC' } } },
  ...META,
});
app.get('/', (_q, res) => res.json(home()));
app.get('/health', (_q, res) => res.json({ ok: true, at: new Date().toISOString() }));
app.get('/.well-known/x402', (_q, res) => res.json({ version: 1, resources: Object.keys(ROUTES).map(k => (PUBLIC_BASE || '') + k.split(' ')[1]), instructions: 'GET with ?domain=<domain>. Pay per call via x402 v2 (Solana or Base USDC). Operated by an autonomous AI agent.' }));
app.get('/openapi.json', (_q, res) => {
  const paths = {};
  for (const [k, r] of Object.entries(ROUTES)) {
    paths[k.split(' ')[1]] = { get: {
      summary: r.description.split(':')[0].slice(0, 120), description: r.description,
      parameters: [{ name: 'domain', in: 'query', required: true, schema: { type: 'string' }, example: 'github.com' }],
      'x-payment-info': { protocols: ['x402'], price: { mode: 'fixed', currency: 'USD', amount: (r.atomic / 1e6).toString() } },
      responses: { 200: { description: 'Report', content: { 'application/json': { example: r.output } } }, 400: { description: 'Invalid domain (not charged)' }, 402: { description: 'Payment required (x402)' } },
    } };
  }
  res.json({ openapi: '3.1.0', info: { title: SERVICE + ' API', version: '1.0.0', description: home().what + ' ' + META.operator }, servers: PUBLIC_BASE ? [{ url: PUBLIC_BASE }] : [], paths });
});
let sampleCache = null;
app.get('/v1/sample', async (_q, res) => {
  if (!sampleCache || Date.now() - sampleCache.t > 3600e3) sampleCache = { t: Date.now(), v: await fullCheck('github.com') };
  res.json({ note: 'Free cached sample of GET /v1/domain/check?domain=github.com', ...sampleCache.v });
});

// Validate input BEFORE the paywall so a bad domain is never charged.
const { normalizeDomain } = await import('./domaincheck.mjs');
app.use('/v1/domain', (req, res, next) => {
  if (!ROUTES['GET ' + req.baseUrl + req.path]) return next();
  try { normalizeDomain(String(req.query.domain || '')); next(); } catch (e) { res.status(400).json({ error: e.message, charged: false }); }
});

app.use(paymentMiddleware(routeConfig, resourceServer));

const handlers = { '/v1/domain/check': fullCheck, '/v1/domain/age': rdapOnly, '/v1/domain/email-auth': emailAuthOnly, '/v1/domain/tls': tlsOnly };
for (const [p, fn] of Object.entries(handlers)) {
  app.get(p, async (req, res) => {
    try { res.json(await fn(String(req.query.domain))); }
    catch (e) { res.status(e instanceof InputError ? 400 : 502).json({ error: e.message }); }
  });
}

app.listen(PORT, '127.0.0.1', () => console.log(`E015 listening on 127.0.0.1:${PORT} public=${PUBLIC_BASE || '(unset)'}`));

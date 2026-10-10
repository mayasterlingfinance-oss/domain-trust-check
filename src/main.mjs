// Apify Actor: Domain Trust Check (bulk). Pay-per-event: one "domain-checked" event per successfully checked domain.
import { Actor, log } from 'apify';
import { fullCheck, normalizeDomain, InputError } from './domaincheck.mjs';

await Actor.init();
const input = (await Actor.getInput()) || {};
const raw = [...(input.domains || []), ...((input.urls || []).map(u => (typeof u === 'string' ? u : u?.url)))].filter(Boolean);
const maxConcurrency = Math.min(Math.max(Number(input.maxConcurrency) || 5, 1), 10);
const seen = new Set(); const queue = [];
for (const r of raw) {
  try { const d = normalizeDomain(String(r)); if (!seen.has(d)) { seen.add(d); queue.push(d); } }
  catch (e) { await Actor.pushData({ input: String(r), error: e.message, charged: false }); }
}
if (!queue.length) { log.warning('No valid domains in input. Provide e.g. {"domains": ["example.com"]}'); await Actor.exit(); }
log.info(`Checking ${queue.length} unique domain(s), concurrency ${maxConcurrency}`);

let charged = 0; let stop = false;
async function worker() {
  while (queue.length && !stop) {
    const d = queue.shift();
    try {
      const rep = await fullCheck(d);
      const flat = {
        domain: rep.domain, score: rep.assessment.score, level: rep.assessment.level,
        reasons: rep.assessment.reasons.map(r => r.signal),
        domain_age_days: rep.rdap.age_days ?? null, registrar: rep.rdap.registrar ?? null, created: rep.rdap.created ?? null, expires: rep.rdap.expires ?? null,
        has_mx: rep.dns.mx.length > 0 && !rep.dns.null_mx, spf: rep.dns.spf.present, spf_all: rep.dns.spf.all_qualifier, dmarc_policy: rep.dns.dmarc.present ? rep.dns.dmarc.policy : null,
        tls_valid: rep.tls.available ? rep.tls.valid_chain : null, tls_issuer: rep.tls.issuer ?? null, tls_days_left: rep.tls.days_left ?? null,
        https_status: rep.http.status ?? null, final_url: rep.http.final_url ?? null, hsts: rep.http.security_headers?.hsts ?? null,
        checked_at: rep.checked_at, details: input.includeDetails === false ? undefined : { dns: rep.dns, rdap: rep.rdap, tls: rep.tls, http: rep.http },
      };
      if (rep.assessment.level === 'invalid') { await Actor.pushData({ ...flat, charged: false }); continue; } // NXDOMAIN: reported, not charged
      const res = await Actor.pushData(flat, 'domain-checked');
      charged++;
      if (res?.eventChargeLimitReached) { log.info('Max charge limit reached; stopping.'); stop = true; }
    } catch (e) {
      await Actor.pushData({ domain: d, error: e instanceof InputError ? e.message : 'check failed: ' + e.message, charged: false });
    }
  }
}
await Promise.all(Array.from({ length: maxConcurrency }, worker));
log.info(`Done. Domains checked: ${charged}`);
await Actor.exit();

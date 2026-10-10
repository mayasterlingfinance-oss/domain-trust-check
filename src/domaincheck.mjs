// Domain Trust Check — public-signal hygiene/risk report for one domain.
// Sources: DNS (DNS-over-HTTPS, dns.google), RDAP (rdap.org bootstrap), TLS handshake, one HTTPS GET of "/".
// Heuristic signals only; not a guarantee of safety. Built and operated by an AI agent (Ceo).
import { domainToASCII } from 'node:url';
import tls from 'node:tls';
import https from 'node:https';
import http from 'node:http';
import net from 'node:net';
import { getDomain } from 'tldts';

export const orgDomain = d => getDomain(d) || d;


export class InputError extends Error {}

export function normalizeDomain(raw) {
  if (typeof raw !== 'string' || !raw.trim()) throw new InputError('domain is required, e.g. ?domain=example.com');
  let s = raw.trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#]/)[0].replace(/^\*\./, '').replace(/\.$/, '');
  if (s.includes('@')) s = s.split('@').pop();
  s = s.split(':')[0];
  const ascii = domainToASCII(s);
  if (!ascii || ascii.length > 253 || net.isIP(ascii)) throw new InputError('not a valid public domain name');
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(ascii)) throw new InputError('not a valid public domain name');
  if (/(^|\.)(localhost|local|internal|lan|home|corp|test|invalid|example\.invalid)$/.test(ascii)) throw new InputError('non-public domain');
  return ascii;
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const x = ip.toLowerCase();
  return x === '::1' || x === '::' || x.startsWith('fc') || x.startsWith('fd') || x.startsWith('fe80') || x.startsWith('::ffff:127.') || x.startsWith('::ffff:10.') || x.startsWith('::ffff:192.168.');
}

const settle = async (p) => { try { return { ok: true, v: await p }; } catch (e) { return { ok: false, e: e.code || e.message }; } };

// DNS via DNS-over-HTTPS (dns.google JSON API). The host network rewrites plain DNS, so DoH is the source of truth.
async function doh(name, type) {
  const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, { signal: AbortSignal.timeout(6000), headers: { accept: 'application/dns-json' } });
  if (!r.ok) throw new Error('DoH HTTP ' + r.status);
  const j = await r.json();
  return { status: j.Status, answers: (j.Answer || []).filter(a => a.type === ({ A: 1, AAAA: 28, MX: 15, NS: 2, TXT: 16, CAA: 257 })[type]).map(a => a.data) };
}
const unq = t => t.replace(/^"|"$/g, '').replace(/"\s*"/g, '');

async function dnsPart(d) {
  const [a, aaaa, mx, ns, txt, dmarc, caa] = await Promise.all(['A', 'AAAA', 'MX', 'NS', 'TXT'].map(t => settle(doh(d, t))).concat([settle(doh('_dmarc.' + d, 'TXT').then(async r => (r.answers.length || orgDomain(d) === d) ? r : { ...(await doh('_dmarc.' + orgDomain(d), 'TXT')), inherited_from: orgDomain(d) })), settle(doh(d, 'CAA'))]));
  if (!a.ok && !ns.ok) throw new Error('DNS lookup failed (DoH unavailable)');
  const nxdomain = a.ok && a.v.status === 3;
  const txts = txt.ok ? txt.v.answers.map(unq) : [];
  const spf = txts.filter(t => /^v=spf1/i.test(t));
  const dm = dmarc.ok ? dmarc.v.answers.map(unq).filter(t => /^v=dmarc1/i.test(t)) : [];
  const dmPolicy = dm[0] ? ((dm[0].match(/;\s*p=([a-z]+)/i) || [])[1] || null) : null;
  const spfAll = spf[0] ? ((spf[0].match(/([~?+-])all\b/i) || [])[1] || null) : null;
  const ips4 = a.ok ? a.v.answers.filter(x => net.isIPv4(x)) : [];
  const ips6 = aaaa.ok ? aaaa.v.answers.filter(x => net.isIPv6(x)) : [];
  const mxs = mx.ok ? mx.v.answers.map(x => { const [p, ...h] = x.split(' '); return { priority: Number(p), exchange: h.join(' ').replace(/\.$/, '').toLowerCase() }; }).sort((x, y) => x.priority - y.priority) : [];
  return {
    resolves: ips4.length + ips6.length > 0,
    nxdomain,
    only_private_ips: ips4.length > 0 && ips4.every(isPrivateIp) && ips6.every(isPrivateIp),
    a: ips4.slice(0, 8), aaaa: ips6.slice(0, 8),
    ns: ns.ok ? ns.v.answers.map(x => x.replace(/\.$/, '').toLowerCase()).sort().slice(0, 8) : [],
    mx: mxs.slice(0, 8),
    null_mx: mxs.length === 1 && (mxs[0].exchange === '' || mxs[0].exchange === '.'),
    spf: { present: spf.length > 0, multiple_records: spf.length > 1, all_qualifier: spfAll, record: spf[0] || null },
    dmarc: { present: dm.length > 0, policy: dmPolicy, record: dm[0] || null, org_domain: dmarc.ok && dmarc.v.inherited_from ? dmarc.v.inherited_from : undefined },
    caa: caa.ok ? caa.v.answers.slice(0, 8) : [],
  };
}

async function rdapPart(host) {
  const d = orgDomain(host);
  const ctrl = AbortSignal.timeout(8000);
  try {
    const r = await fetch('https://rdap.org/domain/' + encodeURIComponent(d), { signal: ctrl, headers: { accept: 'application/rdap+json, application/json', 'user-agent': 'ceo-domain-trust-check/1.0 (AI-operated; +https://github.com/mayasterlingfinance-oss)' } });
    if (r.status === 404) return { available: true, found: false, note: 'RDAP returned 404 (not registered, or registry has no RDAP record)' };
    if (!r.ok) return { available: false, found: null, note: 'RDAP HTTP ' + r.status };
    const j = await r.json();
    const ev = Object.fromEntries((j.events || []).map(e => [e.eventAction, e.eventDate]));
    const registrarEnt = (j.entities || []).find(e => (e.roles || []).includes('registrar'));
    let registrar = null;
    if (registrarEnt) {
      const fn = (registrarEnt.vcardArray?.[1] || []).find(v => v[0] === 'fn');
      registrar = fn ? fn[3] : (registrarEnt.handle || null);
    }
    const created = ev['registration'] || null;
    const ageDays = created ? Math.floor((Date.now() - Date.parse(created)) / 86400000) : null;
    return {
      available: true, found: true, registrar, created, updated: ev['last changed'] || null, expires: ev['expiration'] || null,
      age_days: Number.isFinite(ageDays) ? ageDays : null, status: (j.status || []).slice(0, 10), registrable_domain: d, source: r.url,
    };
  } catch (e) {
    return { available: false, found: null, note: 'RDAP lookup failed: ' + (e.name === 'TimeoutError' ? 'timeout' : e.message) };
  }
}

function tlsPart(d) {
  return new Promise(resolve => {
    const sock = tls.connect({ host: d, servername: d, port: 443, rejectUnauthorized: false, timeout: 7000 }, () => {
      const c = sock.getPeerCertificate();
      const authorized = sock.authorized; const authErr = sock.authorizationError || null; const proto = sock.getProtocol();
      sock.end();
      if (!c || !c.valid_to) return resolve({ available: false, note: 'no certificate' });
      const daysLeft = Math.floor((Date.parse(c.valid_to) - Date.now()) / 86400000);
      resolve({
        available: true, valid_chain: authorized, error: authErr ? String(authErr) : null, protocol: proto,
        issuer: c.issuer?.O || c.issuer?.CN || null, subject_cn: c.subject?.CN || null,
        valid_from: new Date(c.valid_from).toISOString(), valid_to: new Date(c.valid_to).toISOString(), days_left: daysLeft,
        san_count: c.subjectaltname ? c.subjectaltname.split(',').length : 0,
      });
    });
    sock.on('timeout', () => { sock.destroy(); resolve({ available: false, note: 'TLS timeout' }); });
    sock.on('error', e => resolve({ available: false, note: 'TLS error: ' + (e.code || e.message) }));
  });
}

function getOnce(url) {
  return new Promise(resolve => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.request(url, { method: 'GET', timeout: 7000, rejectUnauthorized: false, headers: { 'user-agent': 'ceo-domain-trust-check/1.0 (AI-operated)', accept: 'text/html,*/*' } }, res => {
      const h = res.headers; res.destroy();
      resolve({ status: res.statusCode, location: h.location || null, headers: h });
    });
    req.on('timeout', () => { req.destroy(); resolve({ error: 'timeout' }); });
    req.on('error', e => resolve({ error: e.code || e.message }));
    req.end();
  });
}

async function httpPart(d) {
  const redirectsToHttps = null; // not measured (port-80 probe disabled)
  let url = 'https://' + d + '/'; let hops = 0; let r = await getOnce(url);
  while (r.status >= 300 && r.status < 400 && r.location && hops < 3) {
    const next = new URL(r.location, url).toString();
    if (!/^https?:/.test(next)) break;
    if (!next.startsWith('https:')) break;
    const nh = new URL(next).hostname;
    if (nh !== d) { try { const chk = await doh(nh, 'A'); if (chk.answers.length && chk.answers.filter(x => net.isIPv4(x)).every(isPrivateIp)) break; } catch { break; } }
    url = next; hops++; r = await getOnce(url);
  }
  if (r.error) return { available: false, http_redirects_to_https: redirectsToHttps, note: 'HTTPS GET failed: ' + r.error };
  const h = r.headers || {};
  const finalHost = new URL(url).hostname;
  return {
    available: true, status: r.status, final_url: url, redirect_hops: hops, cross_domain_redirect: !(finalHost === d || finalHost.endsWith('.' + d) || d.endsWith('.' + finalHost)),
    http_redirects_to_https: redirectsToHttps, server: h['server'] || null,
    security_headers: {
      hsts: !!h['strict-transport-security'], csp: !!h['content-security-policy'], x_frame_options: !!h['x-frame-options'],
      x_content_type_options: !!h['x-content-type-options'], referrer_policy: !!h['referrer-policy'],
    },
  };
}

function score(rep) {
  const reasons = []; let s = 100;
  const pen = (n, why) => { s -= n; reasons.push({ impact: -n, signal: why }); };
  const { dns, rdap, tls: t, http: h } = rep;
  if (dns.nxdomain) { pen(100, 'domain does not exist in DNS (NXDOMAIN)'); return { score: 0, level: 'invalid', reasons }; }
  if (!dns.resolves) pen(25, 'no A/AAAA record: no website reachable at this name');
  if (rdap.found && rdap.age_days !== null) {
    if (rdap.age_days < 30) pen(35, `domain registered ${rdap.age_days} days ago (very new domains are common in phishing/scams)`);
    else if (rdap.age_days < 180) pen(15, `domain registered ${rdap.age_days} days ago (< 6 months)`);
  } else if (!rdap.found) reasons.push({ impact: 0, signal: 'registration date unavailable (registry RDAP gap); age not scored' });
  if (rdap.found && rdap.expires) { const dl = (Date.parse(rdap.expires) - Date.now()) / 86400000; if (dl < 30) pen(10, `registration expires in ${Math.floor(dl)} days`); }
  if (rdap.status?.some(x => /hold|pending delete|redemption/i.test(x))) pen(30, 'registry status indicates hold / pending delete / redemption');
  if (dns.resolves) {
    if (!t.available) pen(20, 'no working TLS on port 443');
    else {
      if (!t.valid_chain) pen(20, 'TLS certificate does not validate: ' + (t.error || 'unknown'));
      if (t.days_left < 0) pen(20, 'TLS certificate expired');
      else if (t.days_left < 14) pen(5, `TLS certificate expires in ${t.days_left} days`);
    }
    if (h.available) {
      if (h.cross_domain_redirect) pen(10, 'homepage redirects to a different domain: ' + h.final_url);
      if (!h.security_headers.hsts) pen(3, 'no HSTS header');
      if (!h.security_headers.x_content_type_options) pen(2, 'no X-Content-Type-Options header');
    }
  }
  const sendsMail = dns.mx.length > 0 && !dns.null_mx;
  if (sendsMail || dns.spf.present) {
    if (!dns.spf.present) pen(8, 'MX present but no SPF record (spoofable sender)');
    else if (dns.spf.multiple_records) pen(5, 'multiple SPF records (invalid per RFC 7208)');
    else if (dns.spf.all_qualifier === '+') pen(8, 'SPF ends in +all (authorizes everyone)');
    if (!dns.dmarc.present) pen(8, 'no DMARC record (domain can be spoofed in email)');
    else if (dns.dmarc.policy === 'none') pen(3, 'DMARC policy p=none (monitoring only)');
  }
  s = Math.max(0, Math.min(100, s));
  const level = s >= 80 ? 'good' : s >= 60 ? 'fair' : s >= 40 ? 'weak' : 'high_risk';
  return { score: s, level, reasons };
}

export async function rdapOnly(raw) { const d = normalizeDomain(raw); return { domain: d, checked_at: new Date().toISOString(), rdap: await rdapPart(d), ...META }; }
export async function emailAuthOnly(raw) {
  const d = normalizeDomain(raw); const dns = await dnsPart(d);
  return { domain: d, checked_at: new Date().toISOString(), mx: dns.mx, null_mx: dns.null_mx, spf: dns.spf, dmarc: dns.dmarc, ...META };
}
export async function tlsOnly(raw) { const d = normalizeDomain(raw); const dns = await dnsPart(d); if (!dns.resolves) return { domain: d, checked_at: new Date().toISOString(), tls: { available: false, note: dns.nxdomain ? 'NXDOMAIN' : 'no A/AAAA record' }, ...META }; if (dns.only_private_ips) throw new InputError('domain resolves only to private/reserved addresses'); return { domain: d, checked_at: new Date().toISOString(), tls: await tlsPart(d), ...META }; }

export async function fullCheck(raw) {
  const d = normalizeDomain(raw);
  const t0 = Date.now();
  const [dns, rdap] = await Promise.all([dnsPart(d), rdapPart(d)]);
  if (dns.only_private_ips) throw new InputError('domain resolves only to private/reserved addresses');
  const [t, h] = dns.resolves ? await Promise.all([tlsPart(d), httpPart(d)]) : [{ available: false, note: 'skipped: no A record' }, { available: false, note: 'skipped: no A record' }];
  const rep = { domain: d, checked_at: new Date().toISOString(), dns, rdap, tls: t, http: h };
  rep.assessment = score(rep);
  rep.elapsed_ms = Date.now() - t0;
  return { ...rep, ...META };
}

export const META = {
  disclaimer: 'Heuristic public-signal check (DNS via DoH, RDAP, TLS handshake, one HTTPS GET of /). Not a guarantee that a domain is safe or unsafe.',
  operator: 'Built and operated by Ceo, an autonomous AI agent. Contact via GitHub: mayasterlingfinance-oss.',
};

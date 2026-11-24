// Blog Worker: serves static assets; guards the private /me section by verifying the
// Cloudflare Access JWT itself (defense in depth). If Access is missing or misconfigured,
// /me answers 403 with an empty body — never private content.
// Runs on Workers and on Node 22 (tests): uses only WebCrypto, atob, fetch, Request, Response.

const DENY_HEADERS = { 'Cache-Control': 'private, no-store', 'X-Robots-Tag': 'noindex' };
const JWKS_TTL_S = 600;
const REFETCH_MIN_S = 60;
const SKEW_S = 60;
const JWKS_TIMEOUT_MS = 5000;
const TEAM_DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/i;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

const deny = () => new Response(null, { status: 403, headers: DENY_HEADERS });

// ---------- private path rule ----------
// Deny-by-default: a path is private when its first non-empty segment, after
// repeated percent-decoding, lower-casing, '\'→'/' and resolving '.'/'..', is "me"
// followed by end-of-segment or any character that is not [a-z0-9_-].
// So /me, /me/, /ME/, /%6De/, /me.html, /me;x, //me/, /x/../me are private;
// /media, /meet, /memo, /me-time, /posts/me/ are public. Undecodable paths are private.
export function isPrivatePath(pathname) {
  let p = String(pathname ?? '');
  for (let i = 0; i < 5; i++) {
    let d;
    try { d = decodeURIComponent(p); } catch { return true; }
    if (d === p) break;
    p = d;
    if (i === 4) return true; // still changing after 5 rounds: treat as private
  }
  const out = [];
  for (const seg of p.toLowerCase().replace(/\\/g, '/').split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return out.length > 0 && /^me(?:$|[^a-z0-9_-])/.test(out[0]);
}

// ---------- base64url / JSON ----------
function b64urlToBytes(s) {
  if (typeof s !== 'string' || !B64URL_RE.test(s) || s.length % 4 === 1) throw new Error('bad b64url');
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const b64urlJson = s => {
  const v = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b64urlToBytes(s)));
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
  return v;
};

// ---------- JWKS cache (module scope, per team domain) ----------
// Amplification limits: concurrent lookups share one in-flight fetch; a failed fetch
// blocks further fetches for REFETCH_MIN_S (deny meanwhile, whatever the cache state);
// an unknown kid refetches at most once per REFETCH_MIN_S; each fetch is bounded in time.
const states = new Map(); // domain -> { keys, fetchedAt, lastFetchAt, failedAt, inflight }

export function _resetCache() { states.clear(); }

async function defaultFetchJwks(url) {
  const res = await fetch(url, { redirect: 'error', headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(JWKS_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`JWKS HTTP ${res.status}`);
  return res.json();
}

function withTimeout(promise, ms) {
  let timer;
  const t = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('JWKS timeout')), ms); });
  return Promise.race([promise, t]).finally(() => clearTimeout(timer));
}

function startFetch(st, domain, fetchJwks, now, timeoutMs) {
  st.lastFetchAt = now;
  st.inflight = (async () => {
    try {
      const body = await withTimeout(Promise.resolve().then(() => fetchJwks(`https://${domain}/cdn-cgi/access/certs`)), timeoutMs);
      if (!body || !Array.isArray(body.keys)) throw new Error('bad JWKS');
      const keys = new Map();
      for (const k of body.keys) {
        if (k && typeof k.kid === 'string' && k.kid && k.kty === 'RSA' && (k.alg === undefined || k.alg === 'RS256')) keys.set(k.kid, k);
      }
      st.keys = keys;
      st.fetchedAt = now;
    } catch {
      st.failedAt = now;
    } finally {
      st.inflight = null;
    }
  })();
  return st.inflight;
}

async function getJwk(domain, kid, fetchJwks, now, timeoutMs) {
  let st = states.get(domain);
  if (!st) { st = { keys: null, fetchedAt: -Infinity, lastFetchAt: -Infinity, failedAt: -Infinity, inflight: null }; states.set(domain, st); }
  const lookup = () => (st.keys && now - st.fetchedAt < JWKS_TTL_S ? st.keys.get(kid) ?? null : null);
  const hit = lookup();
  if (hit) return hit;
  if (st.inflight) { await st.inflight; return lookup(); }
  if (now - st.failedAt < REFETCH_MIN_S) return null;                 // backoff after failure
  if (st.keys && now - st.fetchedAt < JWKS_TTL_S && now - st.lastFetchAt < REFETCH_MIN_S) return null; // unknown kid, rate-limited
  await startFetch(st, domain, fetchJwks, now, timeoutMs);
  return lookup();
}

// ---------- verification ----------
const envStr = v => (typeof v === 'string' ? v.trim() : '');

/**
 * Verify a Cloudflare Access JWT. Returns the claims on success, null on any failure. Never throws.
 * opts.fetchJwks(url) → JWKS object (injectable for tests); opts.now = current time in seconds;
 * opts.jwksTimeoutMs bounds each JWKS fetch (default 5000).
 */
export async function verifyAccessJwt(token, env, opts = {}) {
  try {
    const fetchJwks = opts.fetchJwks ?? defaultFetchJwks;
    const now = typeof opts.now === 'number' ? opts.now : Math.floor(Date.now() / 1000);
    const domain = envStr(env?.ACCESS_TEAM_DOMAIN).toLowerCase();
    const aud = envStr(env?.ACCESS_AUD);
    const allowed = envStr(env?.ALLOWED_EMAIL).toLowerCase();
    if (!domain || !aud || !allowed || !TEAM_DOMAIN_RE.test(domain)) return null;

    if (typeof token !== 'string' || token.length > 16384) return null;
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some(x => !B64URL_RE.test(x))) return null;
    const [h, p, s] = parts;
    const header = b64urlJson(h);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid) return null;
    const payload = b64urlJson(p);

    const jwk = await getJwk(domain, header.kid, fetchJwks, now, opts.jwksTimeoutMs ?? JWKS_TIMEOUT_MS);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(s), new TextEncoder().encode(`${h}.${p}`));
    if (!ok) return null;

    if (payload.iss !== `https://${domain}`) return null;
    const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!auds.includes(aud)) return null;
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || payload.exp <= now - SKEW_S) return null;
    if (payload.nbf !== undefined && (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf) || payload.nbf > now + SKEW_S)) return null;
    if (typeof payload.email !== 'string' || payload.email.trim().toLowerCase() !== allowed) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------- handler ----------
export function createHandler({ fetchJwks, now } = {}) {
  return {
    async fetch(request, env) {
      const url = new URL(request.url);
      if (!isPrivatePath(url.pathname)) return env.ASSETS.fetch(request);
      try {
        const token = request.headers.get('Cf-Access-Jwt-Assertion');
        const claims = await verifyAccessJwt(token, env, { fetchJwks, now: now ? now() : undefined });
        if (!claims) return deny();
        const res = await env.ASSETS.fetch(request);
        const out = new Response(res.body, res); // asset headers are immutable: copy
        for (const [k, v] of Object.entries(DENY_HEADERS)) out.headers.set(k, v);
        return out;
      } catch {
        return deny();
      }
    },
  };
}

export default createHandler();

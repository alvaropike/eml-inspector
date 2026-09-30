/*
 * Google Safe Browsing (API v5, hashes.search) con prefijos de hash: las URLs se canonicalizan
 * y se convierten en expresiones «host/ruta» en local; sólo salen los 4 primeros bytes del
 * SHA-256 de cada expresión, que comparten miles de URLs, así que Google no sabe qué enlaces
 * contiene el correo. Las coincidencias se confirman aquí comparando el hash completo.
 * https://developers.google.com/safe-browsing/reference
 */
(function (global) {
  'use strict';

  const ENDPOINT = 'https://safebrowsing.googleapis.com/v5/hashes:search';
  const BATCH = 400;      // prefijos por petición (GET: la URL no debe crecer demasiado)
  const MAX_URLS = 300;
  const THREATS = {
    MALWARE: 'malware',
    SOCIAL_ENGINEERING: 'phishing o ingeniería social',
    UNWANTED_SOFTWARE: 'software no deseado',
    POTENTIALLY_HARMFUL_APPLICATION: 'aplicación potencialmente dañina',
  };
  const ADVISORY_URL = 'https://developers.google.com/safe-browsing/v4/advisory';

  // ---------- canonicalización (se trabaja con cadenas de bytes: un carácter = un byte) ----------

  const toBytes = s => unescape(encodeURIComponent(s));
  const unescapeAll = s => {
    for (let i = 0; i < 20; i++) {
      const next = s.replace(/%([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
      if (next === s) break;
      s = next;
    }
    return s;
  };
  const escapeBytes = s => s.replace(/[\x00-\x20\x7f-\xff#%]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'));

  // IPv4 en cualquier notación legal (decimal, octal, hex, menos de cuatro partes) → a.b.c.d
  function parseIPv4(host) {
    const parts = host.split('.');
    if (!parts.length || parts.length > 4) return null;
    const nums = [];
    for (const p of parts) {
      let n;
      if (/^0x[0-9a-f]*$/i.test(p)) n = p.length > 2 ? parseInt(p.slice(2), 16) : 0;
      else if (/^0[0-7]*$/.test(p)) n = parseInt(p, 8) || 0;
      else if (/^[1-9][0-9]*$/.test(p)) n = parseInt(p, 10);
      else return null;
      nums.push(n);
    }
    const last = nums.pop();
    if (nums.some(n => n > 255) || last >= 2 ** (8 * (4 - nums.length))) return null;
    let value = last;
    nums.forEach((n, i) => { value += n * 2 ** (8 * (3 - i)); });
    return [24, 16, 8, 0].map(s => Math.floor(value / 2 ** s) % 256).join('.');
  }

  function resolvePath(p) {
    const segs = p.replace(/\/{2,}/g, '/').split('/');
    const out = [];
    for (let i = 1; i < segs.length; i++) {
      const s = segs[i], last = i === segs.length - 1;
      if (s === '.' || s === '..') {
        if (s === '..') out.pop();
        if (last) out.push('');
        continue;
      }
      out.push(s);
    }
    return '/' + out.join('/');
  }

  // Devuelve { host, path, query } canónicos, o null si no es una URL http(s).
  function canonicalize(url) {
    let u = toBytes(String(url)).replace(/[\t\r\n]/g, '').replace(/^[\x00-\x20]+|[\x00-\x20]+$/g, '');
    u = u.replace(/#.*$/, '');
    const scheme = u.match(/^([a-z][a-z0-9+.-]*):\/\//i);
    if (!scheme) u = 'http://' + u;
    else if (!/^https?$/i.test(scheme[1])) return null;
    const rest = u.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
    const cut = rest.search(/[/?]/);
    let authority = cut < 0 ? rest : rest.slice(0, cut);
    let tail = cut < 0 ? '/' : rest.slice(cut);
    if (tail[0] === '?') tail = '/' + tail;
    authority = authority.replace(/^.*@/, '');
    let host = /^\[/.test(authority) ? authority.replace(/\](:\d*)?$/, ']') : authority.replace(/:\d*$/, '');
    host = unescapeAll(host).toLowerCase().replace(/^\.+|\.+$/g, '').replace(/\.{2,}/g, '.');
    if (!host) return null;
    const ip = parseIPv4(host);
    if (ip) host = ip;
    else if (/[\x80-\xff]/.test(host)) {
      // Dominio internacionalizado: se consulta en punycode, como lo resuelve el navegador.
      try { host = new URL('http://' + decodeURIComponent(escape(host))).hostname; } catch (_) { /* se deja escapado */ }
    }
    const q = tail.indexOf('?');
    const path = resolvePath(unescapeAll(q < 0 ? tail : tail.slice(0, q)));
    const query = q < 0 ? null : unescapeAll(tail.slice(q + 1));
    return { host: escapeBytes(host), path: escapeBytes(path), query: query == null ? null : escapeBytes(query), isIP: !!ip || /^\[/.test(host) };
  }

  const canonicalURL = c => c && `http://${c.host}${c.path}${c.query != null ? '?' + c.query : ''}`;

  // Combinaciones host/ruta que se comprueban (hasta 5 hosts × 6 rutas).
  function expressions(url) {
    const c = canonicalize(url);
    if (!c) return [];
    const hosts = [c.host];
    if (!c.isIP) {
      const labels = c.host.split('.');
      const org = global.Analysis ? global.Analysis.orgDomain(c.host) : labels.slice(-2).join('.');
      const minLen = Math.max(2, org.split('.').length);
      for (let n = Math.min(5, labels.length); n >= minLen && hosts.length < 5; n--) {
        const h = labels.slice(-n).join('.');
        if (!hosts.includes(h)) hosts.push(h);
      }
    }
    const paths = [];
    if (c.query != null) paths.push(c.path + '?' + c.query);
    paths.push(c.path);
    const dirs = c.path.split('/').slice(1, -1);
    let acc = '/';
    for (let i = 0; i <= dirs.length && i < 4; i++) {
      if (!paths.includes(acc)) paths.push(acc);
      if (i < dirs.length) acc += dirs[i] + '/';
    }
    const out = [];
    hosts.forEach(h => paths.forEach(p => out.push(h + p)));
    return out;
  }

  // ---------- consulta ----------

  const b64 = bytes => btoa(String.fromCharCode(...bytes));
  async function sha256(str) {
    const bytes = Uint8Array.from(str, ch => ch.charCodeAt(0));
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  }

  const cache = new Map(); // prefijo → { expires, full: [{hash, threats}] }

  function parseDuration(d) {
    const m = String(d || '').match(/^([\d.]+)s$/);
    return m ? parseFloat(m[1]) * 1000 : 5 * 60 * 1000;
  }

  // La API v5 responde en protobuf (no admite alt=json). Mensajes de SearchHashesResponse:
  //   1: FullHash { 1: bytes full_hash, 2: FullHashDetail { 1: ThreatType, 2: [ThreatAttribute] } } (repetido)
  //   2: Duration cache_duration { 1: seconds, 2: nanos }
  const THREAT_ENUM = ['THREAT_TYPE_UNSPECIFIED', 'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'];
  const ATTR_ENUM = ['THREAT_ATTRIBUTE_UNSPECIFIED', 'CANARY', 'FRAME_ONLY'];

  function pbFields(buf) {
    const out = [];
    let i = 0;
    const varint = () => {
      let v = 0, mul = 1, b;
      do { if (i >= buf.length) throw new Error('protobuf truncado'); b = buf[i++]; v += (b & 0x7f) * mul; mul *= 128; } while (b & 0x80);
      return v;
    };
    while (i < buf.length) {
      const tag = varint(), field = Math.floor(tag / 8), wire = tag & 7;
      if (wire === 0) out.push({ field, value: varint() });
      else if (wire === 2) { const len = varint(); out.push({ field, bytes: buf.subarray(i, i + len) }); i += len; }
      else if (wire === 1) i += 8;
      else if (wire === 5) i += 4;
      else throw new Error('protobuf no válido');
    }
    return out;
  }
  // Enum repetido: puede venir empaquetado (bytes con varints) o como campos sueltos.
  const pbEnums = (fields, n) => [].concat(...fields.filter(f => f.field === n).map(f => f.bytes ? unpack(f.bytes) : [f.value]));
  function unpack(bytes) {
    const vals = [];
    let v = 0, mul = 1;
    for (const b of bytes) { v += (b & 0x7f) * mul; mul *= 128; if (!(b & 0x80)) { vals.push(v); v = 0; mul = 1; } }
    return vals;
  }

  function decodeSearchResponse(buf) {
    const res = { fullHashes: [], cacheDuration: '' };
    for (const f of pbFields(buf)) {
      if (f.field === 1 && f.bytes) {
        const fh = { fullHash: '', fullHashDetails: [] };
        for (const g of pbFields(f.bytes)) {
          if (g.field === 1 && g.bytes) fh.fullHash = b64(g.bytes);
          else if (g.field === 2 && g.bytes) {
            const d = pbFields(g.bytes);
            const t = d.find(x => x.field === 1 && x.value != null);
            fh.fullHashDetails.push({ threatType: THREAT_ENUM[t ? t.value : 0] || 'THREAT_TYPE_UNSPECIFIED', attributes: pbEnums(d, 2).map(a => ATTR_ENUM[a] || String(a)) });
          }
        }
        res.fullHashes.push(fh);
      } else if (f.field === 2 && f.bytes) {
        const d = pbFields(f.bytes);
        const sec = (d.find(x => x.field === 1) || {}).value || 0, nanos = (d.find(x => x.field === 2) || {}).value || 0;
        res.cacheDuration = (sec + nanos / 1e9) + 's';
      }
    }
    return res;
  }

  async function search(prefixes, key, signal) {
    const qs = prefixes.map(p => 'hashPrefixes=' + encodeURIComponent(p)).join('&');
    const r = await fetch(`${ENDPOINT}?key=${encodeURIComponent(key)}&${qs}`, { signal, referrerPolicy: 'origin', credentials: 'omit' }); // sólo el origen: permite restringir la clave por sitio web
    const isJson = /json/i.test(r.headers.get('content-type') || '');
    if (r.ok && !isJson) return decodeSearchResponse(new Uint8Array(await r.arrayBuffer()));
    const body = await r.json().catch(() => ({}));
    if (!r.ok) {
      const msg = (body.error && body.error.message) || 'HTTP ' + r.status;
      const reason = JSON.stringify(body.error || {});
      if (/API_KEY_INVALID/.test(reason)) throw new Error('la clave de API no es válida');
      if (/SERVICE_DISABLED|accessNotConfigured|has not been used/i.test(reason + msg)) throw new Error('la clave no tiene activada la Safe Browsing API en su proyecto de Google Cloud');
      if (r.status === 429) throw new Error('se ha superado la cuota de la clave');
      throw new Error(msg);
    }
    return body;
  }

  // urls: [{ url, link? | domain?, … }] · devuelve { urls, domains, expressions, prefixes, matches: [{ …entrada, expression, threats }] }
  async function check(urls, key, { signal } = {}) {
    const items = [];
    const seenUrl = new Set();
    for (const it of urls) {
      const canon = canonicalURL(canonicalize(it.url));
      if (!canon || seenUrl.has(canon)) continue;
      seenUrl.add(canon);
      items.push(Object.assign({ exprs: expressions(it.url) }, it));
      if (items.length >= MAX_URLS) break;
    }
    const byExpr = new Map(); // expresión → hash completo (base64)
    for (const it of items) for (const e of it.exprs) if (!byExpr.has(e)) byExpr.set(e, await sha256(e));
    const prefixOf = h => b64(h.slice(0, 4));
    const allPrefixes = [...new Set([...byExpr.values()].map(prefixOf))];

    const now = Date.now();
    const pending = allPrefixes.filter(p => !(cache.has(p) && cache.get(p).expires > now));
    for (let i = 0; i < pending.length; i += BATCH) {
      const batch = pending.slice(i, i + BATCH);
      const res = await search(batch, key, signal);
      const expires = Date.now() + parseDuration(res.cacheDuration);
      batch.forEach(p => cache.set(p, { expires, full: [] }));
      (res.fullHashes || []).forEach(fh => {
        const full = Uint8Array.from(atob(fh.fullHash || ''), ch => ch.charCodeAt(0));
        if (full.length !== 32) return;
        // CANARY: en pruebas, no debe aplicarse. FRAME_ONLY: sólo para contenido incrustado, no para un enlace.
        const threats = (fh.fullHashDetails || [])
          .filter(d => !(d.attributes || []).some(a => a === 'CANARY' || a === 'FRAME_ONLY'))
          .map(d => d.threatType).filter(t => t && t !== 'THREAT_TYPE_UNSPECIFIED');
        const entry = cache.get(prefixOf(full)) || { expires, full: [] };
        entry.full.push({ hash: b64(full), threats });
        cache.set(prefixOf(full), entry);
      });
    }

    const matches = [];
    for (const it of items) {
      for (const e of it.exprs) {
        const h = byExpr.get(e);
        const hit = (cache.get(prefixOf(h)) || { full: [] }).full.find(f => f.hash === b64(h) && f.threats.length);
        if (hit) {
          const { exprs, ...rest } = it;
          matches.push(Object.assign(rest, { embedded: !!it.embedded, expression: e, threats: [...new Set(hit.threats)] }));
          break;
        }
      }
    }
    return { urls: items.filter(i => !i.domain).length, domains: items.filter(i => i.domain).length, expressions: byExpr.size, prefixes: allPrefixes.length, matches };
  }

  global.SafeBrowsing = { check, canonicalize, canonicalURL, expressions, THREATS, ADVISORY_URL, label: t => THREATS[t] || t };
})(typeof globalThis !== 'undefined' ? globalThis : this);

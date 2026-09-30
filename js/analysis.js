/*
 * Análisis forense y heurístico de un correo ya parseado por MIME.parseEmail.
 */
(function (global) {
  'use strict';

  const MIME = global.MIME;
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  // ---------- direcciones y dominios ----------

  function splitTopLevel(str, sep) {
    const out = [];
    let cur = '', q = false, angle = 0, paren = 0;
    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      if (q) { if (c === '\\') { cur += c + (str[++i] || ''); continue; } if (c === '"') q = false; cur += c; continue; }
      if (c === '"') q = true;
      else if (c === '<') angle++;
      else if (c === '>') angle = Math.max(0, angle - 1);
      else if (c === '(') paren++;
      else if (c === ')') paren = Math.max(0, paren - 1);
      else if (c === sep && !angle && !paren) { out.push(cur); cur = ''; continue; }
      cur += c;
    }
    out.push(cur);
    return out.map(s => s.trim()).filter(Boolean);
  }

  function parseAddressList(str) {
    if (!str) return [];
    // Grupos "Nombre: a@b, c@d;"
    str = str.replace(/^[^:<>"@]+:\s*(.*?);?\s*$/, '$1');
    return splitTopLevel(str, ',').map(part => {
      const m = part.match(/^(.*?)<([^>]*)>\s*(?:\(.*\))?$/);
      let name, address;
      if (m) { name = m[1].trim(); address = m[2].trim(); }
      else {
        const c = part.match(/^([^\s(]+)\s*\((.*)\)$/);
        if (c) { address = c[1]; name = c[2]; } else { address = part.trim(); name = ''; }
      }
      name = name.replace(/^"(.*)"$/, '$1').replace(/\\(.)/g, '$1').trim();
      return { name, address: address.replace(/^mailto:/i, '') };
    }).filter(a => a.address || a.name);
  }

  function domainOf(addr) {
    const m = String(addr || '').match(/@([^\s>@]+)\s*$/);
    return m ? m[1].toLowerCase().replace(/\.$/, '') : '';
  }

  // Extracto de la Public Suffix List. MULTI_SUFFIX: sufijos de registro de dos niveles de los
  // ccTLD más habituales. SHARED_HOSTING: plataformas en las que cada subdominio es de un cliente
  // distinto (sección PRIVATE): evil.github.io no es de GitHub ni de paypal.github.io.
  const MULTI_SUFFIX = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'nhs.uk', 'police.uk',
    'com.es', 'org.es', 'gob.es', 'nom.es', 'edu.es',
    'com.mx', 'gob.mx', 'org.mx', 'edu.mx', 'net.mx', 'com.ar', 'gob.ar', 'gov.ar', 'org.ar', 'net.ar', 'edu.ar', 'int.ar',
    'com.br', 'gov.br', 'net.br', 'org.br', 'edu.br', 'com.co', 'gov.co', 'org.co', 'edu.co', 'net.co',
    'com.pe', 'gob.pe', 'org.pe', 'edu.pe', 'net.pe', 'gob.cl', 'cl.cl', 'com.ve', 'gob.ve', 'co.ve', 'com.uy', 'gub.uy', 'edu.uy', 'org.uy',
    'com.ec', 'gob.ec', 'edu.ec', 'org.ec', 'net.ec', 'fin.ec', 'com.bo', 'gob.bo', 'com.py', 'gov.py', 'com.do', 'gob.do', 'com.gt', 'gob.gt',
    'com.sv', 'gob.sv', 'com.ni', 'gob.ni', 'com.pa', 'gob.pa', 'co.cr', 'go.cr', 'com.cu', 'com.pr', 'com.hn', 'gob.hn',
    'com.pt', 'gov.pt', 'org.pt', 'edu.pt', 'com.tr', 'gov.tr', 'org.tr', 'edu.tr', 'com.gr', 'gov.gr', 'com.cy', 'com.pl', 'net.pl', 'org.pl', 'gov.pl',
    'co.at', 'or.at', 'ac.at', 'gv.at', 'co.hu', 'com.ua', 'gov.ua', 'co.il', 'org.il', 'ac.il', 'gov.il',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz', 'ac.nz', 'govt.nz',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr', 'go.kr', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'com.hk', 'org.hk', 'edu.hk', 'gov.hk', 'com.tw', 'org.tw', 'gov.tw', 'edu.tw', 'com.sg', 'edu.sg', 'gov.sg', 'org.sg',
    'com.my', 'gov.my', 'com.ph', 'gov.ph', 'co.th', 'in.th', 'go.th', 'ac.th', 'com.vn', 'gov.vn', 'co.id', 'or.id', 'ac.id', 'go.id',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'com.pk', 'com.bd', 'com.sa', 'gov.sa', 'com.qa', 'com.kw', 'co.ae', 'gov.ae', 'com.eg',
    'co.za', 'org.za', 'gov.za', 'ac.za', 'co.ke', 'com.ng', 'gov.ng', 'co.ma', 'com.tn',
  ]);
  const SHARED_HOSTING = new Set([
    'github.io', 'gitlab.io', 'codeberg.page', 'herokuapp.com', 'pages.dev', 'workers.dev', 'r2.dev', 'trycloudflare.com', 'web.app', 'firebaseapp.com',
    'appspot.com', 'netlify.app', 'vercel.app', 'onrender.com', 'fly.dev', 'glitch.me', 'repl.co', 'surge.sh', 'ngrok.io', 'ngrok.app', 'ngrok-free.app',
    'azurewebsites.net', 'azurestaticapps.net', 'azureedge.net', 'cloudfront.net', 'blob.core.windows.net', 'web.core.windows.net', 's3.amazonaws.com',
    'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com', 'webflow.io', 'myshopify.com', 'square.site', 'godaddysites.com', 'notion.site',
    'gitbook.io', 'carrd.co', '000webhostapp.com', 'pythonanywhere.com', 'duckdns.org', 'ddns.net', 'translate.goog',
  ]);

  // Dominio registrable («organización») de un host: el nivel bajo el sufijo público.
  function orgDomain(host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '');
    if (!host || isIP(host)) return host;
    const labels = host.split('.');
    for (const n of [4, 3, 2]) {
      const suffix = labels.slice(-n).join('.');
      if (labels.length > n && (MULTI_SUFFIX.has(suffix) || SHARED_HOSTING.has(suffix))) return labels.slice(-n - 1).join('.');
    }
    return labels.slice(-2).join('.');
  }

  // Plataforma de alojamiento compartido a la que pertenece el host, o ''.
  function sharedHostOf(host) {
    const suffix = orgDomain(host).split('.').slice(1).join('.');
    return SHARED_HOSTING.has(suffix) ? suffix : '';
  }

  function sameOrg(a, b) {
    return !!a && !!b && orgDomain(a) === orgDomain(b);
  }

  function isIP(s) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || /^\[?[0-9a-f]*:[0-9a-f:.]+\]?$/i.test(s);
  }

  function isPrivateIP(ip) {
    if (/:/.test(ip)) return /^(::1$|fe80:|fc|fd)/i.test(ip);
    const p = ip.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }

  // ---------- fechas ----------

  function parseDate(str) {
    if (!str) return null;
    const clean = str.replace(/\([^)]*\)/g, '').replace(/\s+/g, ' ').trim();
    let d = new Date(clean);
    if (isNaN(d)) d = new Date(clean.replace(/^[A-Za-z]{3},\s*/, ''));
    return isNaN(d) ? null : d;
  }

  // ---------- Received ----------

  function parseReceived(value, index) {
    const semi = value.lastIndexOf(';');
    const main = semi >= 0 ? value.slice(0, semi) : value;
    const dateStr = semi >= 0 ? value.slice(semi + 1).trim() : '';
    const pick = re => { const m = main.match(re); return m ? m[1] : ''; };
    const fromFull = main.match(/\bfrom\s+(\S+)(\s*\([^)]*\))?/i);
    const ips = [];
    const ipRe = /\[(?:IPv6:)?([0-9a-fA-F:.]+)\]|\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;
    const fromPart = fromFull ? fromFull[0] : '';
    let m;
    while ((m = ipRe.exec(fromPart))) {
      const ip = m[1] || m[2];
      if (ip && isIP(ip) && !ips.includes(ip)) ips.push(ip);
    }
    return {
      index,
      raw: value,
      from: fromFull ? fromFull[1] : '',
      fromDetail: fromFull && fromFull[2] ? fromFull[2].trim().replace(/^\(|\)$/g, '') : '',
      by: pick(/\bby\s+(\S+)/i),
      with: pick(/\bwith\s+([A-Za-z0-9-]+)/i),
      id: pick(/\bid\s+<?([^\s;>]+)>?/i),
      for: pick(/\bfor\s+<?([^\s>;]+@[^\s>;]+)>?/i),
      ips,
      date: parseDate(dateStr),
      dateStr,
      tls: /\b(ESMTPS|ESMTPSA|TLS|UTF8SMTPS)\b/i.test(main) || /\bversion=TLS/i.test(value),
    };
  }

  // Salto en que el correo entró en tu proveedor: se baja desde el Received más alto mientras los
  // saltos sean internos del receptor, y el primero que viene de una IP pública de fuera es la
  // entrega. Lo que hay por debajo lo escribió el remitente y puede ser inventado. Si lo reenvía
  // Apple («Ocultar mi correo»), se sigue hasta el salto en que Apple lo recibió.
  function deliveryHop(route, relay) {
    let receiver = null;
    for (const hop of [...route].reverse()) {
      if (!hop.from || !/[a-z]\.[a-z]/i.test(hop.by)) continue;
      const by = providerOf(hop.by);
      if (!receiver) receiver = by;
      if (by !== receiver) return null;
      const fromHost = (hop.fromDetail.match(/^([a-z0-9-]+(?:\.[a-z0-9-]+)+)\.?\s*\[/i) || [])[1] || hop.from;
      const src = providerOf(fromHost);
      if (src === receiver || !hop.ips.some(ip => !isPrivateIP(ip))) continue;
      if (relay && src === 'apple') { receiver = 'apple'; continue; }
      return hop;
    }
    return null;
  }

  function buildRoute(headers) {
    const hops = headers.getAll('received').map(parseReceived);
    // Las cabeceras se añaden arriba: el primer salto real es el último.
    hops.reverse();
    for (let i = 0; i < hops.length; i++) {
      hops[i].hop = i + 1;
      const prev = hops[i - 1];
      hops[i].delay = prev && prev.date && hops[i].date ? (hops[i].date - prev.date) / 1000 : null;
    }
    return hops;
  }

  // ---------- autenticación ----------

  function parseAuthResults(value) {
    const parts = splitTopLevel(value, ';');
    const out = { server: '', results: [] };
    if (!parts.length) return out;
    // El primer token es authserv-id (en ARC va precedido de i=N).
    let first = parts.shift();
    const inst = first.match(/^i=(\d+)$/i);
    if (inst) { out.instance = +inst[1]; first = parts.shift() || ''; }
    // Microsoft omite a veces el authserv-id y empieza directamente por «spf=pass (…)».
    if (/^[a-z0-9._-]+\s*=\s*[a-z]/i.test(first)) parts.unshift(first);
    else out.server = first.split(/\s+/)[0];
    for (const p of parts) {
      const m = p.match(/^([a-z0-9._-]+)\s*=\s*([a-z0-9_-]+)(.*)$/i);
      if (!m) continue;
      const props = {};
      const propRe = /\b([a-z]+\.[a-z0-9_-]+)\s*=\s*("[^"]*"|[^\s;]+)/gi;
      let pm;
      while ((pm = propRe.exec(m[3]))) props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, '');
      const comment = (m[3].match(/\(([^)]*)\)/) || [])[1] || '';
      out.results.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props, comment });
    }
    return out;
  }

  function parseTagList(value) {
    const tags = {};
    value.split(';').forEach(t => {
      const i = t.indexOf('=');
      if (i > 0) tags[t.slice(0, i).trim().toLowerCase()] = t.slice(i + 1).replace(/\s+/g, '').trim();
    });
    return tags;
  }

  // Proveedores cuyo authserv-id no comparte dominio con los servidores que firman sus Received.
  const PROVIDER_ALIASES = {
    'outlook.com': 'microsoft', 'office365.com': 'microsoft', 'microsoft.com': 'microsoft', 'exchangelabs.com': 'microsoft', 'hotmail.com': 'microsoft',
    'google.com': 'google', 'googlemail.com': 'google', 'gmail.com': 'google',
    'icloud.com': 'apple', 'apple.com': 'apple', 'me.com': 'apple',
  };
  const providerOf = host => { const o = orgDomain(String(host || '').replace(/\.$/, '')); return PROVIDER_ALIASES[o] || o; };

  // Cualquiera puede escribir un Authentication-Results al enviar el correo. Sólo cuenta el de un
  // servidor que aparece en la ruta (algún Received «by» suyo) y, de ellos, el más alto, que es el
  // del receptor final; los de más abajo se ignoran para el veredicto (RFC 8601, sección 5).
  function trustedAuthResults(ar, headers) {
    const routeProviders = new Set(headers.getAll('received').map(v => providerOf(parseReceived(v).by)).filter(Boolean));
    ar.forEach(s => { s.inRoute = s.server ? routeProviders.has(providerOf(s.server)) : routeProviders.has('microsoft'); });
    const top = ar.find(s => s.inRoute);
    const trusted = top ? ar.filter(s => s.inRoute && s.server === top.server) : [];
    return { trusted, ignored: ar.filter(s => !trusted.includes(s)) };
  }

  function buildAuth(headers, fromDomain) {
    const allAr = headers.getAll('authentication-results').map(parseAuthResults);
    const { trusted: ar, ignored: ignoredAR } = trustedAuthResults(allAr, headers);
    const arc = headers.getAll('arc-authentication-results').map(parseAuthResults);
    const dkimSigs = headers.getAll('dkim-signature').map(v => {
      const t = parseTagList(v);
      return { domain: (t.d || '').toLowerCase(), selector: t.s || '', algorithm: t.a || '', headers: t.h || '', aligned: sameOrg(t.d, fromDomain) };
    });
    const receivedSpf = headers.get('received-spf');

    // Sólo los del receptor final (ver trustedAuthResults).
    const pickResult = (method) => {
      for (const set of ar) {
        const r = set.results.find(x => x.method === method);
        if (r) return Object.assign({ server: set.server }, r);
      }
      return null;
    };
    let spf = pickResult('spf');
    if (!spf && receivedSpf) {
      const m = receivedSpf.match(/^\s*([a-z]+)/i);
      if (m) spf = { method: 'spf', result: m[1].toLowerCase(), props: {}, comment: receivedSpf, server: 'Received-SPF' };
    }
    const dkimAll = [];
    for (const set of ar) set.results.filter(x => x.method === 'dkim').forEach(r => dkimAll.push(Object.assign({ server: set.server }, r)));
    const dkim = dkimAll.find(r => r.result === 'pass') || dkimAll[0] || null;
    const dmarc = pickResult('dmarc');
    const compauth = pickResult('compauth');
    const arcRes = pickResult('arc');

    // authResults: todos (se muestran y los usa el reenvío de Apple); trustedResults: los que cuentan.
    return { spf, dkim, dkimAll, dmarc, compauth, arc: arcRes, dkimSigs, authResults: allAr, trustedResults: ar, ignoredResults: ignoredAR, arcResults: arc, receivedSpf };
  }

  // ---------- servicios que ocultan tu dirección ----------

  // «Ocultar mi correo» de Apple reenvía a tu buzón lo que llega a un alias y reescribe el From
  // (hello@hinge.co → hello_at_hinge_co_<alias>_<hash>@privaterelay.appleid.com). SPF, DKIM y DMARC
  // del receptor son entonces los de Apple; la autenticación del remitente real es la que Apple
  // comprobó al recibirlo y deja en sus propias cabeceras (dkim-verifier.icloud.com, spf.icloud.com).
  const APPLE_RELAY = 'privaterelay.appleid.com';

  function decodeAppleRelay(address) {
    const m = String(address || '').toLowerCase().match(/^(.+?)_at_(.+)_[a-z0-9]+_[0-9a-f]{8}@privaterelay\.appleid\.com$/);
    if (!m) return '';
    const domain = m[2].replace(/_/g, '.');
    return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain) ? m[1] + '@' + domain : '';
  }

  function detectRelay(from, replyTo, auth) {
    const original = decodeAppleRelay(from.address);
    if (!original) return null;
    // Sólo si el receptor confirma que el correo salió de Apple: si no, cualquiera podría imitar el formato.
    const arDomain = r => String(r.props['header.d'] || r.props['header.i'] || '').replace(/^.*@/, '').toLowerCase();
    const dmarc = auth.dmarc ? auth.dmarc.result : 'none';
    const viaApple = dmarc !== 'fail' && ((dmarc === 'pass' && sameOrg(auth.dmarc.props['header.from'], APPLE_RELAY)) ||
      auth.dkimAll.some(r => r.result === 'pass' && arDomain(r) === APPLE_RELAY));
    if (!viaApple) return null;
    const inner = auth.authResults.filter(s => /\.icloud\.com$/i.test(s.server));
    const dkim = [].concat(...inner.map(s => s.results.filter(r => r.method === 'dkim')))
      .map(r => ({ domain: arDomain(r), result: r.result }));
    const spfR = [].concat(...inner.map(s => s.results.filter(r => r.method === 'spf')))[0];
    const mailfrom = spfR ? String(spfR.props['smtp.mailfrom'] || '') : '';
    const spf = spfR ? { result: spfR.result, domain: mailfrom.includes('@') ? domainOf(mailfrom) : mailfrom.toLowerCase() } : null;
    const domain = domainOf(original);
    const alignedDkim = dkim.filter(r => r.result === 'pass' && sameOrg(r.domain, domain));
    const alignedSpf = !!(spf && spf.result === 'pass' && sameOrg(spf.domain, domain));
    return {
      service: 'Ocultar mi correo de Apple', relayDomain: APPLE_RELAY,
      original: { name: from.name, address: original }, domain,
      replyTo: replyTo.map(r => ({ name: r.name, address: decodeAppleRelay(r.address) || r.address })),
      dkim, spf, mailfrom, alignedDkim: alignedDkim.map(r => r.domain), alignedSpf,
      authenticated: alignedDkim.length > 0 || alignedSpf,
    };
  }

  // ---------- enlaces ----------

  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 'bl.ink', 'lnkd.in', 's.id', 'v.gd', 'qrco.de', 'shorturl.com', 'u.to']);
  const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'click', 'link', 'work', 'support', 'gq', 'ml', 'cf', 'tk', 'ga',
    'country', 'kim', 'rest', 'fit', 'cam', 'monster', 'icu', 'buzz', 'sbs', 'cfd', 'lol', 'quest', 'bond']);

  // Plataformas de envío y rutas típicas de sus enlaces de seguimiento.
  const TRACKER_DOMAINS = new Set(['list-manage.com', 'mailchi.mp', 'sendgrid.net', 'mandrillapp.com', 'sparkpostmail.com', 'mailgun.org', 'rs6.net',
    'awstrack.me', 'exacttarget.com', 'hubspotlinks.com', 'hs-sites.com', 'klclick.com', 'klclick1.com', 'customeriomail.com', 'emlmkt.com', 'mjt.lu',
    'sendibt3.com', 'sendibm1.com', 'mailjet.com', 'cmail19.com', 'cmail20.com', 'createsend.com', 'acemlna.com', 'acemlnb.com', 'mkt.com', 'mktossl.com',
    'mailerlite.com', 'mlsend.com', 'e.linkedin.com', 'salesforce.com', 'sfmc-content.com', 'pardot.com', 'go.pardot.com', 'braze.com', 'iterable.com',
    'links.iterable.com', 'ct.sendgrid.net', 'email.mg', 'mailtrack.io', 'elasticemail.com', 'getresponse.com', 'gr8.com', 'constantcontact.com']);
  const TRACKING_PATH = /\/(url|click|clicks|c|l|ls|r|redirect|track|tracking|trk|wf\/click|link|links|e|ct|mk|ss\/c|f\/a)\//i;

  const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"'()\[\]{}]+[^\s<>"'()\[\]{}.,;:!?]/gi;

  function safeURL(href) {
    try { return new URL(href.startsWith('www.') ? 'http://' + href : href); } catch (_) { return null; }
  }

  function analyzeURL(href, text) {
    const u = safeURL(href);
    const info = { href, text: (text || '').trim(), host: '', scheme: '', flags: [] };
    if (!u) { info.flags.push({ sev: 'low', msg: 'URL no válida' }); return info; }
    info.scheme = u.protocol.replace(':', '');
    info.host = u.hostname.toLowerCase();
    if (info.scheme === 'javascript' || info.scheme === 'data' || info.scheme === 'vbscript') {
      info.flags.push({ sev: 'high', msg: `Esquema peligroso (${info.scheme}:)` });
    }
    if (info.scheme === 'http') info.flags.push({ sev: 'low', msg: 'Sin cifrar (http)' });
    if (isIP(info.host.replace(/^\[|\]$/g, ''))) info.flags.push({ sev: 'high', msg: 'Apunta a una IP directa' });
    if (/(^|\.)xn--/.test(info.host)) info.flags.push({ sev: 'medium', msg: 'Dominio punycode (posible homógrafo)' });
    if (SHORTENERS.has(info.host)) info.flags.push({ sev: 'low', msg: 'Acortador de URL' });
    const tld = info.host.split('.').pop();
    if (SUSPICIOUS_TLDS.has(tld)) info.flags.push({ sev: 'medium', msg: `TLD de uso frecuente en abuso (.${tld})` });
    if (u.username || /@/.test(u.host)) info.flags.push({ sev: 'high', msg: 'Contiene credenciales/@ antes del host' });
    if (info.host.split('.').length > 5) info.flags.push({ sev: 'low', msg: 'Muchos subdominios' });
    if (/(login|signin|verify|account|secure|update|webscr|banking|password|confirm)/i.test(u.pathname + info.host) &&
        !info.flags.length) info.flags.push({ sev: 'info', msg: 'Palabras típicas de login en la URL' });

    // El texto visible muestra otra URL/dominio distinto al destino real.
    const shown = info.text.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/:?#]|$)/i);
    if (shown && info.host && /\./.test(info.text) && !/\s/.test(info.text.trim())) {
      const shownHost = shown[1].toLowerCase();
      if (!sameOrg(shownHost, info.host)) {
        info.flags.push({ sev: 'high', msg: `El texto muestra "${shownHost}" pero lleva a "${info.host}"` });
        info.mismatch = true;
      }
    }
    return info;
  }

  function extractLinks(email) {
    const links = [];
    const seen = new Set();
    const html = { forms: [], scripts: 0, iframes: 0, remoteImages: [], trackingPixels: 0, metaRefresh: '', base: '', hiddenText: false };

    if (email.html && typeof DOMParser !== 'undefined') {
      const doc = new DOMParser().parseFromString(email.html, 'text/html');
      doc.querySelectorAll('a[href], area[href]').forEach(a => {
        const href = a.getAttribute('href').trim();
        if (!href || href.startsWith('#') || /^mailto:|^tel:|^cid:/i.test(href)) return;
        const key = href + '|' + a.textContent.trim();
        if (seen.has(key)) return;
        seen.add(key);
        links.push(Object.assign(analyzeURL(href, a.textContent.replace(/\s+/g, ' ')), { source: 'html' }));
      });
      doc.querySelectorAll('form').forEach(f => html.forms.push({
        action: f.getAttribute('action') || '(sin action)',
        method: (f.getAttribute('method') || 'get').toLowerCase(),
        password: !!f.querySelector('input[type=password]'),
        inputs: f.querySelectorAll('input').length,
      }));
      html.scripts = doc.querySelectorAll('script').length +
        [...doc.querySelectorAll('*')].filter(el => [...el.attributes].some(at => /^on/i.test(at.name))).length;
      html.iframes = doc.querySelectorAll('iframe, frame, object, embed').length;
      doc.querySelectorAll('img[src]').forEach(img => {
        const src = img.getAttribute('src');
        if (/^https?:/i.test(src)) {
          html.remoteImages.push(src);
          const w = img.getAttribute('width'), h = img.getAttribute('height');
          if ((w === '1' || w === '0') && (h === '1' || h === '0')) html.trackingPixels++;
        }
      });
      const meta = doc.querySelector('meta[http-equiv="refresh" i]');
      if (meta) html.metaRefresh = meta.getAttribute('content') || '';
      const base = doc.querySelector('base[href]');
      if (base) html.base = base.getAttribute('href');
      html.hiddenTextLen = [...doc.querySelectorAll('[style]')]
        .filter(el => /display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|max-height\s*:\s*0/i.test(el.getAttribute('style')))
        .filter(el => !el.parentElement || !el.parentElement.closest('[style*="none" i]'))
        .reduce((n, el) => n + el.textContent.replace(/[\s\u200b-\u200d\u034f\u00ad\ufeff]+/g, ' ').trim().length, 0);
      html.hiddenText = html.hiddenTextLen > 40;
    }

    const plain = email.text || '';
    let m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(plain))) {
      const href = m[0];
      if ([...seen].some(k => k.startsWith(href + '|'))) continue;
      seen.add(href + '|');
      links.push(Object.assign(analyzeURL(href, ''), { source: 'texto' }));
    }
    return { links, html };
  }

  // ---------- adjuntos ----------

  const DANGEROUS_EXT = new Set(['exe', 'scr', 'pif', 'com', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta',
    'msi', 'msp', 'cpl', 'jar', 'ps1', 'psm1', 'lnk', 'reg', 'dll', 'iso', 'img', 'vhd', 'vhdx', 'appx', 'msix',
    'application', 'gadget', 'inf', 'scf', 'url', 'xll', 'chm', 'one', 'library-ms', 'settingcontent-ms', 'sh', 'apk', 'dmg', 'pkg']);
  const MACRO_EXT = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm', 'xlsb']);
  const LEGACY_OFFICE = new Set(['doc', 'xls', 'ppt', 'rtf']);
  const ARCHIVE_EXT = new Set(['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'bz2', 'xz', 'cab', 'ace', 'arj', 'lzh', 'z']);
  const WEB_EXT = new Set(['html', 'htm', 'shtml', 'xhtml', 'svg', 'mht', 'mhtml']);
  const DOC_EXT = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'odt', 'ods', 'rtf', 'csv']);

  function sniff(bytes) {
    const b = bytes;
    const s = (n) => MIME.bytesToBinary(b.subarray(0, n));
    if (b.length < 4) return '';
    if (b[0] === 0x4d && b[1] === 0x5a) return 'Ejecutable Windows (PE/MZ)';
    if (b[0] === 0x7f && s(4) === '\x7fELF') return 'Ejecutable ELF';
    if (s(4) === '%PDF') return 'PDF';
    if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return 'ZIP/OOXML';
    if (b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0) return 'OLE2 (Office antiguo/MSG)';
    if (s(4) === 'Rar!') return 'RAR';
    if (b[0] === 0x37 && b[1] === 0x7a && b[2] === 0xbc && b[3] === 0xaf) return '7-Zip';
    if (b[0] === 0x1f && b[1] === 0x8b) return 'GZIP';
    if (b[0] === 0x89 && s(4) === '\x89PNG') return 'PNG';
    if (b[0] === 0xff && b[1] === 0xd8) return 'JPEG';
    if (s(4) === 'GIF8') return 'GIF';
    if (s(5) === '{\\rtf') return 'RTF';
    if (b[0] === 0x4c && b[1] === 0x00 && b[2] === 0x00 && b[3] === 0x00) return 'Acceso directo (LNK)';
    if (b.length > 0x8006 && MIME.bytesToBinary(b.subarray(0x8001, 0x8006)) === 'CD001') return 'Imagen ISO';
    if (b[0] === 0x78 && b[1] === 0x9f && b[2] === 0x3e && b[3] === 0x22) return 'TNEF (winmail.dat)';
    const head = s(512).toLowerCase();
    if (/<(html|script|!doctype html|svg|body|iframe)/.test(head)) return 'HTML/SVG';
    return '';
  }

  // Nombres y cifrado de un ZIP. La lista completa está en el directorio central, al final del
  // fichero; las cabeceras locales no bastan (con data descriptor no se sabe dónde empieza la
  // siguiente) y se usan sólo si el ZIP está truncado. Si ambas discrepan, alguien las manipuló
  // para que el antivirus y el descompresor vean ficheros distintos.
  function zipInfo(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const nameAt = (o, len, flags) => MIME.decodeBytes(bytes.subarray(o, o + len), flags & 0x800 ? 'utf-8' : '');

    const local = [];
    let encrypted = false;
    for (let i = 0; i + 30 <= bytes.length && local.length < 200;) {
      if (dv.getUint32(i, true) !== 0x04034b50) break;
      const flags = dv.getUint16(i + 6, true);
      const compSize = dv.getUint32(i + 18, true);
      const nameLen = dv.getUint16(i + 26, true);
      if (flags & 1) encrypted = true;
      local.push(nameAt(i + 30, nameLen, flags));
      if (flags & 8 && compSize === 0) break; // tamaño en data descriptor
      i += 30 + nameLen + dv.getUint16(i + 28, true) + compSize;
    }

    let central = null;
    for (let e = bytes.length - 22; e >= Math.max(0, bytes.length - 22 - 65535); e--) {
      if (dv.getUint32(e, true) !== 0x06054b50) continue;
      const count = dv.getUint16(e + 10, true);
      let o = dv.getUint32(e + 16, true);
      central = [];
      while (o + 46 <= bytes.length && central.length < Math.min(count, 1000) && dv.getUint32(o, true) === 0x02014b50) {
        const flags = dv.getUint16(o + 8, true);
        const nameLen = dv.getUint16(o + 28, true);
        if (flags & 1) encrypted = true;
        central.push(nameAt(o + 46, nameLen, flags));
        o += 46 + nameLen + dv.getUint16(o + 30, true) + dv.getUint16(o + 32, true);
      }
      if (!central.length) central = null;
      break;
    }

    const names = central || local;
    const mismatch = !!central && local.some((n, k) => n !== central[k]);
    return { names: names.slice(0, 200), total: names.length, encrypted, mismatch };
  }

  // Analiza el contenido de un adjunto HTML/SVG: formularios, destinos, ofuscación y exfiltración.
  function inspectHtmlAttachment(text) {
    const out = { forms: [], urls: [], obfuscation: [], exfil: [], password: false, decoded: [] };
    const formRe = /<form\b[^>]*>/gi;
    let m;
    while ((m = formRe.exec(text))) {
      const action = (m[0].match(/\baction\s*=\s*["']?([^"'\s>]+)/i) || [])[1] || '(sin action)';
      out.forms.push(action);
    }
    out.password = /<input\b[^>]*type\s*=\s*["']?password/i.test(text);
    const OBF = [[/\batob\s*\(/i, 'atob()'], [/\bunescape\s*\(/i, 'unescape()'], [/\beval\s*\(/i, 'eval()'], [/String\.fromCharCode/i, 'String.fromCharCode'],
      [/document\.write\s*\(/i, 'document.write()'], [/(\\x[0-9a-f]{2}){6,}/i, 'cadenas \\x hexadecimales'], [/(%[0-9a-f]{2}){12,}/i, 'cadenas %XX codificadas'],
      [/[A-Za-z0-9+/]{400,}={0,2}/, 'bloques base64 largos']];
    OBF.forEach(([re, label]) => { if (re.test(text)) out.obfuscation.push(label); });
    const EXF = [[/api\.telegram\.org\/bot/i, 'bot de Telegram'], [/discord(app)?\.com\/api\/webhooks/i, 'webhook de Discord'], [/\bfetch\s*\(/i, 'fetch()'],
      [/XMLHttpRequest/i, 'XMLHttpRequest'], [/\$\.(ajax|post)\s*\(/i, 'jQuery ajax/post'], [/\.submit\s*\(\s*\)/i, 'envío automático de formulario']];
    EXF.forEach(([re, label]) => { if (re.test(text)) out.exfil.push(label); });
    // Decodifica una capa de atob("...") para encontrar URLs ocultas.
    const atobRe = /atob\s*\(\s*["'`]([A-Za-z0-9+/=_-]{8,})["'`]\s*\)/g;
    while ((m = atobRe.exec(text)) && out.decoded.length < 20) {
      try { out.decoded.push(atob(m[1].replace(/-/g, '+').replace(/_/g, '/'))); } catch (_) { /* no es base64 */ }
    }
    const urls = new Set();
    const scan = t => { URL_RE.lastIndex = 0; let u; while ((u = URL_RE.exec(t)) && urls.size < 60) urls.add(u[0]); };
    scan(text);
    out.decoded.forEach(scan);
    const loc = /(?:window\.)?location(?:\.href)?\s*=\s*["'`]([^"'`]+)["'`]|location\.(?:replace|assign)\s*\(\s*["'`]([^"'`]+)/gi;
    while ((m = loc.exec(text))) { const u = m[1] || m[2]; if (/^https?:|^\/\//i.test(u)) urls.add(u.replace(/^\/\//, 'https://')); }
    out.forms.filter(a => /^https?:/i.test(a)).forEach(a => urls.add(a));
    out.urls = [...urls];
    return out;
  }

  function fileExt(name) {
    const m = String(name || '').toLowerCase().match(/\.([a-z0-9-]+)$/);
    return m ? m[1] : '';
  }

  function analyzeAttachment(node, idx) {
    const bytes = MIME.getBytes(node);
    const name = node.filename || (node.isEmbeddedMessage ? (node.children[0] && node.children[0].headers.get('subject') || 'mensaje') + '.eml' : `adjunto-${idx + 1}`);
    const ext = fileExt(name);
    const magic = sniff(bytes);
    const flags = [];
    const exts = name.toLowerCase().split('.').slice(1);

    if (/[‪-‮⁦-⁩]/.test(name)) flags.push({ sev: 'high', msg: 'Nombre con caracteres de control RTL (oculta la extensión real)' });
    if (DANGEROUS_EXT.has(ext)) flags.push({ sev: 'high', msg: `Extensión ejecutable/peligrosa (.${ext})` });
    if (MACRO_EXT.has(ext)) flags.push({ sev: 'high', msg: `Documento Office con macros (.${ext})` });
    if (WEB_EXT.has(ext)) flags.push({ sev: 'high', msg: `Adjunto HTML/SVG (técnica habitual de phishing de credenciales)` });
    if (ARCHIVE_EXT.has(ext)) flags.push({ sev: 'medium', msg: `Archivo comprimido (.${ext})` });
    if (LEGACY_OFFICE.has(ext)) flags.push({ sev: 'low', msg: `Formato Office antiguo (.${ext}), puede contener macros` });
    if (exts.length >= 2 && DOC_EXT.has(exts[exts.length - 2]) && (DANGEROUS_EXT.has(ext) || WEB_EXT.has(ext) || ARCHIVE_EXT.has(ext))) {
      flags.push({ sev: 'high', msg: 'Doble extensión (' + exts.slice(-2).map(e => '.' + e).join('') + ')' });
    }
    if (/\s{5,}\./.test(name)) flags.push({ sev: 'high', msg: 'Espacios de relleno antes de la extensión' });
    if (magic === 'Ejecutable Windows (PE/MZ)' && ext !== 'exe' && ext !== 'dll') flags.push({ sev: 'high', msg: 'Contenido ejecutable disfrazado de .' + (ext || 'sin extensión') });
    if (magic === 'HTML/SVG' && !WEB_EXT.has(ext) && ext !== 'txt') flags.push({ sev: 'high', msg: 'Contiene HTML/SVG aunque la extensión es .' + (ext || '—') });
    if (magic === 'PDF' && ext && ext !== 'pdf') flags.push({ sev: 'medium', msg: 'Es un PDF con otra extensión' });
    if (magic === 'Imagen ISO' || magic === 'Acceso directo (LNK)') flags.push({ sev: 'high', msg: magic });
    if (ext === 'pdf' && magic && magic !== 'PDF') flags.push({ sev: 'high', msg: `Dice ser PDF pero es ${magic}` });

    let zip = null;
    if (magic === 'ZIP/OOXML') {
      zip = zipInfo(bytes);
      if (zip.encrypted) flags.push({ sev: 'high', msg: 'ZIP protegido con contraseña (evita el escaneo antivirus)' });
      if (zip.mismatch) flags.push({ sev: 'high', msg: 'ZIP manipulado: los nombres del directorio central no coinciden con los de los ficheros' });
      const inner = zip.names.filter(n => DANGEROUS_EXT.has(fileExt(n)) || WEB_EXT.has(fileExt(n)) || MACRO_EXT.has(fileExt(n)));
      if (inner.length) flags.push({ sev: 'high', msg: 'Contiene: ' + inner.slice(0, 5).join(', ') });
      if (zip.names.some(n => /^xl\/vbaProject|^word\/vbaProject|vbaProject\.bin$/i.test(n))) flags.push({ sev: 'high', msg: 'Documento Office con proyecto VBA (macros)' });
      if (!ARCHIVE_EXT.has(ext) && !/^(docx|xlsx|pptx|docm|xlsm|pptm|odt|ods|odp|jar|apk|epub|xps|oxps|vsdx)$/.test(ext)) {
        flags.push({ sev: 'medium', msg: 'Contenido ZIP con extensión .' + (ext || '—') });
      }
    }
    if (magic === 'PDF') {
      const head = MIME.bytesToBinary(bytes.subarray(0, Math.min(bytes.length, 2 * 1024 * 1024)));
      if (/\/JavaScript|\/JS\s*[(<]/.test(head)) flags.push({ sev: 'high', msg: 'PDF con JavaScript embebido' });
      if (/\/OpenAction|\/AA\s*<</.test(head)) flags.push({ sev: 'medium', msg: 'PDF con acción automática al abrir' });
      if (/\/Launch/.test(head)) flags.push({ sev: 'high', msg: 'PDF con acción /Launch' });
      if (/\/EmbeddedFile/.test(head)) flags.push({ sev: 'medium', msg: 'PDF con ficheros embebidos' });
      const uris = (head.match(/\/URI\s*\(([^)]+)\)/g) || []).length;
      if (uris) flags.push({ sev: 'info', msg: `PDF con ${plural(uris, 'enlace', 'enlaces')}` });
    }
    if (magic === 'TNEF (winmail.dat)') flags.push({ sev: 'info', msg: 'Contenedor TNEF de Outlook' });

    let htmlInfo = null;
    if (WEB_EXT.has(ext) || magic === 'HTML/SVG') {
      htmlInfo = inspectHtmlAttachment(MIME.decodeBytes(bytes.subarray(0, 3 * 1024 * 1024)));
      if (htmlInfo.forms.length) flags.push({ sev: 'high', msg: `Formulario que envía datos a ${htmlInfo.forms.slice(0, 2).join(', ')}${htmlInfo.password ? ' (pide contraseña)' : ''}` });
      else if (htmlInfo.password) flags.push({ sev: 'high', msg: 'Pide una contraseña' });
      if (htmlInfo.exfil.length) flags.push({ sev: /Telegram|Discord/.test(htmlInfo.exfil.join()) ? 'high' : 'medium', msg: 'Envía datos a terceros: ' + htmlInfo.exfil.join(', ') });
      if (htmlInfo.obfuscation.length) flags.push({ sev: 'medium', msg: 'Código ofuscado: ' + htmlInfo.obfuscation.join(', ') });
      if (htmlInfo.decoded.length) flags.push({ sev: 'medium', msg: `${plural(htmlInfo.decoded.length, 'cadena oculta', 'cadenas ocultas')} con atob()` });
    }

    return {
      node,
      name,
      ext,
      contentType: node.contentType,
      size: bytes.length,
      magic,
      inline: node.disposition === 'inline' || (!!node.contentId && node.disposition !== 'attachment'),
      contentId: node.contentId,
      isEmail: !!node.isEmbeddedMessage || ext === 'eml' || ext === 'msg',
      zip,
      html: htmlInfo,
      flags,
      sha256: '',
      sha1: '',
    };
  }

  async function hashAttachments(attachments) {
    if (!global.crypto || !crypto.subtle) return;
    const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    await Promise.all(attachments.map(async a => {
      const bytes = MIME.getBytes(a.node);
      a.sha256 = hex(await crypto.subtle.digest('SHA-256', bytes));
      a.sha1 = hex(await crypto.subtle.digest('SHA-1', bytes));
    }));
  }

  // ---------- contenido ----------

  const LURE_PATTERNS = [
    [/urgente|inmediat[oa]|lo antes posible|últim[oa] aviso|hoy mismo|24 horas|48 horas/i, 'Urgencia'],
    [/urgent|immediately|final notice|within 24 hours|act now|as soon as possible/i, 'Urgencia'],
    [/(verifi|confirm|actualiz|valid)\w* (su|tu|sus|tus)? ?(cuenta|identidad|datos|contraseña|información)/i, 'Solicitud de verificación de cuenta'],
    [/verify (your )?(account|identity)|confirm your (account|password|details)|update your (payment|billing)/i, 'Solicitud de verificación de cuenta'],
    [/(cuenta|tarjeta|acceso) (ha sido |será )?(suspendid|bloquead|restringid|desactivad)/i, 'Amenaza de bloqueo'],
    [/account (has been |will be )?(suspended|locked|disabled|restricted)|unusual (sign-in|activity)/i, 'Amenaza de bloqueo'],
    [/contraseña|password|pin\b|código de verificación|credenciales|clave de acceso/i, 'Mención de credenciales'],
    [/(factura pendiente|pago pendiente|reembolso|devolución|premio|ha ganado|herencia|transferencia|bitcoin|criptomoneda)/i, 'Dinero / pagos'],
    [/invoice|payment (due|failed|pending)|refund|wire transfer|gift card|you (have )?won|lottery|inheritance/i, 'Dinero / pagos'],
    [/paquete|envío retenido|aduanas|entrega fallida|delivery (failed|attempt)|parcel|customs fee/i, 'Paquetería'],
    [/haga clic|pulse aquí|haz clic|click here|click below|pinche aquí/i, 'Llamada a hacer clic'],
    [/hacienda|agencia tributaria|seguridad social|dgt\b|multa|policía|tax refund|irs\b/i, 'Suplantación institucional'],
  ];

  const BRANDS = ['paypal', 'microsoft', 'office365', 'outlook', 'apple', 'icloud', 'amazon', 'netflix', 'google', 'gmail',
    'facebook', 'instagram', 'whatsapp', 'linkedin', 'dhl', 'fedex', 'ups', 'correos', 'seur', 'santander', 'bbva',
    'caixabank', 'bankinter', 'sabadell', 'ing', 'openbank', 'unicaja', 'kutxabank', 'ibercaja', 'abanca', 'evo',
    'agencia tributaria', 'hacienda', 'aeat', 'seguridad social', 'dgt', 'endesa', 'iberdrola', 'naturgy', 'movistar',
    'vodafone', 'orange', 'docusign', 'dropbox', 'wetransfer', 'adobe', 'binance', 'coinbase', 'spotify', 'mercadolibre',
    'bizum', 'visa', 'mastercard', 'american express'];

  // Proveedores de correo gratuito: cualquiera puede abrir una cuenta, así que su DMARC no dice nada del remitente.
  const FREEMAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'outlook.es', 'hotmail.com', 'hotmail.es', 'live.com', 'live.es', 'msn.com',
    'yahoo.com', 'yahoo.es', 'ymail.com', 'icloud.com', 'me.com', 'mac.com', 'aol.com', 'gmx.com', 'gmx.es', 'gmx.net', 'gmx.de', 'mail.com',
    'proton.me', 'protonmail.com', 'pm.me', 'zoho.com', 'yandex.com', 'yandex.ru', 'mail.ru', 'tutanota.com', 'tuta.io', 'web.de', 'libero.it',
    'wp.pl', 'o2.pl', 'onet.pl', 'interia.pl', 'orange.fr', 'laposte.net', 'free.fr', 'qq.com', '163.com', '126.com', 'naver.com']);

  function findLures(text) {
    const hits = new Map();
    for (const [re, label] of LURE_PATTERNS) {
      const m = text.match(re);
      if (m && !hits.has(label)) hits.set(label, m[0]);
    }
    return [...hits.entries()].map(([label, sample]) => ({ label, sample }));
  }

  function htmlToText(html) {
    if (!html) return '';
    if (typeof DOMParser === 'undefined') return html.replace(/<[^>]+>/g, ' ');
    const doc = new DOMParser().parseFromString(html, 'text/html');
    doc.querySelectorAll('script,style,head,title').forEach(n => n.remove());
    doc.querySelectorAll('br').forEach(n => n.replaceWith('\n'));
    doc.querySelectorAll('p,div,tr,li,h1,h2,h3,h4,h5,h6,table').forEach(n => n.append('\n'));
    return (doc.body ? doc.body.textContent : '').replace(/[ \t ]+/g, ' ').replace(/\n\s*\n\s*\n+/g, '\n\n').trim();
  }

  // ---------- dominios parecidos a marcas ----------

  // Dominios oficiales conocidos por marca (se comparan por dominio registrable).
  const BRAND_DOMAINS = {
    paypal: ['paypal.com', 'paypal.es', 'paypal.me', 'paypalobjects.com'],
    microsoft: ['microsoft.com', 'microsoftonline.com', 'office.com', 'live.com', 'outlook.com', 'office365.com', 'sharepoint.com'],
    apple: ['apple.com', 'icloud.com', 'appleid.com', 'me.com', 'mac.com'], amazon: ['amazon.com', 'amazon.es', 'amazonaws.com', 'amazon.co.uk', 'amazon.de'], netflix: ['netflix.com'],
    google: ['google.com', 'google.es', 'gmail.com', 'googleusercontent.com', 'youtube.com'], facebook: ['facebook.com', 'fb.com', 'facebookmail.com'],
    instagram: ['instagram.com'], whatsapp: ['whatsapp.com', 'whatsapp.net'], linkedin: ['linkedin.com'], docusign: ['docusign.com', 'docusign.net'],
    dropbox: ['dropbox.com'], wetransfer: ['wetransfer.com'], adobe: ['adobe.com'], binance: ['binance.com'], coinbase: ['coinbase.com'], spotify: ['spotify.com'],
    correos: ['correos.es', 'correos.com'], santander: ['santander.es', 'bancosantander.es', 'santander.com', 'gruposantander.com'], bbva: ['bbva.es', 'bbva.com'],
    caixabank: ['caixabank.es', 'caixabank.com', 'lacaixa.es'], bankinter: ['bankinter.com', 'bankinter.es'], sabadell: ['bancsabadell.com', 'sabadell.com'],
    openbank: ['openbank.es', 'openbank.com'], unicaja: ['unicajabanco.es', 'unicaja.es'], kutxabank: ['kutxabank.es'], ibercaja: ['ibercaja.es'], abanca: ['abanca.com'],
    endesa: ['endesa.com', 'endesa.es'], iberdrola: ['iberdrola.es', 'iberdrola.com'], naturgy: ['naturgy.es', 'naturgy.com'], movistar: ['movistar.es', 'telefonica.com'],
    vodafone: ['vodafone.es', 'vodafone.com'], orange: ['orange.es', 'orange.com'], fedex: ['fedex.com'], mercadolibre: ['mercadolibre.com'],
    agenciatributaria: ['agenciatributaria.es', 'agenciatributaria.gob.es'], mastercard: ['mastercard.com', 'mastercard.es'],
    dgt: ['dgt.es', 'dgt.gob.es'], aeat: ['agenciatributaria.gob.es', 'aeat.es'], hacienda: ['hacienda.gob.es', 'agenciatributaria.gob.es'],
    dhl: ['dhl.com', 'dhl.es', 'dhl.de'], ups: ['ups.com'], seur: ['seur.com'], bizum: ['bizum.es'], ing: ['ing.es', 'ing.com'], visa: ['visa.com', 'visa.es'],
  };
  const OFFICIAL = new Set([].concat(...Object.values(BRAND_DOMAINS)));
  const CONFUSABLE = [[/rn/g, 'm'], [/vv/g, 'w'], [/0/g, 'o'], [/1/g, 'l'], [/3/g, 'e'], [/4/g, 'a'], [/5/g, 's'], [/7/g, 't'], [/8/g, 'b']];

  // Distancia de Damerau-Levenshtein (con transposiciones).
  function editDistance(a, b) {
    if (Math.abs(a.length - b.length) > 2) return 9;
    const d = [];
    for (let i = 0; i <= a.length; i++) d[i] = [i];
    for (let j = 0; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
    return d[a.length][b.length];
  }

  // Devuelve {brand, kind, detail} si el host parece imitar una marca conocida.
  function lookalike(host) {
    host = String(host || '').toLowerCase();
    if (!host || isIP(host)) return null;
    const org = orgDomain(host);
    if (OFFICIAL.has(org)) return null;
    const label = org.split('.')[0];
    const norm = CONFUSABLE.reduce((s, [re, r]) => s.replace(re, r), label);
    const tokens = label.split('-');
    const sub = host.length > org.length ? host.slice(0, host.length - org.length - 1).split(/[.-]/) : [];
    for (const [brand, official] of Object.entries(BRAND_DOMAINS)) {
      if (label === brand) return { brand, kind: 'tld', detail: `usa el nombre de ${brand} con un dominio no oficial (${org}); los oficiales son ${official.join(', ')}` };
      if (norm === brand) return { brand, kind: 'homoglyph', detail: `sustituye caracteres para imitar a ${brand} (${label})` };
      if (brand.length >= 5 && editDistance(label, brand) === 1) return { brand, kind: 'typo', detail: `difiere en un carácter de ${brand} (${label})` };
      if ((brand.length >= 5 && label.includes(brand)) || tokens.includes(brand)) return { brand, kind: 'combo', detail: `incluye la marca ${brand} en un dominio ajeno (${org})` };
      if (sub.includes(brand)) return { brand, kind: 'subdomain', detail: `pone ${brand} en el subdominio de ${org}` };
    }
    return null;
  }

  // ---------- veredictos antispam de los servidores ----------

  const MS_CAT = { PHSH: 'Phishing', HPHSH: 'Phishing de alta confianza', MALW: 'Malware', SPM: 'Spam', HSPM: 'Spam de alta confianza', BULK: 'Masivo',
    SPOOF: 'Suplantación', DIMP: 'Suplantación de dominio', UIMP: 'Suplantación de usuario', GIMP: 'Suplantación (inteligencia de buzón)', AMP: 'Antimalware',
    NONE: 'Ninguna', OSPM: 'Spam saliente', INTOS: 'Intraorganización' };

  function parseAntispam(h) {
    const out = [];
    const add = (source, label, value, sev) => out.push({ source, label, value, sev });
    const ms = h.get('x-forefront-antispam-report');
    if (ms) {
      const t = {};
      ms.split(';').forEach(p => { const i = p.indexOf(':'); if (i > 0) t[p.slice(0, i).trim().toUpperCase()] = p.slice(i + 1).trim(); });
      if (t.CAT) add('Microsoft 365', 'Categoría (CAT)', `${t.CAT} — ${MS_CAT[t.CAT] || '?'}`, /PHSH|MALW|SPOOF|IMP/.test(t.CAT) ? 'high' : /SPM/.test(t.CAT) ? 'medium' : t.CAT === 'BULK' ? 'low' : 'info');
      if (t.SCL !== undefined) add('Microsoft 365', 'Nivel de spam (SCL)', t.SCL, +t.SCL >= 5 ? 'medium' : +t.SCL === -1 ? 'info' : 'ok');
      if (t.SFV) add('Microsoft 365', 'Veredicto del filtro (SFV)', t.SFV, t.SFV === 'SPM' ? 'medium' : 'info');
      if (t.CTRY) add('Microsoft 365', 'País de la IP (CTRY)', t.CTRY, 'info');
      if (t.CIP) add('Microsoft 365', 'IP de conexión (CIP)', t.CIP, 'info');
      if (t.LANG) add('Microsoft 365', 'Idioma (LANG)', t.LANG, 'info');
      if (t.PTR) add('Microsoft 365', 'PTR', t.PTR, 'info');
    }
    const scl = h.get('x-ms-exchange-organization-scl');
    const sclSev = v => +v >= 7 ? 'high' : +v >= 5 ? 'medium' : 'info';
    if (scl && !ms) add('Microsoft Exchange', 'Nivel de spam (SCL)', `${scl}${+scl >= 7 ? ' — spam de alta confianza' : +scl >= 5 ? ' — spam' : +scl === -1 ? ' — sin filtrar (remitente de confianza)' : ''}`, sclSev(scl));
    const md = microsoftDelivered(h) ? parseMsDelivery(h) : null;
    if (md) {
      if (md.auth !== undefined) add('Microsoft (buzón)', 'Autenticación del remitente (auth)', md.auth === '1' ? '1 — superada' : '0 — no superada', md.auth === '1' ? 'ok' : 'medium');
      if (md.dest) add('Microsoft (buzón)', 'Carpeta de destino (dest)', { I: 'I — Bandeja de entrada', J: 'J — Correo no deseado', D: 'D — Elementos eliminados' }[md.dest] || md.dest, md.dest === 'J' ? 'medium' : 'info');
      if (md.ofr) add('Microsoft (buzón)', 'Motivo (OFR)', { TrustedSenderList: 'TrustedSenderList — remitente en tu lista de confianza', SpamFilterAuthJ: 'SpamFilterAuthJ — no deseado por el filtro' }[md.ofr] || md.ofr, 'info');
    }
    const xmd = h.get('x-message-delivery');
    if (xmd) {
      let dec = '';
      try { dec = atob(xmd.replace(/\s+/g, '')); } catch (_) { /* no es base64 */ }
      const s2 = (dec.match(/SCL=(-?\d+)/) || [])[1];
      if (s2 !== undefined && !scl) add('Microsoft (Outlook.com)', 'SCL (X-Message-Delivery)', s2, sclSev(s2));
    }
    const bcl = (h.get('x-microsoft-antispam').match(/BCL:(\d+)/) || [])[1];
    if (bcl !== undefined) add('Microsoft 365', 'Nivel de correo masivo (BCL)', bcl, +bcl >= 7 ? 'low' : 'info');
    const sa = h.get('x-spam-status');
    if (sa) {
      const score = (sa.match(/score=(-?[\d.]+)/i) || [])[1];
      const req = (sa.match(/required=(-?[\d.]+)/i) || [])[1];
      const tests = (sa.match(/tests=(\S+(?:\s*,\s*\S+)*)/i) || [])[1];
      const yes = /^\s*yes/i.test(sa);
      add('SpamAssassin', 'Estado', yes ? 'Spam' : 'No spam', yes ? 'medium' : 'ok');
      if (score) add('SpamAssassin', 'Puntuación', `${score}${req ? ' / ' + req : ''}`, 'info');
      if (tests) add('SpamAssassin', 'Reglas', tests.replace(/\s+/g, ''), 'info');
    }
    const flag = h.get('x-spam-flag');
    if (flag && !sa) add('Filtro antispam', 'X-Spam-Flag', flag, /yes/i.test(flag) ? 'medium' : 'ok');
    const rs = h.get('x-spamd-result') || h.get('x-rspamd-score');
    if (rs) add('Rspamd', 'Resultado', rs.slice(0, 300), 'info');
    const gsc = h.get('x-spam-score');
    if (gsc && !sa) add('Filtro antispam', 'X-Spam-Score', gsc, 'info');
    return out;
  }

  // El receptor final es Microsoft: el Received más alto con nombre de servidor es suyo.
  function microsoftDelivered(h) {
    const top = h.getAll('received').map(v => parseReceived(v).by).find(by => /[a-z]\.[a-z]/i.test(by));
    return !!top && providerOf(top) === 'microsoft';
  }

  // X-Microsoft-Antispam-Mailbox-Delivery: veredicto de Microsoft que Outlook conserva al exportar.
  function parseMsDelivery(h) {
    const v = h.get('x-microsoft-antispam-mailbox-delivery');
    if (!v) return null;
    const t = {};
    v.split(';').forEach(p => { const i = p.indexOf(':'); if (i > 0) t[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim(); });
    return { auth: t.auth, dest: t.dest, ofr: t.ofr || '', trusted: t.wl === '1' || t.pcwl === '1' };
  }

  // Outlook (escritorio) no guarda el original al exportar: lo reconstruye sin
  // Authentication-Results ni DKIM-Signature y añade Thread-Index.
  function detectOutlookExport(h, auth) {
    const exchange = h.list.some(x => /^x-ms-exchange-organization-/.test(x.key));
    const stripped = !h.has('dkim-signature') && !auth.authResults.length && !h.has('arc-seal');
    return exchange && h.has('thread-index') && stripped;
  }

  // ---------- dominios inválidos o aleatorios ----------

  function domainProblems(rawDomain) {
    const d = String(rawDomain || '').replace(/\.$/, '');
    if (!d) return null;
    const labels = d.split('.');
    if (labels.some(l => !l || l.length > 63 || /^-|-$/.test(l) || /[^A-Za-z0-9-]/.test(l)) || labels.length < 2) {
      return { kind: 'invalid', detail: 'no es un nombre de dominio válido (etiquetas vacías, con guiones al principio o al final, o caracteres no permitidos)' };
    }
    const main = labels.length > 2 ? labels.slice(0, -1).reduce((a, b) => (b.length > a.length ? b : a)) : labels[0];
    const transitions = (main.match(/[a-z][A-Z]|[A-Z][a-z]/g) || []).length;
    const low = main.toLowerCase();
    const consonantRun = Math.max(0, ...(low.match(/[bcdfghjklmnpqrstvwxz]+/g) || ['']).map(x => x.length));
    const vowels = (low.match(/[aeiouy]/g) || []).length / Math.max(1, low.replace(/[^a-z]/g, '').length);
    if (main.length >= 8 && (transitions >= 3 || (consonantRun >= 5 && vowels < 0.3))) {
      return { kind: 'random', detail: `«${main}» parece una cadena aleatoria${transitions >= 3 ? ' (mayúsculas y minúsculas mezcladas)' : ''}, típica de dominios desechables` };
    }
    return null;
  }

  // ---------- puntuación ----------

  // Cada hallazgo suma según su gravedad; las evidencias a favor llevan puntos negativos.
  // Las evidencias de confianza en el remitente (trust: DMARC, DKIM, antigüedad…) sólo prueban
  // que el correo viene del dominio del From, no que ese dominio sea de fiar: si el propio
  // dominio es sospechoso (voidsTrust: imita una marca, es nuevo, es gratuito…) no restan nada.
  const pointsOf = (f, trustVoided) => (trustVoided && f.trust ? 0 : f.points != null ? f.points : SEV_WEIGHT[f.sev]);
  const MITIGATION_CAP = 30;      // lo máximo que pueden restar las evidencias a favor
  const MITIGATION_CAP_HIGH = 10; // si hay alguna alerta grave (una cuenta legítima puede estar comprometida)

  function scoreFindings(findings) {
    const voidedBy = findings.filter(f => f.voidsTrust);
    const trustVoided = voidedBy.length > 0;
    let pos = 0, neg = 0;
    findings.forEach(f => { const p = pointsOf(f, trustVoided); if (p > 0) pos += p; else neg += p; });
    const cap = findings.some(f => f.sev === 'high') ? MITIGATION_CAP_HIGH : MITIGATION_CAP;
    const mitigation = Math.max(neg, -cap);
    const score = Math.max(0, Math.min(100, pos + mitigation));
    return { score, level: score >= 50 ? 'alto' : score >= 20 ? 'medio' : 'bajo', positive: pos, mitigation, mitigationCap: cap, rawMitigation: neg,
      trustVoided, voidedBy: voidedBy.map(f => f.title) };
  }

  const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3, ok: 4 };
  const sortFindings = list => list.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);

  // Conclusión en lenguaje llano a partir de la puntuación y los hallazgos (texto plano).
  // entry: { analysis, email, findings, level, trustVoided, voidedBy } tras scoreFindings.
  function conclusion(entry) {
    const s = entry.analysis.summary;
    const high = entry.findings.filter(f => f.sev === 'high');
    const med = entry.findings.filter(f => f.sev === 'medium');
    // Si lo reenvía Apple, el DMARC del receptor es el de Apple: cuenta la autenticación del remitente real.
    const senderAuth = s.relay ? s.senderAuth : s.dmarc === 'pass' || s.msAuth === '1';
    const authOk = senderAuth && !entry.trustVoided;
    if (entry.level === 'alto') {
      return {
        title: 'Muy probablemente malicioso',
        text: `Tiene ${plural(high.length, 'señal grave', 'señales graves')}${med.length ? ` y ${plural(med.length, 'señal', 'señales')} más a revisar` : ''}. Trátalo como un intento de phishing o fraude.`,
        actions: ['No hagas clic en los enlaces ni abras los adjuntos', 'No respondas ni facilites datos o contraseñas', 'Repórtalo a tu equipo de seguridad y bórralo'],
      };
    }
    if (entry.level === 'medio') {
      return {
        title: 'Sospechoso: revísalo antes de actuar',
        text: `Hay ${plural(high.length + med.length, 'señal', 'señales')} que no ${high.length + med.length === 1 ? 'encaja' : 'encajan'} con un correo legítimo, aunque no es concluyente.`,
        actions: ['Confirma con el remitente por otro canal (teléfono, web oficial)', 'Revisa los enlaces y adjuntos marcados antes de usarlos'],
      };
    }
    if (entry.email.attached) {
      return {
        title: 'Riesgo bajo, pero su remitente no se puede comprobar',
        text: 'No hay indicios claros de engaño, pero este correo venía adjunto a otro: sus cabeceras de autenticación y de ruta pueden estar inventadas.',
        actions: ['No te fíes del remitente que muestra sólo porque aparezca como autenticado', 'Mantén la precaución habitual con enlaces y adjuntos'],
      };
    }
    if (entry.trustVoided && senderAuth) {
      return {
        title: 'Riesgo bajo, pero revisa quién lo envía',
        text: `El correo está autenticado, pero eso sólo prueba que viene de ${entry.analysis.senderDomain || entry.analysis.fromDomain}, y ese dominio no inspira confianza (${entry.voidedBy.join("; ")}).`,
        actions: ['Comprueba que el dominio del remitente es realmente de quien dice ser', 'Mantén la precaución habitual con enlaces y adjuntos'],
      };
    }
    return {
      title: authOk && !med.length ? 'Sin señales de riesgo relevantes' : 'Riesgo bajo',
      text: authOk ? `El remitente está autenticado (${s.relay ? 'según Apple, que lo reenvió' : s.dmarc === 'pass' ? 'DMARC correcto' : 'validado por Microsoft'}) y no hay indicios claros de engaño.` : 'No hay indicios claros de engaño, aunque la autenticación no es completa.',
      actions: ['Mantén la precaución habitual con enlaces y adjuntos'],
    };
  }

  // Los 3 motivos de la conclusión: el más grave de cada categoría, para que no sean tres variantes
  // de lo mismo (SPF, DKIM y DMARC fallan a la vez). Si hay menos categorías, se completa con el resto.
  function topReasons(findings, n = 3) {
    const bad = findings.filter(f => f.sev === 'high' || f.sev === 'medium');
    const seen = new Set(), picked = [];
    for (const f of bad) {
      const key = f.category === 'dkim' ? 'auth' : f.category;
      if (picked.length < n && !seen.has(key)) { seen.add(key); picked.push(f); }
    }
    for (const f of bad) if (picked.length < n && !picked.includes(f)) picked.push(f);
    return picked;
  }

  // ---------- análisis principal ----------

  const SEV_WEIGHT = { high: 25, medium: 10, low: 4, info: 0, ok: 0 };

  async function analyze(email) {
    const h = email.headers;
    const findings = [];
    const add = (sev, category, title, detail, points, extra) => findings.push(Object.assign({ sev, category, title, detail: detail || '' }, points != null ? { points } : {}, extra));
    // trust: evidencia de que el correo viene del dominio del From. voidsTrust: el dominio del From es sospechoso,
    // así que esa evidencia no vale. impersonation: además, el dominio o el nombre se hace pasar por otro.
    const TRUST = { trust: true }, VOIDS = { voidsTrust: true }, IMPERSONATES = { voidsTrust: true, impersonation: true };

    const from = parseAddressList(h.get('from'))[0] || { name: '', address: '' };
    const sender = parseAddressList(h.get('sender'))[0];
    const replyTo = parseAddressList(h.get('reply-to'));
    const returnPath = (h.get('return-path').match(/<?([^<>\s]*@[^<>\s]*)>?/) || [])[1] || '';
    const to = parseAddressList(h.get('to'));
    const cc = parseAddressList(h.get('cc'));
    const bcc = parseAddressList(h.get('bcc'));
    const fromDomain = domainOf(from.address);
    const date = parseDate(h.get('date'));
    const route = buildRoute(h);
    const auth = buildAuth(h, fromDomain);
    // Si lo reenvía un servicio que oculta tu dirección, las comprobaciones del remitente se hacen
    // sobre el remitente real; from/fromDomain siguen siendo los de la cabecera.
    const relay = detectRelay(from, replyTo, auth);
    const senderDomain = relay ? relay.domain : fromDomain;
    const senderReplyTo = relay ? relay.replyTo : replyTo;
    const envelopeFrom = relay ? relay.mailfrom : returnPath;
    const { links, html } = extractLinks(email);
    const attachments = email.attachments.map(analyzeAttachment);
    await hashAttachments(attachments);
    const bodyText = email.text || htmlToText(email.html);
    const outlookExport = detectOutlookExport(h, auth);
    // X-Microsoft-Antispam-Mailbox-Delivery sólo es de fiar si el correo lo entregó Microsoft: si no,
    // la ha escrito el remitente.
    const msDelivery = microsoftDelivered(h) ? parseMsDelivery(h) : null;

    // Enlaces encontrados dentro de adjuntos HTML: se analizan como el resto.
    attachments.forEach(x => (x.html ? x.html.urls : []).forEach(u => {
      if (!links.some(l => l.href === u)) links.push(Object.assign(analyzeURL(u, ''), { source: 'adjunto · ' + x.name }));
    }));

    // --- Autenticación
    const res = r => r ? r.result : 'none';
    const spfR = res(auth.spf), dkimR = res(auth.dkim), dmarcR = res(auth.dmarc);
    // Un correo que venía adjunto a otro no ha pasado por tu servidor: todas sus cabeceras, también las
    // de autenticación y los Received, las pudo escribir quien lo adjuntó.
    if (email.attached) {
      add('info', 'auth', 'Correo adjunto: su autenticación no es verificable',
        'No lo recibió tu proveedor, así que sus Authentication-Results, Received y demás cabeceras pueden ser inventados por quien lo adjuntó. No restan riesgo.', undefined, VOIDS);
    }
    const noAuthHeaders = !auth.trustedResults.length && !auth.receivedSpf;
    // Authentication-Results de servidores que no aparecen en la ruta: los ha escrito el remitente.
    const claims = s => s.results.filter(r => ['spf', 'dkim', 'dmarc'].includes(r.method)).map(r => `${r.method}=${r.result}`);
    const forged = auth.ignoredResults.filter(s => !s.inRoute && claims(s).length);
    if (forged.length) {
      add('medium', 'auth', 'Authentication-Results que no añadió ningún servidor de la ruta',
        forged.slice(0, 3).map(s => `${s.server || '(sin servidor)'}: ${claims(s).join(', ')}`).join(' · ') +
        '. Cualquiera puede incluir esta cabecera al enviar el correo para aparentar que está autenticado: no se tiene en cuenta.');
    }
    if (noAuthHeaders) {
      add('info', 'auth', auth.authResults.length ? 'Sin Authentication-Results de tu proveedor' : 'Sin cabeceras Authentication-Results',
        'El correo no contiene el veredicto SPF/DKIM/DMARC del servidor receptor (p. ej. correo enviado, exportado de borradores o de un servidor que no las añade). No se puede verificar la autenticidad.');
    } else {
      if (outlookExport) {
        add('info', 'auth', 'Exportado desde Outlook: faltan las cabeceras de autenticación',
          'Outlook reconstruye el mensaje al guardarlo como .eml y elimina Authentication-Results y DKIM-Signature, así que no se puede comprobar DKIM ni DMARC. ' +
          'Para un análisis completo, arrastra el correo desde Outlook como .msg o descárgalo desde Outlook en la web (··· › Descargar).');
      }
      if (relay) {
        const list = xs => xs.join(', ');
        const innerDesc = [
          ...relay.dkim.map(r => `DKIM ${r.result} de ${r.domain}`),
          relay.spf ? `SPF ${relay.spf.result} de ${relay.spf.domain}` : '',
        ].filter(Boolean);
        add('info', 'auth', `Reenviado por ${relay.service}: el remitente real es ${relay.original.address}`,
          `Apple sustituye la dirección del remitente por una de ${relay.relayDomain} para no revelar la tuya. Por eso SPF, DKIM y DMARC del receptor (${spfR} / ${dkimR} / ${dmarcR}) ` +
          'sólo prueban que el correo pasó por Apple, no quién lo escribió: lo que cuenta es la autenticación que Apple comprobó al recibirlo.');
        if (relay.authenticated) {
          add('ok', 'auth', 'Remitente real autenticado (según Apple)',
            `Apple verificó ${relay.alignedDkim.length ? 'la firma DKIM de ' + list(relay.alignedDkim) : 'el SPF de ' + relay.spf.domain} antes de reenviarlo, alineada con ${relay.domain}. Resultados: ${list(innerDesc)}.`, -10, TRUST);
        } else if (innerDesc.length) {
          add('medium', 'auth', 'Remitente real sin autenticar (según Apple)',
            `Ni DKIM ni SPF respaldan a ${relay.domain}: ${list(innerDesc)}. Puede ser una suplantación del remitente original.`);
        } else {
          add('low', 'auth', 'Sin datos de autenticación del remitente real', 'Apple no dejó sus cabeceras Authentication-Results (dkim-verifier.icloud.com, spf.icloud.com), así que no se puede saber si el remitente original está autenticado.');
        }
      } else {
        if (dmarcR === 'fail') add('high', 'auth', 'DMARC falla', `El dominio ${auth.dmarc.props['header.from'] || fromDomain} no autoriza este envío. ${auth.dmarc.comment || ''}`);
        else if (dmarcR === 'pass') add('ok', 'auth', 'DMARC correcto', `header.from=${auth.dmarc.props['header.from'] || fromDomain}. El dominio del remitente respalda este envío.`, -10, TRUST);
        else if (dmarcR !== 'none' || auth.dmarc) add('low', 'auth', `DMARC: ${dmarcR}`, auth.dmarc ? auth.dmarc.comment : '');
        else if (!outlookExport) add('low', 'auth', 'Sin resultado DMARC', 'El servidor receptor no evaluó DMARC o el dominio no tiene política.');

        if (spfR === 'fail') add('high', 'auth', 'SPF falla', auth.spf.comment || 'La IP de envío no está autorizada por el dominio.');
        else if (spfR === 'softfail') add('medium', 'auth', 'SPF softfail', auth.spf.comment || '');
        else if (spfR === 'pass') add('ok', 'auth', 'SPF correcto', auth.spf.props['smtp.mailfrom'] ? 'smtp.mailfrom=' + auth.spf.props['smtp.mailfrom'] : '');
        else if (['permerror', 'temperror', 'neutral', 'none'].includes(spfR)) add('low', 'auth', `SPF: ${spfR}`, auth.spf ? auth.spf.comment : '');

        if (dkimR === 'fail') add('high', 'auth', 'Firma DKIM inválida', 'El mensaje pudo ser modificado o la firma no es válida.');
        else if (dkimR === 'pass') {
          const d = (auth.dkim.props['header.d'] || auth.dkim.props['header.i'] || '').replace(/^@/, '');
          const aligned = sameOrg(domainOf('x@' + d.replace(/^.*@/, '')), fromDomain);
          if (d && !aligned) add('low', 'auth', 'DKIM válido pero no alineado', `Firmado por ${d}, pero el remitente es ${fromDomain}.`);
          else add('ok', 'auth', 'DKIM correcto', (d ? 'Firmado por ' + d : '') + ' y alineado con el remitente.', -5, TRUST);
        } else if (dkimR === 'none' || !auth.dkim) { if (!outlookExport) add('low', 'auth', 'Sin firma DKIM', ''); }
        else add('low', 'auth', `DKIM: ${dkimR}`, '');
      }

      if (auth.compauth && auth.compauth.result === 'fail') add('high', 'auth', 'Microsoft compauth=fail', auth.compauth.props['reason'] || auth.compauth.comment || '');
    }
    // Veredicto de autenticación de Microsoft (sobrevive a la exportación de Outlook).
    if (msDelivery && msDelivery.auth === '1' && dmarcR !== 'pass' && dmarcR !== 'fail') {
      add('ok', 'auth', 'Microsoft autenticó al remitente', 'auth:1 en X-Microsoft-Antispam-Mailbox-Delivery: el servidor de Microsoft comprobó que el dominio del remitente respalda el envío (SPF/DKIM/DMARC o su autenticación compuesta).', -10, TRUST);
    } else if (msDelivery && msDelivery.auth === '0' && dmarcR !== 'fail') {
      add('medium', 'auth', 'Microsoft no pudo autenticar al remitente', 'auth:0 en X-Microsoft-Antispam-Mailbox-Delivery: el dominio del From no está respaldado por SPF, DKIM ni DMARC según Microsoft.');
    }
    if (msDelivery && msDelivery.trusted) add('info', 'auth', 'Remitente en tu lista de remitentes seguros', 'Lo añadiste tú (o tu organización) en Outlook; no es una prueba de autenticidad por sí misma.');

    // --- Remitente
    // Un .msg sin cabeceras de Internet suele ser un borrador o un elemento enviado: no tiene From ni Message-ID.
    const msgWithoutHeaders = email.sourceFormat === 'msg' && !(email.msgInfo && email.msgInfo.transportHeaders);
    if (!from.address) add(msgWithoutHeaders ? 'info' : 'medium', 'remitente', msgWithoutHeaders ? 'Sin remitente (borrador o elemento enviado)' : 'Sin dirección From válida', h.get('from'));
    const senderAddress = relay ? relay.original.address : from.address;
    const nameEmail = (from.name.match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/) || [])[0];
    if (nameEmail && nameEmail.toLowerCase() !== from.address.toLowerCase() && nameEmail.toLowerCase() !== senderAddress) {
      add('high', 'remitente', 'El nombre visible contiene otra dirección', `Muestra "${nameEmail}" pero la dirección real es ${senderAddress}.`, undefined, IMPERSONATES);
    }
    const brand = BRANDS.find(b => new RegExp('(^|[^a-z])' + b + '([^a-z]|$)').test(from.name.toLowerCase()));
    const brandKey = brand && brand.replace(/[^a-z]/g, '');
    const officialForBrand = brand && (BRAND_DOMAINS[brandKey] || []).includes(orgDomain(senderDomain));
    if (brand && senderDomain && !officialForBrand && !senderDomain.replace(/[^a-z]/g, '').includes(brandKey)) {
      add('medium', 'remitente', `Posible suplantación de "${brand}"`, `El nombre del remitente menciona ${brand} pero el dominio es ${senderDomain}.`, undefined, IMPERSONATES);
    }
    if (FREEMAIL.has(orgDomain(senderDomain))) {
      add('info', 'remitente', `Remitente con cuenta de correo gratuita (${orgDomain(senderDomain)})`,
        `Cualquiera puede abrir una cuenta en ${orgDomain(senderDomain)}: la autenticación sólo prueba que el correo salió de ese proveedor, no quién lo escribió, así que no resta riesgo.`, undefined, VOIDS);
    }
    if (senderReplyTo.length && senderReplyTo.some(r => !sameOrg(domainOf(r.address), senderDomain))) {
      add('medium', 'remitente', 'Reply-To apunta a otro dominio', `Las respuestas irían a ${senderReplyTo.map(r => r.address).join(', ')} en lugar de ${senderAddress}.`);
    }
    if (envelopeFrom && senderDomain && !sameOrg(domainOf(envelopeFrom.includes('@') ? envelopeFrom : '@' + envelopeFrom), senderDomain)) {
      add('low', 'remitente', 'Return-Path distinto del remitente', `Envelope-from: ${envelopeFrom}. Es habitual en plataformas de mailing, pero también en suplantaciones.`);
    }
    if (sender && fromDomain && !sameOrg(domainOf(sender.address), fromDomain)) {
      add('info', 'remitente', 'Cabecera Sender distinta', `Enviado en nombre de ${from.address} por ${sender.address}.`);
    }
    const rawDomainOf = a => (String(a || '').match(/@([^\s>@]+)\s*$/) || [])[1] || '';
    const seenBad = new Set();
    [[senderAddress, 'remitente (From)'], [returnPath, 'Return-Path'], ...senderReplyTo.map(r => [r.address, 'Reply-To'])].forEach(([addrs, role]) => {
      const raw = rawDomainOf(addrs);
      const pr = raw && domainProblems(raw);
      const key = orgDomain(raw.toLowerCase());
      if (!pr || seenBad.has(key)) return;
      seenBad.add(key);
      const voids = sameOrg(raw.toLowerCase(), senderDomain) ? IMPERSONATES : undefined;
      if (pr.kind === 'invalid') add('high', 'remitente', `Dominio del ${role} inválido: ${raw}`, `«${raw}» ${pr.detail}. Ningún servidor legítimo envía desde un dominio así.`, undefined, voids);
      else add('medium', 'remitente', `Dominio del ${role} con aspecto aleatorio: ${raw}`, pr.detail + '.', undefined, voids);
    });

    // Asunto que finge ser una respuesta o reenvío sin pertenecer a ninguna conversación.
    const subject = h.get('subject') || '';
    const replyPrefix = subject.match(/^\s*(re|rv|fw|fwd|reenv|aw|wg|sv|vs|tr|antw|odp)\s*(\[\d+\])?\s*:/i);
    if (replyPrefix && !h.has('in-reply-to') && !h.has('references')) {
      // En Exchange, Thread-Index de 22 bytes = inicio de conversación; las respuestas reales lo alargan.
      let rootThread = true;
      const ti = h.get('thread-index').replace(/\s+/g, '');
      if (ti) { try { rootThread = atob(ti).length <= 22; } catch (_) { rootThread = true; } }
      if (rootThread) {
        const isFw = /^(fw|fwd|rv|reenv|wg|tr)$/i.test(replyPrefix[1]);
        add('medium', 'cabeceras', `Falsa ${isFw ? 'reenvío' : 'respuesta'}: el asunto empieza por «${replyPrefix[1]}:»`,
          `No tiene cabeceras In-Reply-To ni References${ti ? ' y su Thread-Index indica una conversación nueva' : ''}: finge continuar una conversación para ganarse tu confianza, técnica habitual en fraudes de facturas.`);
      }
    }

    const msgId = h.get('message-id');
    if (!msgId) { if (!msgWithoutHeaders) add('low', 'cabeceras', 'Falta Message-ID', 'Los servidores legítimos casi siempre lo incluyen.'); }
    else {
      const midDomain = (msgId.match(/@([^>\s]+)/) || [])[1];
      if (midDomain && senderDomain && !sameOrg(midDomain, senderDomain)) add('info', 'cabeceras', 'Message-ID de otro dominio', `Generado por ${midDomain}.`);
    }
    if (!date) add('low', 'cabeceras', 'Fecha ausente o inválida', h.get('date'));
    else {
      const firstHop = route.find(r => r.date);
      const lastHop = [...route].reverse().find(r => r.date);
      if (lastHop && date - lastHop.date > 15 * 60 * 1000) add('medium', 'cabeceras', 'Fecha del correo posterior a su recepción', `Date: ${date.toISOString()} · recibido: ${lastHop.date.toISOString()}`);
      if (firstHop && firstHop.date - date > 3 * 24 * 3600 * 1000) add('low', 'cabeceras', 'Fecha muy anterior al envío real', 'La fecha declarada es días anterior al primer salto SMTP.');
    }
    if (!to.length && !cc.length) add('info', 'cabeceras', 'Sin destinatarios visibles', 'Enviado en copia oculta (BCC); típico de envíos masivos.');
    else if (to.length + cc.length > 20) add('info', 'cabeceras', `${to.length + cc.length} destinatarios visibles`, '');

    // --- Ruta
    const publicIPs = [];
    route.forEach(hop => hop.ips.forEach(ip => { if (!isPrivateIP(ip) && !publicIPs.includes(ip)) publicIPs.push(ip); }));
    // IP de origen: la que entregó el correo a tu proveedor. declaredIP: la del primer salto, que
    // puede ser la real del remitente o una inventada en un Received falso.
    const declaredIP = (route.find(hp => hp.ips.some(ip => !isPrivateIP(ip))) || { ips: [] }).ips.find(ip => !isPrivateIP(ip)) || '';
    const delivery = deliveryHop(route, relay);
    const originIP = (delivery && delivery.ips.find(ip => !isPrivateIP(ip))) || declaredIP;
    const longHop = route.find(hp => hp.delay !== null && hp.delay > 3600);
    if (longHop) add('info', 'ruta', 'Retraso de entrega elevado', `Salto ${longHop.hop}: ${Math.round(longHop.delay / 60)} min.`);
    const negHop = route.find(hp => hp.delay !== null && hp.delay < -300);
    if (negHop) add('low', 'ruta', 'Marcas de tiempo incoherentes', `El salto ${negHop.hop} es anterior al anterior (relojes desajustados o cabeceras falsificadas).`);
    const plainHops = route.filter(hp => hp.from && !hp.tls && hp.ips.some(ip => !isPrivateIP(ip)));
    if (plainHops.length) add('info', 'ruta', 'Saltos externos sin TLS aparente', plainHops.map(hp => `${hp.from} → ${hp.by}`).join(' · '));

    // --- Enlaces
    // Los enlaces de campañas pasan por el redireccionador de la plataforma de envío (Mailchimp, SendGrid…):
    // el texto muestra la web real y el destino es el rastreador. No es un engaño si el mismo
    // redireccionador se usa en la mayoría de enlaces y la ruta tiene forma de enlace de seguimiento.
    const hostCount = {};
    links.forEach(l => { if (l.host) hostCount[orgDomain(l.host)] = (hostCount[orgDomain(l.host)] || 0) + 1; });
    const htmlLinks = links.filter(l => l.source === 'html').length || links.length;
    links.filter(l => l.mismatch).forEach(l => {
      const org = orgDomain(l.host);
      const dominant = (hostCount[org] || 0) >= Math.max(2, htmlLinks * 0.5);
      if (dominant && (TRACKER_DOMAINS.has(org) || TRACKING_PATH.test(safeURL(l.href) ? safeURL(l.href).pathname : ''))) {
        l.mismatch = false;
        l.tracking = true;
        const f = l.flags.find(x => /El texto muestra/.test(x.msg));
        if (f) { f.sev = 'low'; f.msg = f.msg.replace(/ pero lleva a /, ' pero pasa por el redireccionador de seguimiento ') + ' (destino final no verificable)'; }
      }
    });
    const tracked = links.filter(l => l.tracking);
    if (tracked.length) add('info', 'enlaces', `Enlaces a través de un redireccionador de seguimiento (${orgDomain(tracked[0].host)})`, 'Habitual en envíos de marketing: la plataforma registra el clic y redirige a la web real. El destino final no se puede comprobar sin visitarlo.');
    const mismatches = links.filter(l => l.mismatch);
    if (mismatches.length) add('high', 'enlaces', `${plural(mismatches.length, 'enlace', 'enlaces')} con destino engañoso`, mismatches.slice(0, 3).map(l => `"${l.text}" → ${l.host}`).join(' · '));
    const ipLinks = links.filter(l => l.flags.some(f => /IP directa/.test(f.msg)));
    if (ipLinks.length) add('high', 'enlaces', 'Enlaces a direcciones IP', ipLinks.slice(0, 3).map(l => l.host).join(', '));
    const dangerScheme = links.filter(l => l.flags.some(f => /Esquema peligroso|credenciales/.test(f.msg)));
    if (dangerScheme.length) add('high', 'enlaces', 'Enlaces con esquema o formato peligroso', dangerScheme.slice(0, 3).map(l => l.href.slice(0, 80)).join(' · '));
    const puny = links.filter(l => l.flags.some(f => /punycode/.test(f.msg)));
    if (puny.length) add('medium', 'enlaces', 'Dominios punycode (posibles homógrafos)', puny.map(l => l.host).join(', '));
    const badTld = links.filter(l => l.flags.some(f => /TLD/.test(f.msg)));
    if (badTld.length) add('medium', 'enlaces', 'Dominios con TLD de riesgo', [...new Set(badTld.map(l => l.host))].slice(0, 5).join(', '));
    const shorts = links.filter(l => l.flags.some(f => /Acortador/.test(f.msg)));
    if (shorts.length) add('low', 'enlaces', 'Uso de acortadores de URL', [...new Set(shorts.map(l => l.host))].join(', '));
    const recipients = [...new Set([...to, ...cc].map(r => r.address.toLowerCase())
      .concat(h.getAll('delivered-to'), h.getAll('x-original-to')).map(x => String(x).toLowerCase().trim()).filter(x => /@/.test(x)))];
    const personal = [];
    if (recipients.length) {
      const b64 = t => { try { return btoa(t); } catch (_) { return ''; } };
      links.forEach(l => {
        if (/unsub|baja|optout|opt-out|preferenc|manage|gestionar|suscrip/i.test(l.href + ' ' + l.text)) return;
        let dec = l.href;
        try { dec = decodeURIComponent(l.href); } catch (_) { /* URL mal codificada */ }
        const lower = dec.toLowerCase();
        for (const r of recipients) {
          const enc = b64(r).replace(/=+$/, '');
          const encUrl = enc.replace(/\+/g, '-').replace(/\//g, '_');
          const hashPart = (l.href.split('#')[1] || '');
          const inB64 = enc && (l.href.includes(enc) || l.href.includes(encUrl));
          const inFragment = hashPart && (hashPart.toLowerCase().includes(r) || hashPart.includes(enc) || hashPart.includes(encUrl));
          if (inB64 || inFragment || lower.includes(r)) {
            const how = inFragment ? 'tras # en la URL' : inB64 ? 'codificada en base64' : 'en claro';
            l.flags.push({ sev: inB64 || inFragment ? 'high' : 'low', msg: `Incluye tu dirección ${how}` });
            personal.push({ link: l, how, strong: !!(inB64 || inFragment), r });
            break;
          }
        }
      });
    }
    const strongPersonal = personal.filter(p => p.strong);
    if (strongPersonal.length) add('high', 'enlaces', 'Enlace personalizado con tu dirección oculta', `${plural(strongPersonal.length, 'enlace lleva', 'enlaces llevan')} ${strongPersonal[0].r} ${strongPersonal[0].how} (${strongPersonal[0].link.host}). Los kits de phishing lo usan para rellenar el login falso con tu correo y parecer auténticos.`);
    else if (personal.length) add('low', 'enlaces', 'Enlaces con tu dirección de correo', `${plural(personal.length, 'enlace incluye', 'enlaces incluyen')} ${personal[0].r} en claro. Es habitual en envíos de marketing, pero confirma que el destino es legítimo.`);

    const linkDomains = [...new Set(links.map(l => l.host).filter(Boolean))];
    const foreign = linkDomains.filter(d => !sameOrg(d, senderDomain));
    if (links.length && senderDomain && foreign.length === linkDomains.length && linkDomains.length <= 3 && links.length >= 1) {
      add('info', 'enlaces', 'Ningún enlace pertenece al dominio del remitente', foreign.join(', '));
    }

    // --- HTML
    if (html.forms.length) add('high', 'html', 'El HTML contiene formularios', html.forms.map(f => `${f.method.toUpperCase()} ${f.action}${f.password ? ' (pide contraseña)' : ''}`).join(' · '));
    if (html.scripts) add('medium', 'html', 'El HTML contiene scripts o manejadores de eventos', `${plural(html.scripts, 'elemento', 'elementos')}. No se ejecutan en este visor.`);
    if (html.iframes) add('medium', 'html', 'El HTML incrusta iframes/objetos', '');
    if (html.metaRefresh) add('high', 'html', 'Redirección automática (meta refresh)', html.metaRefresh);
    // El «preheader» (texto de vista previa oculto) es estándar en newsletters; sólo es sospechoso si es extenso.
    if (html.hiddenTextLen >= 300) add('low', 'html', `Texto oculto extenso en el HTML (${html.hiddenTextLen} caracteres)`, 'Relleno invisible para despistar a los filtros antispam.');
    else if (html.hiddenText) add('info', 'html', 'Texto de vista previa oculto', `${html.hiddenTextLen} caracteres ocultos: es el resumen que muestran los clientes de correo junto al asunto, habitual en newsletters.`);
    if (html.trackingPixels) add('info', 'html', `${plural(html.trackingPixels, 'píxel', 'píxeles')} de seguimiento`, 'Imágenes de 1×1 que avisan al remitente cuando abres el correo.');

    // --- Adjuntos
    attachments.forEach(a => {
      const worst = a.flags.filter(f => f.sev === 'high' || f.sev === 'medium');
      if (worst.length) add(worst.some(f => f.sev === 'high') ? 'high' : 'medium', 'adjuntos', `Adjunto sospechoso: ${a.name}`, worst.map(f => f.msg).join(' · '));
    });

    // --- Contenido
    const lures = findLures((h.get('subject') || '') + '\n' + bodyText.slice(0, 20000));
    if (lures.length >= 3) add('medium', 'contenido', 'Lenguaje típico de phishing', lures.map(l => `${l.label} («${l.sample}»)`).join(' · '));
    else if (lures.length) add('low', 'contenido', 'Algunas expresiones de presión o cebo', lures.map(l => `${l.label} («${l.sample}»)`).join(' · '));

    // --- Dominios parecidos a marcas
    const lookTargets = [[senderDomain, 'remitente'], [domainOf(returnPath), 'Return-Path'], ...(relay && relay.spf ? [[relay.spf.domain, 'Return-Path']] : []), ...senderReplyTo.map(r => [domainOf(r.address), 'Reply-To']),
      ...[...new Set(links.map(l => l.host))].map(host => [host, 'enlace'])];
    const seenLook = new Set();
    const senderLook = lookalike(senderDomain);
    const senderBrand = senderLook ? senderLook.brand : (orgDomain(senderDomain).split('.')[0] || '');
    const LOOK_LABEL = { homoglyph: 'Dominio que imita una marca', typo: 'Posible typosquatting', combo: 'Dominio con marca ajena', subdomain: 'Marca en el subdominio', tld: 'Marca con dominio no oficial' };
    // Mismo nombre de marca que el remitente con otro TLD (openbank.es → openbank.com): no es sospechoso por sí mismo.
    const benignTld = (m, role) => m.kind === 'tld' && role !== 'remitente' && m.brand === senderBrand;
    lookTargets.forEach(([host, role]) => {
      const m = host && lookalike(host);
      if (!m || seenLook.has(orgDomain(host))) return;
      if (benignTld(m, role)) return;
      seenLook.add(orgDomain(host));
      const sev = m.kind === 'homoglyph' || m.kind === 'typo' ? 'high' : m.kind === 'tld' && role !== 'enlace' ? 'low' : 'medium';
      add(sev, 'dominios', `${LOOK_LABEL[m.kind]}: ${host}`, `El ${role} ${m.detail}.`, undefined, role === 'remitente' ? IMPERSONATES : undefined);
    });
    // La misma alerta en cada enlace afectado, para que la lista de enlaces no diga «sin alertas»
    // (se hace aparte porque arriba se deduplica por dominio, también contra el del remitente).
    links.forEach(l => {
      const m = l.host && lookalike(l.host);
      if (!m || benignTld(m, 'enlace')) return;
      l.flags.push({ sev: m.kind === 'homoglyph' || m.kind === 'typo' ? 'high' : 'medium', msg: `${LOOK_LABEL[m.kind]} (${m.brand})` });
    });

    // Autenticado pero haciéndose pasar por otro: el atacante controla el dominio (registrado
    // para la ocasión) o la cuenta, así que pasa SPF/DKIM/DMARC. No es menos grave que una
    // falsificación del From, que al menos fallaría la autenticación y sumaría por ello.
    const senderAuthOk = relay ? relay.authenticated
      : dmarcR === 'pass' || (msDelivery && msDelivery.auth === '1') || findings.some(f => f.trust && f.title === 'DKIM correcto');
    const impersonation = findings.filter(f => f.impersonation);
    if (senderAuthOk && impersonation.length) {
      add('medium', 'remitente', `Remitente autenticado que se hace pasar por otro (${senderDomain})`,
        `SPF/DKIM/DMARC son correctos, así que el From no está falsificado: quien lo envía controla ${senderDomain}. Pero ese dominio ${impersonation.length > 1 ? 'tiene varias señales de suplantación' : 'es sospechoso'} (${impersonation.map(f => f.title).join('; ')}). ` +
        'Es la técnica habitual para superar los filtros: registrar un dominio parecido y configurarlo correctamente. La autenticación no resta riesgo.');
    }

    // --- Veredictos antispam de los servidores
    const antispam = parseAntispam(h);
    const threat = antispam.find(x => x.source === 'Microsoft 365' && x.label.startsWith('Categoría') && x.sev === 'high');
    if (threat) add('high', 'antispam', 'Microsoft 365 lo clasificó como amenaza', threat.value);
    const highSpam = antispam.find(x => /SCL/.test(x.label) && x.sev === 'high');
    const spamV = antispam.filter(x => x.sev === 'medium' && !/auth/.test(x.label));
    if (highSpam) add('high', 'antispam', 'Microsoft lo clasificó como spam de alta confianza', `${highSpam.source}: SCL ${String(highSpam.value).split(' ')[0]}${spamV.length ? ' · ' + spamV.map(x => `${x.label} ${x.value}`).join(' · ') : ''}`);
    else if (spamV.length) add('medium', 'antispam', 'Un filtro antispam lo marcó como spam', spamV.map(x => `${x.source}: ${x.label} ${x.value}`).join(' · '));

    // --- Estructura
    email.warnings.forEach(w => add('low', 'estructura', 'Estructura MIME anómala', w.text));

    // --- Puntuación
    const { score, level } = scoreFindings(findings);
    sortFindings(findings);

    // --- IOCs
    const emails = new Set();
    [from, relay && relay.original, sender, ...replyTo, ...(relay ? relay.replyTo : [])].filter(Boolean).forEach(a => a.address && emails.add(a.address.toLowerCase()));
    if (returnPath) emails.add(returnPath.toLowerCase());
    if (relay && relay.mailfrom.includes('@')) emails.add(relay.mailfrom.toLowerCase());
    const domains = new Set([fromDomain, senderDomain, domainOf(returnPath), relay && relay.spf && relay.spf.domain, ...senderReplyTo.map(r => domainOf(r.address)), ...linkDomains]
      .filter(d => d && !isIP(d.replace(/^\[|\]$/g, ''))));
    links.forEach(l => {
      const host = (l.host || '').replace(/^\[|\]$/g, '');
      if (isIP(host) && !isPrivateIP(host) && !publicIPs.includes(host)) publicIPs.push(host);
    });
    const iocs = {
      ips: publicIPs,
      originIP,
      declaredIP: declaredIP !== originIP ? declaredIP : '',
      domains: [...domains],
      urls: [...new Set(links.map(l => l.href))],
      emails: [...emails],
      hashes: attachments.map(a => ({ name: a.name, sha256: a.sha256, sha1: a.sha1 })),
    };

    return {
      from, sender, replyTo, returnPath, to, cc, bcc, fromDomain,
      relay, senderDomain,
      subject: h.get('subject'),
      date,
      messageId: msgId,
      mailer: h.get('x-mailer') || h.get('user-agent') || '',
      route, deliveryHop: delivery, auth, links, html, attachments, lures, antispam,
      bodyText,
      findings, score, level, iocs,
      summary: { spf: spfR, dkim: dkimR, dmarc: dmarcR, noAuthHeaders, outlookExport, msAuth: msDelivery ? msDelivery.auth : undefined,
        relay: !!relay, senderAuth: !!senderAuthOk },
      msDelivery,
    };
  }

  const Analysis = {
    analyze, parseAddressList, domainOf, orgDomain, sharedHostOf, isPrivateIP, parseDate, htmlToText, parseAuthResults,
    analyzeURL, lookalike, scoreFindings, sortFindings, SEV_WEIGHT, pointsOf, domainProblems, conclusion, topReasons,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = Analysis;
  global.Analysis = Analysis;
})(typeof globalThis !== 'undefined' ? globalThis : this);

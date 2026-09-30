/*
 * Comprobaciones en línea opcionales. Sólo envían dominios, IPs y selectores
 * DKIM a servicios públicos; el contenido del correo nunca sale del equipo.
 *  - DNS-over-HTTPS (Cloudflare o Google): DKIM, SPF, DMARC, MX, PTR y DNSBL
 *  - Cloudflare 1.1.1.2 (filtro de malware) como lista negra de dominios
 *  - RDAP (el sucesor JSON de WHOIS): antigüedad y registrador de dominios, titular de IPs
 */
(function (global) {
  'use strict';

  const Analysis = global.Analysis;

  const DOH = {
    cloudflare: { label: 'Cloudflare (1.1.1.1)', url: n => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=` },
    // Sin edns_client_subnet=0.0.0.0/0, Google reenvía la subred de tu IP (ECS) a los servidores
    // DNS autoritativos, que pueden ser del remitente. Cloudflare no envía ECS.
    google: { label: 'Google (8.8.8.8)', url: n => `https://dns.google/resolve?edns_client_subnet=0.0.0.0/0&name=${encodeURIComponent(n)}&type=` },
  };
  const TYPES = { A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };
  let provider = 'cloudflare';

  function withTimeout(ms) {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(new DOMException('Tiempo de espera agotado', 'TimeoutError')), ms);
    return { signal: c.signal, done: () => clearTimeout(t) };
  }

  async function fetchJSON(url, opts, ms) {
    const to = withTimeout(ms || 10000);
    try {
      const r = await fetch(url, Object.assign({ signal: to.signal, referrerPolicy: 'no-referrer', credentials: 'omit' }, opts || {}));
      if (r.status === 404) return { __status: 404 };
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.json();
    } finally { to.done(); }
  }

  // ---------- DNS ----------

  const dnsCache = new Map();

  function parseTxtData(data) {
    // Cloudflare devuelve cadenas entrecomilladas ("a" "b"); Google, texto plano.
    if (!/^"/.test(data)) return data;
    const parts = [];
    data.replace(/"((?:[^"\\]|\\.)*)"/g, (_, s) => { parts.push(s.replace(/\\(\d{3})/g, (m, d) => String.fromCharCode(+d)).replace(/\\(.)/g, '$1')); });
    return parts.join('');
  }

  // only: consultar sólo a ese proveedor, sin recurrir al otro si falla.
  async function dns(name, type, only) {
    const key = (only ? '=' + only : provider) + '|' + type + '|' + name.toLowerCase();
    if (dnsCache.has(key)) return dnsCache.get(key);
    const p = (async () => {
      const order = only ? [only] : provider === 'google' ? ['google', 'cloudflare'] : ['cloudflare', 'google'];
      let lastErr;
      for (const prov of order) {
        try {
          const j = await fetchJSON(DOH[prov].url(name) + type, { headers: { accept: 'application/dns-json' } }, 8000);
          const answers = (j.Answer || []).filter(a => a.type === TYPES[type]).map(a => {
            if (type === 'TXT') return parseTxtData(a.data);
            if (type === 'MX') { const [pref, host] = a.data.split(/\s+/); return { pref: +pref, host: (host || '').replace(/\.$/, '') }; }
            return String(a.data).replace(/\.$/, '');
          });
          // Status: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN
          return { status: j.Status, nx: j.Status === 3, answers, provider: prov };
        } catch (e) { lastErr = e; }
      }
      throw lastErr || new Error('DNS no disponible');
    })();
    dnsCache.set(key, p);
    p.catch(() => dnsCache.delete(key));
    return p;
  }

  async function txt(name) {
    const r = await dns(name, 'TXT');
    if (r.status !== 0 && !r.nx) throw new Error('SERVFAIL');
    return r.answers;
  }

  // ---------- RDAP (WHOIS) ----------

  let bootstrap = null;
  function loadBootstrap() {
    if (!bootstrap) {
      bootstrap = Promise.all([
        fetchJSON('https://data.iana.org/rdap/dns.json', null, 10000).catch(() => null),
        fetchJSON('https://data.iana.org/rdap/ipv4.json', null, 10000).catch(() => null),
      ]).then(([d, ip]) => ({ dns: d, ipv4: ip }));
      bootstrap.then(b => { if (!b.dns) bootstrap = null; });
    }
    return bootstrap;
  }

  function ipv4ToInt(ip) { return ip.split('.').reduce((a, o) => (a * 256) + (+o), 0); }
  function inCidr(ip, cidr) {
    const [base, bits] = cidr.split('/');
    const size = Math.pow(2, 32 - (+bits));
    const start = ipv4ToInt(base);
    const v = ipv4ToInt(ip);
    return v >= start && v < start + size;
  }

  async function rdapBase(kind, value) {
    const b = await loadBootstrap();
    if (kind === 'domain' && b.dns) {
      const tld = value.split('.').pop().toLowerCase();
      const svc = b.dns.services.find(s => s[0].includes(tld));
      if (svc) return svc[1][0].replace(/\/?$/, '/');
      return null;
    }
    if (kind === 'ip' && b.ipv4 && /^\d+\.\d+\.\d+\.\d+$/.test(value)) {
      const svc = b.ipv4.services.find(s => s[0].some(c => inCidr(value, c)));
      if (svc) return svc[1][0].replace(/\/?$/, '/');
    }
    return 'https://rdap.org/';
  }

  function vcardField(entity, field) {
    const card = entity && entity.vcardArray && entity.vcardArray[1];
    if (!card) return '';
    const f = card.find(x => x[0] === field);
    if (!f) return '';
    const v = f[3];
    return Array.isArray(v) ? v.filter(Boolean).join(' ').trim() : String(v || '').trim();
  }

  function findEntity(entities, role) {
    for (const e of entities || []) {
      if ((e.roles || []).includes(role)) return e;
      const nested = findEntity(e.entities, role);
      if (nested) return nested;
    }
    return null;
  }

  const rdapCache = new Map();
  function cached(key, fn) {
    if (!rdapCache.has(key)) {
      const p = fn();
      rdapCache.set(key, p);
      p.catch(() => rdapCache.delete(key));
    }
    return rdapCache.get(key);
  }

  function rdapDomain(domain) {
    return cached('d|' + domain, async () => {
      const base = await rdapBase('domain', domain);
      if (!base) return { error: `El registro de .${domain.split('.').pop()} no publica WHOIS consultable por RDAP`, unsupported: true };
      const j = await fetchJSON(base + 'domain/' + encodeURIComponent(domain), { headers: { accept: 'application/rdap+json' } }, 12000);
      if (j.__status === 404) return { notFound: true };
      const ev = a => { const e = (j.events || []).find(x => x.eventAction === a); return e ? new Date(e.eventDate) : null; };
      const created = ev('registration');
      const registrar = findEntity(j.entities, 'registrar');
      const registrant = findEntity(j.entities, 'registrant');
      const abuse = findEntity(registrar ? registrar.entities : j.entities, 'abuse');
      return {
        created,
        expires: ev('expiration'),
        updated: ev('last changed'),
        ageDays: created && !isNaN(created) ? Math.floor((Date.now() - created) / 86400000) : null,
        registrar: vcardField(registrar, 'fn') || (registrar && registrar.handle) || '',
        registrantOrg: vcardField(registrant, 'org') || vcardField(registrant, 'fn') || '',
        registrantCountry: (() => {
          const card = registrant && registrant.vcardArray && registrant.vcardArray[1];
          const adr = card && card.find(x => x[0] === 'adr');
          return adr ? ((adr[1] && adr[1].cc) || (Array.isArray(adr[3]) ? adr[3][6] : '') || '') : '';
        })(),
        abuseEmail: vcardField(abuse, 'email'),
        status: j.status || [],
        nameservers: (j.nameservers || []).map(n => (n.ldhName || '').toLowerCase()).filter(Boolean),
        dnssec: j.secureDNS ? !!j.secureDNS.delegationSigned : null,
        source: base,
      };
    });
  }

  function rdapIP(ip) {
    return cached('i|' + ip, async () => {
      const base = await rdapBase('ip', ip);
      const j = await fetchJSON(base + 'ip/' + encodeURIComponent(ip), { headers: { accept: 'application/rdap+json' } }, 12000);
      if (j.__status === 404) return { notFound: true };
      const org = findEntity(j.entities, 'registrant') || findEntity(j.entities, 'administrative');
      const abuse = findEntity(j.entities, 'abuse');
      const cidr = (j.cidr0_cidrs || []).map(c => `${c.v4prefix || c.v6prefix}/${c.length}`).join(', ');
      return {
        name: j.name || '',
        handle: j.handle || '',
        country: j.country || '',
        range: cidr || (j.startAddress && j.endAddress ? `${j.startAddress} – ${j.endAddress}` : ''),
        org: vcardField(org, 'fn') || vcardField(org, 'org') || '',
        abuseEmail: vcardField(abuse, 'email'),
        type: j.type || '',
        source: base,
      };
    });
  }

  // ---------- listas negras (DNSBL) ----------

  // blocked: códigos que indican que la lista rechaza consultas desde resolvedores públicos.
  // test: punto de prueba que la lista siempre da como listado.
  const IP_LISTS = [
    { zone: 'bl.spamcop.net', label: 'SpamCop', test: '2.0.0.127', blocked: () => false },
    { zone: 'psbl.surriel.com', label: 'PSBL', test: '2.0.0.127', blocked: () => false },
    { zone: 'dnsbl.dronebl.org', label: 'DroneBL', test: '2.0.0.127', blocked: () => false },
    { zone: 'b.barracudacentral.org', label: 'Barracuda', test: '2.0.0.127', blocked: () => false },
  ];
  const DOMAIN_LISTS = [
    { zone: 'multi.uribl.com', label: 'URIBL', test: 'test.uribl.com', blocked: c => c === '127.0.0.1' },
  ];

  async function dnsbl(lists, prefix) {
    return Promise.all(lists.map(async l => {
      const out = (status, code) => Object.assign({ list: l.label, zone: l.zone, status }, code ? { code } : {});
      try {
        const r = await dns(prefix + '.' + l.zone, 'A');
        if (r.status !== 0 && !r.nx) return out('error', 'SERVFAIL');
        const codes = r.answers;
        if (codes.some(l.blocked)) return out('refused', codes.join(', '));
        if (codes.some(c => !/^127\./.test(c))) return out('error', codes.join(', '));
        if (codes.length) return out('listed', codes.join(', '));
        // Un NXDOMAIN sólo significa «limpio» si el mismo resolvedor ve listado el punto de prueba:
        // algunas listas contestan NXDOMAIN a todo lo que les llega desde un resolvedor público.
        const t = await dns(l.test + '.' + l.zone, 'A', r.provider);
        const tc = t.answers;
        if (!tc.length || tc.some(l.blocked) || tc.some(c => !/^127\./.test(c))) {
          return out('refused', tc.length ? `punto de prueba → ${tc.join(', ')}` : `punto de prueba sin listar (${DOH[r.provider].label})`);
        }
        return out('clean');
      } catch (e) {
        return out('error', e.message);
      }
    }));
  }

  // Cloudflare 1.1.1.2 (resolvedor con filtro de malware): a los dominios que clasifica como
  // maliciosos responde 0.0.0.0 con el error extendido EDE(16) «Censored». No sirve como resolvedor
  // del análisis (a esos dominios les niega TXT y MX), pero sí como lista negra.
  const CF_SECURITY = { list: 'Cloudflare 1.1.1.2', zone: 'security.cloudflare-dns.com' };
  const CF_SECURITY_IPS = ['1.1.1.2', '1.0.0.2'];

  // Se pregunta a las dos IPs del servicio a la vez y vale la primera respuesta: en algunas redes
  // una de ellas no es alcanzable y la conexión se queda colgada hasta agotar el tiempo.
  async function cfSecurityQuery(domain) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(new DOMException('Tiempo de espera agotado', 'TimeoutError')), 8000);
    try {
      return await Promise.any(CF_SECURITY_IPS.map(async ip => {
        const r = await fetch(`https://${ip}/dns-query?name=${encodeURIComponent(domain)}&type=A`,
          { signal: ctrl.signal, referrerPolicy: 'no-referrer', credentials: 'omit', headers: { accept: 'application/dns-json' } });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      }));
    } catch (e) {
      throw (e && e.errors && e.errors[0]) || e;
    } finally {
      clearTimeout(t);
      ctrl.abort(); // cancela la petición que no ganó
    }
  }

  async function cloudflareSecurity(domain) {
    try {
      const [j, real] = await Promise.all([cfSecurityQuery(domain), dns(domain, 'A').catch(() => null)]);
      const answers = (j.Answer || []).filter(a => a.type === TYPES.A).map(a => a.data);
      const ede = [].concat(j.Comment || []).join(' ');
      // 0.0.0.0 cuenta como bloqueo si lo indica el EDE o si el resolvedor normal da otra respuesta
      // (hay dominios que apuntan de verdad a 0.0.0.0).
      const blocked = answers.includes('0.0.0.0') && (/EDE\((15|16|17)\)/.test(ede) || !!(real && !real.answers.includes('0.0.0.0')));
      return Object.assign({}, CF_SECURITY, { zone: domain + ' @ ' + CF_SECURITY.zone }, blocked ? { status: 'listed', code: 'bloqueado como malicioso' } : { status: 'clean' });
    } catch (e) {
      return Object.assign({}, CF_SECURITY, { zone: domain + ' @ ' + CF_SECURITY.zone }, { status: 'error', code: e.message });
    }
  }

  const reverseIP = ip => ip.split('.').reverse().join('.');

  // ---------- comprobaciones por dominio / IP ----------

  function parseDmarc(record) {
    const t = {};
    record.split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) t[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim(); });
    return { policy: (t.p || '').toLowerCase(), subPolicy: (t.sp || '').toLowerCase(), pct: t.pct ? +t.pct : 100, rua: t.rua || '', adkim: t.adkim || 'r', aspf: t.aspf || 'r' };
  }

  async function mailDns(domain) {
    const [mx, a, spfTxt] = await Promise.all([dns(domain, 'MX'), dns(domain, 'A'), dns(domain, 'TXT')]);
    const spf = spfTxt.answers.filter(t => /^v=spf1\b/i.test(t));
    let dmarcRec = (await dns('_dmarc.' + domain, 'TXT')).answers.find(t => /^v=DMARC1/i.test(t));
    const org = Analysis.orgDomain(domain);
    let dmarcFrom = domain;
    if (!dmarcRec && org !== domain) {
      dmarcRec = (await dns('_dmarc.' + org, 'TXT')).answers.find(t => /^v=DMARC1/i.test(t));
      dmarcFrom = org;
    }
    return {
      exists: !(mx.nx && a.nx),
      nx: mx.nx && a.nx,
      mx: mx.answers.sort((x, y) => x.pref - y.pref),
      a: a.answers,
      spf: spf[0] || '',
      spfMultiple: spf.length > 1,
      dmarc: dmarcRec ? Object.assign(parseDmarc(dmarcRec), { record: dmarcRec, from: dmarcFrom }) : null,
    };
  }

  async function ptrCheck(ip) {
    const r = await dns(reverseIP(ip) + '.in-addr.arpa', 'PTR');
    const ptr = r.answers[0] || '';
    let fcrdns = null;
    if (ptr) {
      try { fcrdns = (await dns(ptr, 'A')).answers.includes(ip); } catch (_) { fcrdns = null; }
    }
    return { ptr, fcrdns };
  }

  // ---------- orquestación ----------

  // Devuelve una función que dice si un nombre DNS lleva la dirección del destinatario (en claro, con
  // la parte local sola o en base64). Un nombre así es único por destinatario: consultarlo le diría al
  // dueño del dominio quién está abriendo el correo y cuándo.
  function personalMatcher(entry) {
    const a = entry.analysis, h = entry.email.headers;
    const recipients = [...a.to, ...a.cc].map(r => r.address).concat(h.getAll('delivered-to'), h.getAll('x-original-to'))
      .map(x => String(x || '').toLowerCase().trim()).filter(x => /^[^@\s]+@[^@\s]+$/.test(x));
    const b64 = s => { try { return btoa(s).replace(/=+$/, ''); } catch (_) { return ''; } };
    const tokens = new Set();
    recipients.forEach(r => {
      const local = r.split('@')[0];
      [r.replace(/[@.]/g, '-'), local, local.replace(/[._+-]/g, ''), local.replace(/[._+]/g, '-'), b64(r), b64(r).replace(/\+/g, '-').replace(/\//g, '_')]
        .map(t => t.toLowerCase()).filter(t => t.length >= 6).forEach(t => tokens.add(t));
    });
    return name => { const n = String(name || '').toLowerCase(); return [...tokens].some(t => n.includes(t)); };
  }

  function collectTargets(entry) {
    const a = entry.analysis;
    const domains = new Map();
    const personal = personalMatcher(entry);
    const addDomain = (d, role, mail) => {
      d = (d || '').toLowerCase().replace(/\.$/, '');
      if (!d || !/\./.test(d) || Analysis.isPrivateIP(d) || /^\d+\.\d+\.\d+\.\d+$/.test(d)) return;
      // Con tu dirección en el nombre, sólo el dominio registrable (como con los enlaces).
      const masked = personal(d) && Analysis.orgDomain(d) !== d ? d : '';
      if (masked) d = Analysis.orgDomain(d);
      const cur = domains.get(d) || { domain: d, roles: [], mail: false };
      if (!cur.roles.includes(role)) cur.roles.push(role);
      cur.mail = cur.mail || !!mail;
      if (masked) cur.masked = masked;
      domains.set(d, cur);
    };
    // Reenviado por un servicio que oculta tu dirección: el From y el Return-Path son los del
    // servicio; el remitente real y su envelope-from son los que se evalúan como tales.
    const relay = a.relay;
    addDomain(relay ? relay.domain : a.fromDomain, 'From', true);
    if (relay) addDomain(a.fromDomain, 'Reenvío', true);
    addDomain(Analysis.domainOf(a.returnPath), relay ? 'Reenvío' : 'Return-Path', true);
    if (relay && relay.spf) addDomain(relay.spf.domain, 'Return-Path', true);
    (relay ? relay.replyTo : a.replyTo).forEach(r => addDomain(Analysis.domainOf(r.address), 'Reply-To', true));
    a.auth.dkimSigs.forEach(s => addDomain(s.domain, 'DKIM'));
    // De los enlaces se consulta sólo el dominio registrable, nunca el host completo:
    // los subdominios únicos por destinatario podrían delatar que se ha abierto el correo.
    const linkDomains = [...new Set(a.links.map(l => l.host).filter(h => h && !/^\[?[\d.:]+\]?$/.test(h)).map(Analysis.orgDomain))];
    linkDomains.slice(0, 15).forEach(d => addDomain(d, 'Enlace'));

    const ips = new Map();
    if (a.iocs.originIP && !/:/.test(a.iocs.originIP)) ips.set(a.iocs.originIP, { ip: a.iocs.originIP, roles: ['Origen'] });
    if (a.iocs.declaredIP && !/:/.test(a.iocs.declaredIP)) ips.set(a.iocs.declaredIP, { ip: a.iocs.declaredIP, roles: ['Primer salto'] });
    a.links.forEach(l => {
      const h = (l.host || '').replace(/^\[|\]$/g, '');
      if (/^\d+\.\d+\.\d+\.\d+$/.test(h) && !Analysis.isPrivateIP(h)) {
        const cur = ips.get(h) || { ip: h, roles: [] };
        if (!cur.roles.includes('Enlace')) cur.roles.push('Enlace');
        ips.set(h, cur);
      }
    });
    return { domains: [...domains.values()], ips: [...ips.values()] };
  }

  // URLs para Safe Browsing: los enlaces, la URL de destino que llevan embebida los
  // redireccionadores de seguimiento y los dominios del remitente (From, Return-Path, Reply-To).
  function safeBrowsingTargets(entry) {
    const a = entry.analysis;
    const out = [];
    a.links.forEach(l => {
      if (!/^(https?:|www\.)/i.test(l.href)) return;
      out.push({ url: l.href, link: l.href });
      let dec = l.href;
      for (let i = 0; i < 3; i++) { try { const d = decodeURIComponent(dec); if (d === dec) break; dec = d; } catch (_) { break; } }
      const inner = dec.slice(1).match(/https?:\/\/[^\s"'<>&]+/i);
      if (inner) out.push({ url: inner[0], link: l.href, embedded: true });
    });
    const relay = a.relay;
    const roles = new Map();
    [[a.senderDomain || a.fromDomain, 'From'],
      [relay ? relay.spf && relay.spf.domain : Analysis.domainOf(a.returnPath), 'Return-Path'],
      ...(relay ? relay.replyTo : a.replyTo).map(r => [Analysis.domainOf(r.address), 'Reply-To'])]
      .forEach(([d, role]) => {
        d = String(d || '').toLowerCase();
        if (!/\./.test(d) || /^\[?[\d.:]+\]?$/.test(d)) return;
        if (!roles.has(d)) roles.set(d, []);
        if (!roles.get(d).includes(role)) roles.get(d).push(role);
      });
    roles.forEach((r, d) => out.push({ url: `http://${d}/`, domain: d, roles: r }));
    return out;
  }

  // Veredicto de tu proveedor para una firma DKIM concreta (mismo d= y, si lo indica, mismo s=).
  function serverDkim(a, s) {
    const r = (a.auth.dkimAll || []).find(x => String(x.props['header.d'] || x.props['header.i'] || '').replace(/^.*@/, '').toLowerCase() === s.domain &&
      (!x.props['header.s'] || x.props['header.s'] === s.selector));
    return r ? r.result : null;
  }

  // Firmas DKIM que no se verifican automáticamente: consultar su clave (selector._domainkey.dominio)
  // llega al DNS del firmante. Si tu proveedor ya la comprobó, verificarla aquí apenas aporta; si el
  // nombre lleva tu dirección, además le diría al firmante quién abre el correo. Se pueden verificar a mano.
  function dkimSkipper(entry) {
    const a = entry.analysis;
    const personal = personalMatcher(entry);
    return s => {
      if (personal(s.selector) || personal(s.domain)) return 'El selector o el dominio incluyen tu dirección: consultar la clave le diría al firmante que abres el correo';
      const srv = serverDkim(a, s);
      if (srv === 'pass' || srv === 'fail') return `Tu proveedor ya la comprobó (dkim=${srv}). No se consulta la clave para no avisar al firmante de que se analiza el correo`;
      return '';
    };
  }

  async function run(entry, { onUpdate, safeBrowsingKey, verifyAllDkim } = {}) {
    const email = entry.email;
    const res = { startedAt: new Date(), done: false, provider, dkim: null, domains: {}, ips: {}, errors: [], safeBrowsing: null };
    const update = () => onUpdate && onUpdate(res);
    const { domains, ips } = collectTargets(entry);

    const tasks = [];
    tasks.push((async () => {
      // Un .msg se reconstruye a partir de propiedades MAPI: el cuerpo ya no es byte a byte el
      // firmado, así que verificar DKIM daría un «fallo» falso.
      if (email.sourceFormat === 'msg') { res.dkim = []; res.dkimSkipped = 'msg'; update(); return; }
      try { res.dkim = await global.DKIM.verifyAll(email.raw, txt, { skip: verifyAllDkim ? null : dkimSkipper(entry) }); }
      catch (e) { res.dkim = []; res.errors.push('DKIM: ' + e.message); }
      update();
    })());

    for (const d of domains) {
      const org = Analysis.orgDomain(d.domain);
      const info = res.domains[d.domain] = { domain: d.domain, org, roles: d.roles, mail: d.mail, masked: d.masked || '', dns: null, rdap: null, dnsbl: null };
      tasks.push((async () => {
        try {
          if (d.mail) info.dns = await mailDns(d.domain);
          else { const r = await dns(d.domain, 'A'); info.dns = { exists: !r.nx, nx: r.nx, a: r.answers, mx: [], light: true }; }
        } catch (e) { info.dns = { error: e.message }; }
        update();
      })());
      tasks.push((async () => {
        // En github.io, pages.dev… el WHOIS sería el de la plataforma, no el del cliente que publica.
        const platform = Analysis.sharedHostOf(org);
        if (platform) { info.rdap = { error: `Subdominio de ${platform}, una plataforma de alojamiento: su WHOIS sería el de la plataforma`, unsupported: true }; update(); return; }
        try { info.rdap = await rdapDomain(org); }
        catch (e) { info.rdap = { error: /Failed to fetch|NetworkError|TypeError/i.test(e.message) ? 'El servidor RDAP no responde o no permite consultas desde el navegador' : e.message }; }
        update();
      })());
      tasks.push((async () => {
        // Las listas DNSBL se consultan con el dominio registrable; Cloudflare, con el mismo nombre que la consulta DNS.
        const [bl, cf] = await Promise.all([dnsbl(DOMAIN_LISTS, org), cloudflareSecurity(d.domain)]);
        info.dnsbl = bl.concat(cf);
        update();
      })());
    }

    for (const i of ips) {
      const info = res.ips[i.ip] = { ip: i.ip, roles: i.roles, rdap: null, ptr: null, dnsbl: null };
      tasks.push((async () => {
        try { info.rdap = await rdapIP(i.ip); } catch (e) { info.rdap = { error: e.message }; }
        update();
      })());
      // El DNS inverso lo contesta quien controla la zona inversa de la IP. La IP de origen ya la
      // consultó tu proveedor al recibir el correo; la del primer salto o la de un enlace las elige
      // el remitente, que podría usar una IP suya para ver quién analiza el correo.
      if (i.roles.includes('Origen')) {
        tasks.push((async () => {
          try { info.ptr = await ptrCheck(i.ip); } catch (e) { info.ptr = { error: e.message }; }
          update();
        })());
      } else info.ptr = { skipped: true };
      tasks.push((async () => {
        info.dnsbl = await dnsbl(IP_LISTS, reverseIP(i.ip));
        update();
      })());
    }

    if (safeBrowsingKey && global.SafeBrowsing) {
      tasks.push((async () => {
        const targets = safeBrowsingTargets(entry);
        if (!targets.length) { res.safeBrowsing = { skipped: 'sin enlaces ni dominios' }; update(); return; }
        const to = withTimeout(20000);
        try { res.safeBrowsing = await global.SafeBrowsing.check(targets, safeBrowsingKey, { signal: to.signal }); }
        catch (e) { res.safeBrowsing = { error: e.message }; res.errors.push('Google Safe Browsing: ' + e.message); }
        finally { to.done(); }
        update();
      })());
    } else {
      res.safeBrowsing = { skipped: 'sin clave' };
    }

    await Promise.all(tasks);
    res.done = true;
    res.finishedAt = new Date();
    res.findings = findingsFrom(entry, res);
    flagLinks(entry, res);
    update();
    return res;
  }

  // Copia en cada enlace los problemas de su dominio (o IP), para que la lista de enlaces y su
  // resumen no digan «sin alertas» cuando hay un hallazgo sobre ese mismo dominio.
  function flagLinks(entry, res) {
    const links = entry.analysis.links;
    links.forEach(l => { l.flags = l.flags.filter(f => !f.online); }); // al repetir las comprobaciones
    const byOrg = {};
    Object.values(res.domains).filter(d => d.roles.includes('Enlace')).forEach(d => {
      const out = byOrg[d.domain] = [];
      const r = d.rdap;
      if (d.dns && d.dns.nx) out.push({ sev: 'medium', msg: 'El dominio no existe' });
      if (r && r.ageDays != null && r.ageDays < 30) out.push({ sev: 'high', msg: `Dominio registrado hace ${r.ageDays} días` });
      else if (r && r.ageDays != null && r.ageDays < 180) out.push({ sev: 'medium', msg: `Dominio reciente (${r.ageDays} días)` });
      if (r && r.status && r.status.some(x => /hold/i.test(x))) out.push({ sev: 'medium', msg: 'Dominio suspendido por el registro' });
      const listed = (d.dnsbl || []).filter(x => x.status === 'listed');
      if (listed.length) out.push({ sev: 'high', msg: `Dominio en listas negras (${listed.map(x => x.list).join(', ')})` });
    });
    const byIp = {};
    Object.values(res.ips).filter(i => i.roles.includes('Enlace')).forEach(i => {
      const listed = (i.dnsbl || []).filter(x => x.status === 'listed');
      if (listed.length) byIp[i.ip] = [{ sev: 'high', msg: `IP en listas negras (${listed.map(x => x.list).join(', ')})` }];
    });
    const sbHits = {};
    ((res.safeBrowsing && res.safeBrowsing.matches) || []).forEach(m => {
      (sbHits[m.link] = sbHits[m.link] || []).push({ sev: 'high', msg: `Google Safe Browsing${m.embedded ? ' (destino embebido)' : ''}: ${m.threats.map(global.SafeBrowsing.label).join(', ')}` });
    });
    links.forEach(l => {
      const host = (l.host || '').replace(/^\[|\]$/g, '');
      const extra = (byIp[host] || byOrg[Analysis.orgDomain(host)] || []).concat(sbHits[l.href] || []);
      extra.forEach(f => l.flags.push(Object.assign({ online: true }, f)));
    });
  }

  // ---------- hallazgos derivados ----------

  function findingsFrom(entry, res) {
    const a = entry.analysis;
    const out = [];
    const add = (sev, category, title, detail, points, extra) => out.push(Object.assign({ sev, category, title, detail: detail || '', online: true }, points != null ? { points } : {}, extra));
    // Ver Analysis.scoreFindings: trust = evidencia a favor del remitente; voidsTrust = el dominio del From es sospechoso y la anula.
    const TRUST = { trust: true };
    const voidsIfFrom = d => (d.roles.includes('From') ? { voidsTrust: true } : undefined);

    // DKIM criptográfico
    const sigs = res.dkim || [];
    const arDkim = a.summary.dkim;
    const senderDomain = a.senderDomain || a.fromDomain;
    const sameOrg = (x, y) => !!x && !!y && Analysis.orgDomain(x) === Analysis.orgDomain(y);
    const senderAuthenticated = a.relay ? a.relay.authenticated : a.summary.dmarc === 'pass' || a.summary.msAuth === '1' ||
      sigs.some(s => s.result === 'pass' && !s.partialBody && sameOrg(s.domain, senderDomain));
    sigs.forEach(s => {
      const aligned = sameOrg(s.domain, senderDomain);
      const relaySig = a.relay && sameOrg(s.domain, a.relay.relayDomain);
      const who = `d=${s.domain} s=${s.selector}`;
      if (s.result === 'pass') {
        if (s.partialBody) add('high', 'dkim', 'Contenido añadido fuera de la firma DKIM (l=)', `${who}: hay ${s.partialBody} bytes después de la parte firmada; alguien pudo añadir texto o enlaces.`);
        else if (s.testing) add('low', 'dkim', 'DKIM válido con clave en modo pruebas (t=y)', who);
        // Resta riesgo sólo si aporta algo nuevo: firma alineada y el servidor receptor no la había validado ya.
        else add('ok', 'dkim', `DKIM verificado criptográficamente${aligned ? ' y alineado' : relaySig ? ' (firma del reenvío de Apple)' : ''}`, who + (s.expired ? ' · firma caducada' : '') + (s.keyBits ? ` · clave de ${s.keyBits} bits` : ''),
          aligned && arDkim !== 'pass' && !s.expired ? -5 : undefined, TRUST);
        if (s.keyBits && s.keyBits < 2048 && s.algorithm !== 'ed25519-sha256') add('info', 'dkim', `Clave DKIM de ${s.keyBits} bits`, 'Se recomiendan 2048 bits o más.');
      } else if (s.result === 'fail') {
        const title = s.bodyHashOk === false ? 'DKIM: el cuerpo se modificó tras la firma' : 'DKIM: firma criptográfica inválida';
        const srv = serverDkim(a, s);
        const byApple = a.relay && a.relay.dkim.find(r => r.domain === s.domain);
        if (srv ? srv === 'pass' : arDkim === 'pass') {
          add('low', 'dkim', title, `${who}. ${s.reason}. El servidor receptor la dio por buena, así que probablemente el .eml se modificó al exportarlo o reenviarlo.`);
        } else if (a.relay && !relaySig) {
          add('info', 'dkim', 'Firma original invalidada por el reenvío de Apple', `${who}. Apple reescribe el From y el To al reenviar el correo, lo que rompe las firmas del remitente original: es lo esperado.` +
            (byApple ? ` Apple la comprobó al recibirlo (dkim=${byApple.result}).` : ''));
        } else if (!aligned && senderAuthenticated) {
          add('low', 'dkim', 'DKIM: firma de terceros inválida', `${who}. ${s.reason}. No afecta a la autenticación: el remitente está respaldado por otra firma o por DMARC.`);
        } else {
          add('high', 'dkim', title, `${who}. ${s.reason}.`);
        }
      } else if (s.result === 'permerror') {
        add(/No existe la clave|revocada/.test(s.reason) ? 'medium' : 'low', 'dkim', 'DKIM no verificable', `${who}: ${s.reason}.`);
      } else if (s.result === 'temperror') {
        add('info', 'dkim', 'DKIM: error temporal de DNS', `${who}: ${s.reason}`);
      }
    });

    // Dominios inexistentes: una sola alerta por dominio registrable.
    const nxByOrg = {};
    Object.values(res.domains).filter(d => d.dns && d.dns.nx).forEach(d => {
      const g = nxByOrg[d.org] = nxByOrg[d.org] || { hosts: [], roles: new Set(), mail: false };
      g.hosts.push(d.domain);
      d.roles.forEach(r => g.roles.add(r));
      g.mail = g.mail || d.mail;
    });
    Object.entries(nxByOrg).forEach(([org, g]) => {
      const roles = [...g.roles].join(', ');
      add(g.mail ? 'high' : 'medium', 'dns', `El dominio ${org} no existe`, `${g.hosts.length > 1 ? 'Nombres afectados: ' + g.hosts.join(', ') + '. ' : ''}Rol: ${roles}. NXDOMAIN: ${g.mail ? 'no puede enviar ni recibir correo legítimo' : 'el enlace apunta a un dominio dado de baja o inventado'}.`);
    });

    // Dominios
    Object.values(res.domains).forEach(d => {
      const roles = d.roles.join(', ');
      if (d.dns && d.dns.nx) {
        /* ya agrupado arriba */
      } else if (d.dns && d.mail && !d.dns.error) {
        if (!d.dns.mx.length && !d.dns.a.length) {
          if (d.dns.spf) add('info', 'dns', `${d.domain} no recibe correo (sin MX ni A)`, `Rol: ${roles}. Es normal en subdominios usados sólo para enviar (tiene SPF), pero las respuestas no llegarán a esta dirección.`);
          else add('medium', 'dns', `${d.domain} no tiene MX, A ni SPF`, `Rol: ${roles}. El dominio existe pero no está preparado para enviar ni recibir correo.`);
        }
        if (d.roles.includes('From')) {
          if (!d.dns.dmarc) add('low', 'dns', `${d.domain} no publica DMARC`, 'Cualquiera puede suplantar este dominio sin que los receptores lo rechacen.');
          else if (d.dns.dmarc.policy === 'none') add('info', 'dns', `DMARC de ${d.domain} en modo monitorización (p=none)`, 'Los correos que fallan no se rechazan ni se ponen en cuarentena.');
          if (!d.dns.spf) add('low', 'dns', `${d.domain} no publica SPF`, '');
          if (d.dns.spfMultiple) add('low', 'dns', `${d.domain} tiene varios registros SPF`, 'Es un error de configuración (permerror).');
        }
      }
      const r = d.rdap;
      if (r && r.ageDays != null) {
        const fromNote = d.roles.includes('From') ? ' Aunque el correo esté autenticado, eso sólo prueba que lo envió quien registró este dominio.' : '';
        if (r.ageDays < 30) add('high', 'whois', `Dominio registrado hace ${r.ageDays} días: ${d.org}`, `Rol: ${roles}. Los dominios recién creados son típicos de campañas de phishing.${fromNote}`, undefined, voidsIfFrom(d));
        else if (r.ageDays < 180) add('medium', 'whois', `Dominio reciente (${r.ageDays} días): ${d.org}`, `Rol: ${roles}. Registrado el ${r.created.toLocaleDateString('es-ES')}.${fromNote}`, undefined, voidsIfFrom(d));
        else if (d.roles.includes('From') && r.ageDays >= 730 && !Analysis.lookalike(d.domain)) {
          const years = Math.floor(r.ageDays / 365);
          const since = `${d.org} está registrado desde ${r.created.toLocaleDateString('es-ES')}${r.registrar ? ' (' + r.registrar + ')' : ''}.`;
          // La antigüedad sólo cuenta si el remitente demuestra que usa ese dominio: si no,
          // cualquiera puede haber escrito un dominio antiguo en el From.
          if (senderAuthenticated) add('ok', 'whois', `Dominio del remitente con ${years} años de antigüedad`, `${since} Los dominios de phishing suelen tener días o semanas.`, years >= 10 ? -10 : -5, TRUST);
          else add('info', 'whois', `Dominio del remitente con ${years} años de antigüedad, pero sin autenticar`, `${since} Como el envío no está autenticado, podría ser una suplantación de un dominio legítimo: no resta riesgo.`);
        }
      }
      if (r && r.status && r.status.some(s => /hold/i.test(s))) add('medium', 'whois', `${d.org} está suspendido por el registro (${r.status.filter(s => /hold/i.test(s)).join(', ')})`, 'Suele indicar abuso denunciado.', undefined, voidsIfFrom(d));
      if (r && r.notFound && d.dns && d.dns.exists) add('low', 'whois', `${d.org} resuelve en DNS pero no figura en el registro RDAP`, `Rol: ${roles}.`);
      const listed = (d.dnsbl || []).filter(x => x.status === 'listed');
      // Las DNSBL se consultan con el dominio registrable; Cloudflare, con el nombre completo.
      if (listed.length) add('high', 'reputacion', `${listed.some(x => x.list === CF_SECURITY.list) ? d.domain : d.org} aparece en listas negras de dominios`,listed.map(x => `${x.list} (${x.code})`).join(', ') + `. Rol: ${roles}.`, undefined, voidsIfFrom(d));
    });

    // Google Safe Browsing: una coincidencia confirmada por Google es casi concluyente, así que
    // basta por sí sola para el nivel alto aunque se descuenten las evidencias a favor (máx. 10).
    const SB_POINTS = 60;
    const sb = res.safeBrowsing;
    if (sb && sb.matches) {
      const SB = global.SafeBrowsing;
      const threatsOf = ms => [...new Set([].concat(...ms.map(m => m.threats)))].map(SB.label).join(', ');
      const linkHits = sb.matches.filter(m => !m.domain), domainHits = sb.matches.filter(m => m.domain);
      if (linkHits.length) {
        add('high', 'reputacion', `Enlace en las listas de Google Safe Browsing (${threatsOf(linkHits)})`,
          linkHits.slice(0, 3).map(m => `${m.url.slice(0, 120)}${m.embedded ? ' (destino dentro de un redireccionador)' : ''} → ${m.threats.map(SB.label).join(', ')}`).join(' · ') +
          '. Aviso proporcionado por Google.', SB_POINTS);
      }
      if (domainHits.length) {
        add('high', 'reputacion', `Dominio del remitente en las listas de Google Safe Browsing (${threatsOf(domainHits)})`,
          domainHits.map(m => `${m.domain} (${m.roles.join(', ')}) → ${m.threats.map(SB.label).join(', ')}`).join(' · ') + '. Aviso proporcionado por Google.',
          SB_POINTS, domainHits.some(m => m.roles.includes('From')) ? { voidsTrust: true } : undefined);
      }
      if (!sb.matches.length) {
        const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
        add('info', 'reputacion', `Google Safe Browsing: sin coincidencias (${n(sb.urls, 'URL', 'URLs')} y ${n(sb.domains || 0, 'dominio del remitente', 'dominios del remitente')})`,
          `Se enviaron sólo ${sb.prefixes} prefijos de hash de 4 bytes, no las URLs ni los dominios. Que no figuren no garantiza que sean seguros: las campañas más recientes aún no están en las listas.`);
      }
    }

    // IPs
    Object.values(res.ips).forEach(i => {
      const listed = (i.dnsbl || []).filter(x => x.status === 'listed');
      if (listed.length) add(i.roles.includes('Origen') ? 'high' : 'medium', 'reputacion', `La IP ${i.ip} está en listas negras`, listed.map(x => `${x.list} (${x.code})`).join(', ') + `. Rol: ${i.roles.join(', ')}.`);
      if (i.roles.includes('Origen') && i.ptr && !i.ptr.error) {
        if (!i.ptr.ptr) add('low', 'dns', `La IP de origen ${i.ip} no tiene DNS inverso`, 'Los servidores de correo legítimos casi siempre tienen PTR.');
        else if (/(\d{1,3}[-.]){3}\d{1,3}|dyn|dsl|dhcp|pool|cable|broadband|customer|client|ppp/i.test(i.ptr.ptr)) add('low', 'dns', 'PTR genérico/residencial en la IP de origen', i.ptr.ptr);
        else if (i.ptr.fcrdns === false) add('info', 'dns', 'El DNS inverso de la IP de origen no confirma en directo', `${i.ip} → ${i.ptr.ptr} → no resuelve a ${i.ip}`);
      }
      if (i.rdap && i.rdap.country && i.roles.includes('Origen')) add('info', 'whois', `IP de origen en ${i.rdap.country}`, [i.rdap.name || i.rdap.org, i.rdap.range].filter(Boolean).join(' · '));
    });
    return out;
  }

  // Estado de reputación de cada IOC según las comprobaciones en línea, para la pestaña IOCs y el CSV.
  // Cada valor: { checked, issues: [{ sev, msg }] }. Sin entrada = no se ha consultado.
  function iocStatus(entry, o) {
    o = o || entry.online;
    const a = entry.analysis;
    const out = { ran: !!(o && o.done && !o.error), ips: {}, domains: {}, urls: {}, safeBrowsing: o && o.safeBrowsing };
    if (!out.ran) return out;
    const sb = o.safeBrowsing && o.safeBrowsing.matches ? o.safeBrowsing : null;
    const SB = global.SafeBrowsing;
    const listedIn = l => (l || []).filter(x => x.status === 'listed').map(x => x.list);

    a.iocs.ips.forEach(ip => {
      const info = o.ips[ip];
      if (!info) return;
      const bl = listedIn(info.dnsbl);
      out.ips[ip] = { checked: true, issues: bl.length ? [{ sev: 'high', msg: 'Listas negras: ' + bl.join(', ') }] : [] };
    });
    const domainIssues = d => {
      const info = o.domains[d] || o.domains[Analysis.orgDomain(d)];
      const issues = [];
      if (info) {
        const r = info.rdap;
        if (info.dns && info.dns.nx) issues.push({ sev: 'high', msg: 'No existe' });
        if (r && r.ageDays != null && r.ageDays < 30) issues.push({ sev: 'high', msg: `Registrado hace ${r.ageDays} días` });
        else if (r && r.ageDays != null && r.ageDays < 180) issues.push({ sev: 'medium', msg: `Reciente (${r.ageDays} días)` });
        if (r && r.status && r.status.some(x => /hold/i.test(x))) issues.push({ sev: 'medium', msg: 'Suspendido por el registro' });
        const bl = listedIn(info.dnsbl);
        if (bl.length) issues.push({ sev: 'high', msg: 'Listas negras: ' + bl.join(', ') });
      }
      // Safe Browsing a nivel de dominio: el dominio consultado como tal, o una expresión «host/» que lo cubre.
      const hit = sb && sb.matches.find(m => {
        if (m.domain === d) return true;
        const host = /^[^/]+\/$/.test(m.expression) ? m.expression.slice(0, -1) : '';
        return host && (d === host || d.endsWith('.' + host));
      });
      if (hit) issues.push({ sev: 'high', msg: 'Google Safe Browsing: ' + hit.threats.map(SB.label).join(', ') });
      return info || sb ? { checked: true, issues } : null;
    };
    a.iocs.domains.forEach(d => {
      const st = domainIssues(d);
      if (st) out.domains[d] = st;
    });
    // Una URL hereda las alertas de su dominio (o de su IP): si el dominio no existe, la URL tampoco puede estar «sin coincidencias».
    a.iocs.urls.forEach(u => {
      if (!/^(https?:|www\.)/i.test(u)) return;
      let host = '';
      try { host = new URL(/^www\./i.test(u) ? 'http://' + u : u).hostname.toLowerCase().replace(/^\[|\]$/g, ''); } catch (_) { /* URL inválida */ }
      const hostSt = !host ? null : o.ips[host] ? out.ips[host] : domainIssues(host);
      const hits = sb ? sb.matches.filter(m => !m.domain && (m.link === u || m.url === u)) : [];
      if (!sb && !hostSt) return;
      out.urls[u] = { checked: true, issues: [
        ...hits.map(m => ({ sev: 'high', msg: `Google Safe Browsing${m.embedded ? ' (destino embebido)' : ''}: ${m.threats.map(SB.label).join(', ')}` })),
        ...(hostSt ? hostSt.issues.filter(x => !/^Google Safe Browsing/.test(x.msg) || !hits.length).map(x => ({ sev: x.sev, msg: `${x.msg} (${o.ips[host] ? 'IP' : 'dominio'})` })) : []),
      ] };
    });
    return out;
  }

  global.Online = {
    run,
    iocStatus,
    dns,
    txt,
    rdapDomain,
    rdapIP,
    providers: DOH,
    setProvider(p) { if (DOH[p]) { provider = p; } },
    getProvider: () => provider,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);

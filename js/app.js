(function () {
  'use strict';

  // ---------- utilidades ----------

  const $ = (sel, root) => (root || document).querySelector(sel);
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ESC[c]);
  const fmtBytes = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB';
  const fmtDate = d => d ? d.toLocaleString('es-ES', { dateStyle: 'medium', timeStyle: 'medium' }) : '—';
  const fmtDelay = s => s == null ? '' : Math.abs(s) < 60 ? `${Math.round(s)} s` : Math.abs(s) < 3600 ? `${Math.round(s / 60)} min` : `${(s / 3600).toFixed(1)} h`;
  const addr = a => a ? (a.name ? `${a.name} <${a.address}>` : a.address) : '';
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const SEV_LABEL = { high: 'Alto', medium: 'Medio', low: 'Bajo', info: 'Info', ok: 'OK' };
  const LEVEL_LABEL = { bajo: 'Riesgo bajo', medio: 'Riesgo medio', alto: 'Riesgo alto' };
  const CAT_LABEL = { auth: 'Autenticación', dkim: 'DKIM', remitente: 'Remitente', cabeceras: 'Cabeceras', ruta: 'Ruta', enlaces: 'Enlaces', html: 'HTML',
    adjuntos: 'Adjuntos', contenido: 'Contenido', estructura: 'Estructura', dominios: 'Dominios', antispam: 'Antispam', qr: 'Código QR', dns: 'DNS',
    whois: 'WHOIS', reputacion: 'Reputación' };
  // Pestaña donde se ve el detalle de cada categoría de hallazgo.
  const CAT_TAB = { auth: 'auth', dkim: 'auth', remitente: 'auth', antispam: 'auth', cabeceras: 'cabeceras', ruta: 'ruta', enlaces: 'enlaces',
    dominios: 'enlaces', html: 'contenido', contenido: 'contenido', adjuntos: 'adjuntos', qr: 'adjuntos', estructura: 'estructura', dns: 'reputacion',
    whois: 'reputacion', reputacion: 'reputacion' };
  const TAB_GROUPS = [
    { id: 'resumen', label: 'Resumen' },
    { id: 'contenido', label: 'Contenido' },
    { id: 'origen', label: 'Origen', sub: [['auth', 'Autenticación'], ['ruta', 'Ruta de entrega']] },
    { id: 'enlaces', label: 'Enlaces' },
    { id: 'adjuntos', label: 'Adjuntos' },
    { id: 'reputacion', label: 'DNS y WHOIS' },
    { id: 'iocs', label: 'IOCs' },
    { id: 'avanzado', label: 'Avanzado', sub: [['cabeceras', 'Cabeceras'], ['estructura', 'Estructura MIME'], ['fuente', 'Código fuente']] },
  ];
  const groupOf = id => TAB_GROUPS.find(g => g.id === id || (g.sub && g.sub.some(x => x[0] === id))) || TAB_GROUPS[0];
  const ICON = {
    clip: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 11l-8.5 8.5a5 5 0 0 1-7-7L14 4a3.5 3.5 0 0 1 5 5l-8.5 8.5a2 2 0 0 1-3-3L15 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    qr: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 18h2v2h-2zM14 18h2v2h-2zM18 14h2v2h-2z" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>',
    chevron: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    shield: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>',
    link: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    globe: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>',
    gear: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    spark: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>',
  };
  const LANG_NAMES = { en: 'inglés', es: 'español', fr: 'francés', de: 'alemán', it: 'italiano', pt: 'portugués', nl: 'neerlandés', ca: 'catalán', ru: 'ruso', zh: 'chino', ja: 'japonés', pl: 'polaco', tr: 'turco', ar: 'árabe' };
  const IS_EDGE = /\bEdg\//.test(navigator.userAgent);
  const MODEL = IS_EDGE ? 'Phi-4-mini' : 'Gemini Nano';

  function toast(msg) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => t.classList.remove('show'), 2600);
  }

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast('Copiado al portapapeles'); }
    catch (_) { toast('No se pudo copiar'); }
  }

  function download(name, data, type) {
    const blob = data instanceof Blob ? data : new Blob([data], { type: type || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name.replace(/[‪-‮⁦-⁩]/g, '').replace(/[\\/:*?"<>|]+/g, '_') || 'archivo';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  function md(text) {
    const inline = s => s
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>');
    let out = '', list = false;
    for (const line of esc(text).split('\n')) {
      const li = line.match(/^\s*(?:[-*•]|\d+[.)])\s+(.*)$/);
      if (li) { if (!list) { out += '<ul>'; list = true; } out += '<li>' + inline(li[1]) + '</li>'; continue; }
      if (list) { out += '</ul>'; list = false; }
      if (!line.trim()) continue;
      const hd = line.match(/^#{1,6}\s+(.*)$/);
      out += hd ? '<p><strong>' + inline(hd[1]) + '</strong></p>' : '<p>' + inline(line) + '</p>';
    }
    return out + (list ? '</ul>' : '');
  }

  // ---------- estado ----------

  const state = {
    entries: [],
    currentId: null,
    tab: 'resumen',
    ai: { status: null, progress: null },
    linkFilter: false,
    headerFilter: '',
    settings: { autoOnline: true, provider: 'cloudflare', defang: false, sbKey: '', version: 2 },
    lastSub: { origen: 'auth', avanzado: 'cabeceras' },
    sidebarFilter: '',
    sidebarOpen: false,
    loading: null,
    openGroups: { info: false, ok: false },
    settingsOpen: false,
  };
  let nextId = 1;
  const current = () => state.entries.find(e => e.id === state.currentId);

  try {
    const saved = JSON.parse(localStorage.getItem('eml-settings') || '{}');
    // v2: las comprobaciones en línea pasan a estar activadas por defecto; se ignora
    // el valor guardado por versiones anteriores, que siempre era el antiguo por defecto.
    if ((saved.version || 1) < 2) delete saved.autoOnline;
    Object.assign(state.settings, saved, { version: 2 });
  } catch (_) { /* sin almacenamiento */ }
  Online.setProvider(state.settings.provider);
  function saveSettings() {
    try { localStorage.setItem('eml-settings', JSON.stringify(state.settings)); } catch (_) { /* sin almacenamiento */ }
  }

  // Clave de Safe Browsing: la del campo de la pestaña DNS y WHOIS o, si está vacío, la de config.js.
  const configSbKey = () => String((window.EML_CONFIG && window.EML_CONFIG.safeBrowsingKey) || '').trim();
  const sbKey = () => (state.settings.sbKey || '').trim() || configSbKey();
  // En el servidor publicado, config.js apunta al proxy que añade la clave del sitio.
  const sbProxy = () => String((window.EML_CONFIG && window.EML_CONFIG.safeBrowsingProxy) || '').trim();

  // Une los hallazgos del análisis local, de los QR y de las comprobaciones en línea.
  function rescore(entry) {
    const local = [...entry.analysis.findings, ...(entry.qrFindings || [])];
    const list = [...local, ...((entry.online && entry.online.findings) || [])];
    Analysis.sortFindings(list);
    entry.findings = list;
    Object.assign(entry, Analysis.scoreFindings(list, entry.analysis.summary));
    entry.localScore = Analysis.scoreFindings(local, entry.analysis.summary).score;
  }

  // Las comprobaciones en línea ya terminaron y han contado para la puntuación.
  const onlineApplied = entry => !!(entry.online && !entry.online.running && !entry.online.error && entry.online.findings);

  // Vista del análisis que se pasa a la IA, con todos los hallazgos.
  const aiView = entry => Object.assign({}, entry.analysis, { findings: entry.findings, trustVoided: entry.trustVoided, voidedBy: entry.voidedBy });

  // ---------- carga de ficheros ----------

  async function loadFiles(files) {
    files = files.filter(f => {
      if (f.size > 60 * 1024 * 1024) { toast(`${f.name} es demasiado grande (${fmtBytes(f.size)})`); return false; }
      return true;
    });
    if (!files.length) return;
    setLoading(0, files.length);
    let shown = false;
    for (let i = 0; i < files.length; i++) {
      setLoading(i, files.length, files[i].name);
      // Se muestra el primero de la tanda que se pueda analizar; el resto sólo se añade a la lista.
      if (await addEmail(new Uint8Array(await files[i].arrayBuffer()), files[i].name, undefined, !shown)) shown = true;
    }
    setLoading(null);
  }

  function setLoading(done, total, name) {
    state.loading = done == null ? null : { done, total, name };
    const bar = $('#busy-bar');
    bar.hidden = !state.loading;
    const st = $('#loading-status');
    st.hidden = !state.loading;
    if (state.loading) st.textContent = total > 1 ? `Analizando ${done + 1} de ${total}${name ? ': ' + name : ''}…` : `Analizando${name ? ' ' + name : ''}…`;
  }

  async function addEmail(bytes, name, parentId, select = true) {
    try {
      // .msg de Outlook: se convierte a .eml antes de analizarlo.
      let msgInfo = null;
      if (MSG.isMsg(bytes)) {
        const conv = MSG.toEml(bytes);
        bytes = conv.bytes;
        msgInfo = conv.info;
      }
      const email = MIME.parseEmail(bytes, name);
      if (msgInfo) { email.sourceFormat = 'msg'; email.msgInfo = msgInfo; }
      if (parentId) email.attached = true;
      if (!email.headers.list.length) throw new Error('no parece un correo (no hay cabeceras)');
      const analysis = await Analysis.analyze(email);
      const entry = {
        id: nextId++, name, email, analysis, parentId,
        ai: { chatLog: [], ctrl: {} },
        view: { mode: email.html ? 'html' : 'text', remote: false },
        online: null,
        qr: [],
        qrFindings: [],
      };
      rescore(entry);
      state.entries.push(entry);
      if (select || !current()) {
        state.currentId = entry.id;
        state.tab = 'resumen';
        state.sidebarOpen = false;
        render();
      } else renderSidebar();
      detectLanguage(entry);
      // Las comprobaciones en línea esperan a la lectura de los QR para consultar también sus enlaces.
      const qr = scanQR(entry);
      if (state.settings.autoOnline) qr.then(() => { if (state.entries.includes(entry)) runOnline(entry); });
      return entry;
    } catch (e) {
      console.error(e);
      toast(`No se pudo analizar ${name}: ${e.message}`);
    }
  }

  // ---------- códigos QR (quishing) ----------

  async function scanQR(entry) {
    const a = entry.analysis;
    if (!a.attachments.length || typeof QR === 'undefined') return;
    let found;
    try { found = await QR.scan(a.attachments); } catch (_) { return; }
    if (!found.length) return;
    entry.qr = found;
    entry.qrFindings = [];
    let newLinks = false;
    for (const q of found) {
      const text = q.text.trim();
      const isUrl = /^(https?:\/\/|www\.)/i.test(text);
      if (!isUrl) {
        entry.qrFindings.push({ sev: /^(mailto|tel|sms|smsto|wifi|bitcoin|ethereum):/i.test(text) ? 'low' : 'info', category: 'qr', title: `Código QR en «${q.attachment.name}»`, detail: text.slice(0, 200) });
        continue;
      }
      const link = Object.assign(Analysis.analyzeURL(text, ''), { source: 'QR · ' + q.attachment.name });
      const look = Analysis.lookalike(link.host);
      if (look) link.flags.push({ sev: look.kind === 'tld' ? 'medium' : 'high', msg: 'Imita a ' + look.brand });
      q.link = link;
      a.links.push(link);
      newLinks = true;
      if (!a.iocs.urls.includes(link.href)) a.iocs.urls.push(link.href);
      const isIpHost = /^\d{1,3}(\.\d{1,3}){3}$|:/.test(link.host.replace(/^\[|\]$/g, ''));
      if (link.host && !isIpHost && !a.iocs.domains.includes(link.host)) a.iocs.domains.push(link.host);
      const bad = link.flags.some(f => f.sev === 'high');
      entry.qrFindings.push({
        sev: bad ? 'high' : 'medium', category: 'qr',
        title: `Código QR con enlace en «${q.attachment.name}»`,
        detail: `${link.href.slice(0, 160)}${link.flags.length ? ' · ' + link.flags.map(f => f.msg).join(' · ') : ''}. Los QR se usan para esquivar los filtros de enlaces (quishing) y llevar a la víctima al móvil.`,
      });
    }
    rescore(entry);
    if (state.entries.includes(entry)) render();
    // Si las comprobaciones en línea ya se lanzaron (a mano), se repiten para incluir los enlaces de los QR.
    if (newLinks && entry.online) {
      if (entry.online.running) entry.onlineStale = true;
      else runOnline(entry);
    }
  }

  // ---------- comprobaciones en línea ----------

  let onlineRenderTimer = null;
  function scheduleOnlineRender(entry) {
    if (entry !== current() || !['reputacion', 'auth'].includes(state.tab)) return;
    if (onlineRenderTimer) return;
    onlineRenderTimer = setTimeout(() => { onlineRenderTimer = null; if (entry === current()) renderTabOnly(); }, 200);
  }

  async function runOnline(entry) {
    if (entry.online && entry.online.running) return;
    entry.online = { running: true, domains: {}, ips: {}, dkim: null, findings: [] };
    if (entry === current()) render();
    try {
      const res = await Online.run(entry, {
        safeBrowsingKey: sbKey(),
        safeBrowsingProxy: sbProxy(),
        verifyAllDkim: !!entry.verifyAllDkim,
        onUpdate: r => { entry.online = Object.assign(r, { running: !r.done }); scheduleOnlineRender(entry); },
      });
      entry.online = Object.assign(res, { running: false });
    } catch (e) {
      console.error(e);
      entry.online = { running: false, error: e.message, domains: {}, ips: {}, dkim: [], findings: [] };
    }
    const prev = entry.score;
    rescore(entry);
    if (!state.entries.includes(entry)) return;
    render();
    if (entry.online.error) toast('No se pudieron completar las comprobaciones en línea');
    else if (entry.score !== prev) toast(`Riesgo recalculado con DNS y WHOIS: ${prev} → ${entry.score}`);
    else toast(`Comprobaciones completadas: el riesgo se mantiene en ${entry.score}`);
    if (entry.onlineStale) { entry.onlineStale = false; runOnline(entry); }
  }

  function removeEntry(id) {
    const i = state.entries.findIndex(e => e.id === id);
    if (i < 0) return;
    const [entry] = state.entries.splice(i, 1);
    Object.values(entry.ai.ctrl).forEach(c => c && c.abort());
    if (entry.ai.chat) entry.ai.chat.destroy();
    if (state.currentId === id) state.currentId = (state.entries[i] || state.entries[i - 1] || {}).id || null;
    render();
  }

  // ---------- render general ----------

  function render() {
    renderSidebar();
    renderMain();
  }

  // Fecha corta para la lista: hora si es de hoy, día y mes si es de este año.
  function fmtShort(d) {
    if (!d) return '';
    const now = new Date();
    if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
    if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString('es-ES', { day: 'numeric', month: 'short' });
    return d.toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit', year: 'numeric' });
  }

  function visibleEntries() {
    const q = state.sidebarFilter.trim().toLowerCase();
    if (!q) return state.entries;
    return state.entries.filter(e => {
      const a = e.analysis;
      return [a.subject, a.from.name, a.from.address, e.name].some(v => String(v || '').toLowerCase().includes(q));
    });
  }

  function renderSidebar() {
    const list = $('#file-list');
    const n = state.entries.length;
    $('#clear-all').hidden = n < 2;
    $('#entry-count').textContent = n ? n : '';
    $('.sidebar-search').hidden = n < 3;
    const cur = current();
    $('#sidebar-current').textContent = cur ? (cur.analysis.subject || '(sin asunto)') : '';
    $('#sidebar').classList.toggle('open', state.sidebarOpen);
    $('#sidebar-toggle').setAttribute('aria-expanded', state.sidebarOpen);
    if (!n) {
      list.innerHTML = '<li class="empty">Aún no hay correos.<br>Arrástralos a la ventana o pulsa <kbd>O</kbd>.</li>';
      return;
    }
    const items = visibleEntries();
    if (!items.length) {
      list.innerHTML = '<li class="empty">Ningún correo coincide con la búsqueda.</li>';
      return;
    }
    list.innerHTML = items.map(e => {
      const a = e.analysis;
      const icons = (a.attachments.length ? `<span class="f-icon" title="${plural(a.attachments.length, 'adjunto', 'adjuntos')}">${ICON.clip}</span>` : '') +
        (e.qr.length ? `<span class="f-icon warn" title="Contiene códigos QR">${ICON.qr}</span>` : '');
      return `<li data-id="${e.id}" tabindex="0" class="lvl-${e.level}${e.id === state.currentId ? ' active' : ''}" title="${esc(e.name)}" aria-current="${e.id === state.currentId}">
        <div class="f-top"><span class="f-from">${esc(a.from.name || a.from.address || e.name)}</span><span class="f-date">${fmtShort(a.date)}</span></div>
        <div class="f-subject">${e.parentId ? '<span class="muted">↳ </span>' : ''}${esc(a.subject || '(sin asunto)')}</div>
        <div class="f-meta"><span class="pill ${e.level}" title="Riesgo ${e.score}/100">${e.score}</span><span class="f-level">${LEVEL_LABEL[e.level]}</span>${icons}</div>
        <button class="f-close" data-close="${e.id}" title="Quitar (Supr)" aria-label="Quitar">×</button>
      </li>`;
    }).join('');
  }

  function tabMeta(entry) {
    const a = entry.analysis, s = a.summary, o = entry.online;
    const high = list => list.some(f => f.sev === 'high');
    return {
      origen: { alert: ['spf', 'dkim', 'dmarc'].some(k => s[k] === 'fail') },
      enlaces: { count: a.links.length, alert: a.links.some(l => high(l.flags)) },
      adjuntos: { count: a.attachments.length, alert: a.attachments.some(x => high(x.flags)) || high(entry.qrFindings) },
      reputacion: o ? (o.running ? { spin: true } : { count: (o.findings || []).filter(f => f.sev === 'high' || f.sev === 'medium').length, alert: high(o.findings || []) }) : {},
    };
  }

  function tabsNav(entry) {
    const meta = tabMeta(entry);
    const active = groupOf(state.tab).id;
    return `<nav class="tabs" role="tablist" aria-label="Secciones del análisis">${TAB_GROUPS.map((g, i) => {
      const m = meta[g.id] || {};
      const on = g.id === active;
      const badge = m.spin ? '<span class="spinner sm" aria-label="consultando"></span>'
        : m.count !== undefined ? `<span class="count${m.alert ? ' alert' : ''}">${m.count}</span>`
        : m.alert ? '<span class="dot-alert" title="Con alertas"></span>' : '';
      return `<button role="tab" data-tab="${g.id}" id="tab-${g.id}" class="${on ? 'active' : ''}" aria-selected="${on}" tabindex="${on ? 0 : -1}" title="${g.label} (${i + 1})">${g.label}${badge}</button>`;
    }).join('')}</nav>`;
  }

  function subNav() {
    const g = groupOf(state.tab);
    if (!g.sub) return '';
    return `<div class="subnav" role="tablist" aria-label="${g.label}">${g.sub.map(([id, label]) =>
      `<button role="tab" data-tab="${id}" class="${state.tab === id ? 'active' : ''}" aria-selected="${state.tab === id}">${label}</button>`).join('')}</div>`;
  }

  function setTab(id, opts) {
    const g = TAB_GROUPS.find(x => x.id === id);
    if (g && g.sub) id = state.lastSub[g.id];
    const owner = groupOf(id);
    if (owner.sub) state.lastSub[owner.id] = id;
    state.tab = id;
    renderTabOnly();
    const nav = $('.tabs');
    if (opts && opts.scroll && nav && nav.getBoundingClientRect().top < 0) nav.scrollIntoView({ block: 'start' });
    if (opts && opts.focus) { const b = $(`.tabs [data-tab="${groupOf(id).id}"]`); if (b) b.focus(); }
  }

  function renderMain() {
    const main = $('#main');
    const entry = current();
    main.dataset.view = entry ? state.tab : '';
    if (!entry) { main.innerHTML = emptyState(); return; }
    main.innerHTML = `
      ${mailHead(entry)}
      ${tabsNav(entry)}
      <section id="tab-panel" role="tabpanel">${subNav()}${renderTab(entry)}</section>`;
    revealActiveTab();
    afterTabRender(entry);
  }

  function renderTabOnly() {
    const entry = current();
    if (!entry) return;
    $('#main').dataset.view = state.tab;
    const nav = $('.tabs');
    if (nav) nav.outerHTML = tabsNav(entry);
    const panel = $('#tab-panel');
    // Las comprobaciones en línea re-renderizan la pestaña mientras avanzan: se conserva el campo
    // que se estaba editando (p. ej. la clave de Safe Browsing a medio escribir).
    const ae = document.activeElement;
    const keep = ae && ae.id && panel.contains(ae) && /^(INPUT|SELECT)$/.test(ae.tagName) && ae.type !== 'checkbox'
      ? { id: ae.id, value: ae.value, start: ae.selectionStart, end: ae.selectionEnd } : null;
    panel.innerHTML = subNav() + renderTab(entry);
    if (keep) {
      const el = document.getElementById(keep.id);
      if (el) {
        el.value = keep.value;
        el.focus();
        try { el.setSelectionRange(keep.start, keep.end); } catch (_) { /* select o tipo sin selección */ }
      }
    }
    revealActiveTab();
    afterTabRender(entry);
  }

  // En pantallas estrechas la barra de pestañas se desplaza en horizontal: la activa ha de quedar a la vista.
  // Se ajusta sólo scrollLeft, para no mover la página en vertical.
  function revealActiveTab() {
    const nav = $('.tabs');
    const tab = nav && nav.querySelector('.active');
    if (!tab || nav.scrollWidth <= nav.clientWidth) return;
    const left = tab.offsetLeft, right = left + tab.offsetWidth;
    if (left < nav.scrollLeft) nav.scrollLeft = left - 16;
    else if (right > nav.scrollLeft + nav.clientWidth) nav.scrollLeft = right - nav.clientWidth + 16;
  }

  function emptyState() {
    return `<div class="empty-state">
      <h1 class="empty-title">Analiza un correo sospechoso</h1>
      <p class="empty-sub">Arrastra un fichero <code>.eml</code> o <code>.msg</code> y obtendrás en segundos una conclusión clara y todo el detalle técnico.</p>
      <label class="dropzone" id="dropzone" role="button" tabindex="0">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16v12H4z M4 6l8 7 8-7" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
        <strong>Arrastra aquí uno o varios ficheros .eml o .msg</strong>
        <span>o haz clic para seleccionarlos · también puedes pegar el código fuente con <kbd>Ctrl</kbd>+<kbd>V</kbd></span>
        <input type="file" accept=".eml,.msg,.txt,message/rfc822,application/vnd.ms-outlook" multiple hidden data-file-input>
      </label>
      <p class="sample-link"><button class="btn" data-action="load-samples">Probar con los ejemplos incluidos</button></p>
      <div class="features">
        <div class="feature"><span class="f-ico">${ICON.shield}</span><strong>Autenticación</strong><span>SPF, DKIM verificado por DNS, DMARC y ruta de entrega.</span></div>
        <div class="feature"><span class="f-ico">${ICON.link}</span><strong>Enlaces y adjuntos</strong><span>Destinos engañosos, marcas imitadas, macros y QR maliciosos.</span></div>
        <div class="feature"><span class="f-ico">${ICON.globe}</span><strong>DNS y WHOIS</strong><span>Antigüedad de dominios, listas negras y titular de la IP.</span></div>
        <div class="feature"><span class="f-ico">${ICON.spark}</span><strong>IA local</strong><span>Veredicto, resumen y chat con ${MODEL}, sin enviar nada fuera.</span></div>
      </div>
      <p class="privacy-note">${ICON.shield} El contenido de los correos se analiza en tu navegador y nunca sale de tu equipo.</p>
    </div>`;
  }

  // Resultados SPF/DKIM/DMARC en español; el valor original (pass, fail…) queda en el title para el analista.
  const AUTH_LABEL = { pass: 'correcto', fail: 'falla', hardfail: 'falla', softfail: 'falla leve', neutral: 'neutral', none: 'ausente',
    temperror: 'error temporal', permerror: 'error permanente', policy: 'rechazado por política', bestguesspass: 'correcto (estimado)' };
  const authText = r => AUTH_LABEL[String(r).toLowerCase()] || r;
  function authResult(r) {
    return `<span class="badge ${esc(r)}" title="${esc(r)}">${esc(authText(r))}</span>`;
  }
  function authBadge(label, r) {
    return `<span class="badge ${esc(r)}" title="${label}=${esc(r)}">${label}: ${esc(authText(r))}</span>`;
  }

  function gauge(score, level, size) {
    const r = 30, c = 2 * Math.PI * r;
    return `<svg class="gauge g-${level}" viewBox="0 0 72 72" width="${size}" height="${size}" role="img" aria-label="Riesgo ${score} sobre 100">
      <circle cx="36" cy="36" r="${r}" class="g-track"/>
      <circle cx="36" cy="36" r="${r}" class="g-val" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${(c * (1 - score / 100)).toFixed(1)}" transform="rotate(-90 36 36)"/>
      <text x="36" y="42" text-anchor="middle">${score}</text></svg>`;
  }

  function mailHead(entry) {
    const a = entry.analysis;
    const s = a.summary;
    return `<header class="mail-head">
      <div class="mh-main">
        <h1>${esc(a.subject || '(sin asunto)')}</h1>
        <div class="who"><strong>${esc(a.from.name || a.from.address)}</strong>${a.from.name ? ` <span class="muted">&lt;${esc(a.from.address)}&gt;</span>` : ''}</div>
        ${a.relay ? `<div class="relay-line">Reenviado por ${esc(a.relay.service)} · remitente real <strong>${esc(a.relay.original.address)}</strong></div>` : ''}
        <div class="meta-line">
          <span>Para ${esc(a.to.map(x => x.address).slice(0, 2).join(', ') || '(sin destinatarios visibles)')}${a.to.length > 2 ? ` y ${a.to.length - 2} más` : ''}</span>
          <span>${fmtDate(a.date)}</span>
          <span>${fmtBytes(entry.email.size)}</span>
        </div>
        <div class="auth-badges">
          ${s.noAuthHeaders ? '<span class="badge">Sin datos de autenticación</span>'
            : s.outlookExport ? authBadge('SPF', s.spf) + '<span class="badge" title="Outlook eliminó estas cabeceras al exportar">DKIM/DMARC: no disponibles</span>'
            : authBadge('SPF', s.spf) + authBadge('DKIM', s.dkim) + authBadge('DMARC', s.dmarc)}
          ${s.msAuth ? `<span class="badge ${s.msAuth === '1' ? 'pass' : 'fail'}" title="auth en X-Microsoft-Antispam-Mailbox-Delivery">Microsoft: ${s.msAuth === '1' ? 'autenticado' : 'no autenticado'}</span>` : ''}
          ${entry.email.sourceFormat === 'msg' ? '<span class="badge">desde .msg</span>' : ''}
          ${dkimVerifiedBadge(entry)}
          ${entry.qr.length ? `<span class="badge medium">${plural(entry.qr.length, 'código QR', 'códigos QR')}</span>` : ''}
        </div>
      </div>
      <div class="mh-side">
        <div class="head-risk risk-${entry.level}">${gauge(entry.score, entry.level, 52)}<div><div class="lvl">${LEVEL_LABEL[entry.level]}${riskDelta(entry)}</div>
          <div class="sub">${onlineApplied(entry) ? 'recalculado con DNS y WHOIS' : 'análisis local'}</div></div></div>
        <div class="head-actions">
          ${onlineButton(entry)}
          <details class="menu">
            <summary class="btn small" aria-label="Exportar" aria-haspopup="menu">Exportar <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></summary>
            <div class="menu-pop" role="menu">
              <button role="menuitem" data-action="export-md"><strong>Informe</strong><span>Markdown, para compartir</span></button>
              <button role="menuitem" data-action="export-json"><strong>Análisis completo</strong><span>JSON, para otras herramientas</span></button>
              <button role="menuitem" data-action="export-csv"><strong>IOCs</strong><span>CSV, para SIEM o listas de bloqueo</span></button>
            </div>
          </details>
        </div>
      </div>
    </header>`;
  }

  function riskDelta(entry) {
    if (!onlineApplied(entry)) return '';
    const d = entry.score - entry.localScore;
    return d ? ` <span class="delta" title="Cambio debido a las comprobaciones en línea (antes ${entry.localScore})">${d > 0 ? '+' : ''}${d}</span>` : '';
  }

  // Explica cómo han cambiado el riesgo las comprobaciones en línea.
  function rescoreBanner(entry) {
    if (!onlineApplied(entry)) return '';
    const pointsOf = f => Analysis.pointsOf(f, entry.trustVoided);
    const scoring = entry.online.findings.filter(f => pointsOf(f));
    const pts = scoring.reduce((n, f) => n + pointsOf(f), 0);
    const d = entry.score - entry.localScore;
    let msg;
    if (d > 0) msg = `El riesgo ha subido de <b>${entry.localScore}</b> a <b>${entry.score}</b> (+${d}) con estas comprobaciones.`;
    else if (d < 0) msg = `El riesgo ha bajado de <b>${entry.localScore}</b> a <b>${entry.score}</b> (${d}) gracias a las evidencias a favor.`;
    else if (!scoring.length) msg = `Las comprobaciones no han encontrado nada que cambie el riesgo: se mantiene en <b>${entry.score}</b>.`;
    else if (entry.score === 100 && pts > 0) msg = `Estas comprobaciones suman ${pts} puntos, pero el riesgo ya estaba en el máximo: se mantiene en <b>${entry.score}</b>.`;
    else if (entry.score === 0 && pts < 0) msg = `Las evidencias a favor no pueden bajar más el riesgo: ya estaba en <b>0</b>.`;
    else msg = `El resultado neto no cambia el riesgo: se mantiene en <b>${entry.score}</b> (las evidencias a favor tienen un tope).`;
    return `<section class="rescore risk-${entry.level}">
      <div class="rescore-gauge">${gauge(entry.score, entry.level, 56)}</div>
      <div class="rescore-body">
        <h2>Riesgo recalculado</h2>
        <p>${msg}</p>
        ${scoring.length ? `<ul>${scoring.map(f => { const p = pointsOf(f); return `<li><span class="pts ${p < 0 ? 'neg' : ''}">${p > 0 ? '+' : '−'}${Math.abs(p)}</span>${esc(f.title)}</li>`; }).join('')}</ul>` : ''}
      </div>
      <button class="btn small" data-tab="resumen">Ver resumen actualizado</button>
    </section>`;
  }

  function dkimVerifiedBadge(entry) {
    const sigs = entry.online && entry.online.dkim && entry.online.dkim.filter(x => x.result !== 'skipped');
    if (!sigs || !sigs.length) return '';
    const best = sigs.find(x => x.result === 'pass') || sigs[0];
    return `<span class="badge ${esc(best.result)}" title="Verificación criptográfica local con la clave publicada en DNS">DKIM (verificación local): ${esc(RESULT_LABEL[best.result] || best.result)}</span>`;
  }

  function onlineButton(entry) {
    const o = entry.online;
    if (o && o.running) return '<button class="btn small" disabled><span class="spinner"></span> Consultando…</button>';
    return `<button class="btn small ${o ? '' : 'primary'}" data-action="online-run" title="Verifica DKIM, consulta DNS, WHOIS (RDAP) y listas negras. Sólo se envían dominios e IPs.">${ICON.globe}${o ? 'Repetir comprobaciones' : 'Comprobaciones en línea'}</button>`;
  }

  function renderTab(entry) {
    switch (state.tab) {
      case 'resumen': return tabResumen(entry);
      case 'contenido': return tabContenido(entry);
      case 'cabeceras': return tabCabeceras(entry);
      case 'ruta': return tabRuta(entry);
      case 'auth': return tabAuth(entry);
      case 'reputacion': return tabReputacion(entry);
      case 'enlaces': return tabEnlaces(entry);
      case 'adjuntos': return tabAdjuntos(entry);
      case 'estructura': return tabEstructura(entry);
      case 'iocs': return tabIocs(entry);
      case 'fuente': return tabFuente(entry);
      default: return '';
    }
  }

  function afterTabRender(entry) {
    if (state.tab === 'contenido' && entry.view.mode === 'html' && entry.email.html) mountHtml(entry);
  }

  // ---------- pestaña Resumen ----------

  function statChips(entry) {
    const a = entry.analysis, s = a.summary, o = entry.online;
    const bad = f => f.sev === 'high' || f.sev === 'medium';
    const fails = ['spf', 'dkim', 'dmarc'].filter(k => s[k] === 'fail' || s[k] === 'softfail').length;
    const passes = ['spf', 'dkim', 'dmarc'].filter(k => s[k] === 'pass').length;
    const susLinks = a.links.filter(l => l.flags.some(bad)).length;
    const badAtt = a.attachments.filter(x => x.flags.some(bad) || entry.qr.some(q => q.attachment === x && q.link)).length;
    const chips = [
      s.outlookExport && s.msAuth
        ? { tab: 'auth', icon: ICON.shield, label: 'Autenticación', value: s.msAuth === '1' ? 'Validada por Microsoft' : 'Microsoft: no superada', tone: s.msAuth === '1' ? 'ok' : 'high' }
        : s.relay
        ? { tab: 'auth', icon: ICON.shield, label: 'Autenticación', value: s.senderAuth ? 'Correcta · vía Apple' : 'Remitente sin autenticar', tone: s.senderAuth ? 'ok' : 'medium' }
        : { tab: 'auth', icon: ICON.shield, label: 'Autenticación',
          value: s.noAuthHeaders ? 'Sin datos' : fails ? `${fails} de 3 fallan` : s.dmarc === 'pass' ? 'Correcta' : 'Incompleta',
          tone: s.noAuthHeaders ? '' : fails ? 'high' : s.dmarc === 'pass' ? 'ok' : 'low' },
      { tab: 'enlaces', icon: ICON.link, label: 'Enlaces',
        value: a.links.length ? (susLinks ? `${susLinks} de ${a.links.length} sospechosos` : `${a.links.length} sin alertas`) : 'Ninguno',
        tone: susLinks ? 'high' : a.links.length ? 'ok' : '' },
      { tab: 'adjuntos', icon: ICON.clip, label: 'Adjuntos',
        value: a.attachments.length ? (badAtt ? `${badAtt} de ${a.attachments.length} sospechosos` : `${a.attachments.length} sin alertas`) : 'Ninguno',
        tone: badAtt ? 'high' : a.attachments.length ? 'ok' : '' },
      { tab: 'reputacion', icon: ICON.globe, label: 'DNS y WHOIS',
        value: !o ? 'Sin consultar' : o.running ? 'Consultando…' : (o.findings || []).some(bad) ? plural((o.findings || []).filter(bad).length, 'alerta', 'alertas') : 'Sin alertas',
        tone: !o || o.running ? '' : (o.findings || []).some(f => f.sev === 'high') ? 'high' : (o.findings || []).some(bad) ? 'medium' : 'ok' },
    ];
    return `<div class="stat-row">${chips.map(c => `<button class="stat tone-${c.tone || 'none'}" data-tab="${c.tab}" data-scroll="1">
      <span class="stat-ico">${c.icon}</span><span class="stat-txt"><span class="stat-label">${c.label}</span><span class="stat-value">${c.value}</span></span>${ICON.chevron}</button>`).join('')}</div>`;
  }

  function pointsChip(f, trustVoided) {
    const p = Analysis.pointsOf(f, trustVoided);
    if (!p && f.trust && trustVoided && Analysis.pointsOf(f)) {
      return `<span class="f-pts void" title="No resta: el dominio del remitente es sospechoso, así que la autenticación no prueba que sea de fiar"><s>−${Math.abs(Analysis.pointsOf(f))}</s></span>`;
    }
    if (!p) return '';
    return `<span class="f-pts ${p < 0 ? 'neg' : ''}" title="${p < 0 ? 'Resta' : 'Suma'} ${Math.abs(p)} puntos de riesgo">${p > 0 ? '+' : '−'}${Math.abs(p)}</span>`;
  }

  function findingRow(f, trustVoided) {
    const tab = CAT_TAB[f.category];
    const inner = `<span class="badge ${f.sev} sev-label">${SEV_LABEL[f.sev]}</span>
      <span class="f-body"><span class="f-title">${esc(f.title)}</span>${f.detail ? `<span class="f-detail">${esc(f.detail)}</span>` : ''}</span>
      <span class="f-cat">${pointsChip(f, trustVoided)}${esc(CAT_LABEL[f.category] || f.category)}${f.online ? ' · en línea' : ''}</span>`;
    return tab ? `<li><button class="finding" data-tab="${tab}" data-scroll="1" title="Ver detalle en ${esc(groupOf(tab).label)}">${inner}${ICON.chevron}</button></li>`
      : `<li><div class="finding">${inner}</div></li>`;
  }

  // Hallazgos agrupados por gravedad. Los informativos y los que restan riesgo van plegados
  // (se recuerda si el usuario los abre), para que lo grave no quede enterrado.
  function findingsList(list, trustVoided) {
    if (!list.length) return '<p class="muted card-body" style="margin:0">Sin hallazgos.</p>';
    const groups = [['high', 'Graves'], ['medium', 'A revisar'], ['low', 'Menores'], ['info', 'Informativos'], ['ok', 'A favor']];
    return groups.map(([sev, label]) => {
      const items = list.filter(f => f.sev === sev);
      if (!items.length) return '';
      const body = `<ul class="findings">${items.map(f => findingRow(f, trustVoided)).join('')}</ul>`;
      if (!(sev in state.openGroups)) return `<div class="f-group"><h3 class="f-group-title sev-${sev}">${label} <span>${items.length}</span></h3>${body}</div>`;
      return `<details class="f-group" data-group="${sev}" ${state.openGroups[sev] ? 'open' : ''}>
        <summary><h3 class="f-group-title sev-${sev}">${label} <span>${items.length}</span>${ICON.chevron}</h3></summary>${body}</details>`;
    }).join('');
  }

  // Cómo se llega a la puntuación: lo que suma, lo que resta y el tope de lo que resta.
  function scoreBreakdown(entry) {
    const r = Analysis.scoreFindings(entry.findings);
    const capped = r.rawMitigation < r.mitigation;
    return `<div class="score-breakdown">
      <span><b class="pos">+${r.positive}</b> por señales de riesgo</span>
      <span><b class="neg">${r.mitigation ? '−' + Math.abs(r.mitigation) : '0'}</b> por evidencias a favor${capped ? ` <span class="muted">(de −${Math.abs(r.rawMitigation)}; máximo −${r.mitigationCap}${r.mitigationCap < 30 ? ' porque hay alertas graves' : ''})</span>` : ''}</span>
      <span>= <b>${entry.score}</b>${r.positive + r.mitigation > 100 ? ' <span class="muted">(máximo 100)</span>' : ''}</span>
      ${r.trustVoided && entry.findings.some(f => f.trust && Analysis.pointsOf(f)) ? `<span class="void-note">La autenticación y la antigüedad no restan: sólo prueban que el correo viene de su dominio, y ese dominio es sospechoso (${esc(r.voidedBy.join('; '))}).</span>` : ''}
    </div>`;
  }

  // Aviso cuando el .eml no es el original (exportado desde Outlook o convertido desde .msg).
  function sourceNotice(entry) {
    const s = entry.analysis.summary;
    if (entry.email.attached) {
      return `<div class="source-notice">${ICON.shield}<div><strong>Este correo venía adjunto a otro.</strong> No lo recibió tu proveedor, así que sus cabeceras (autenticación, ruta, remitente) pueden estar inventadas por quien lo adjuntó: los resultados SPF, DKIM y DMARC que muestra no restan riesgo.</div></div>`;
    }
    if (entry.email.sourceFormat === 'msg') {
      return `<div class="source-notice">${ICON.shield}<div><strong>Convertido desde un .msg de Outlook.</strong> ${entry.email.msgInfo && entry.email.msgInfo.transportHeaders
        ? 'Las cabeceras originales (autenticación, ruta) se conservan, pero el cuerpo se reconstruye a partir de los datos de Outlook, así que la firma DKIM no se puede volver a verificar.'
        : 'El .msg no incluía las cabeceras originales de Internet (suele pasar con correos enviados o borradores): no hay datos de autenticación ni de ruta.'}</div></div>`;
    }
    if (s.outlookExport) {
      return `<div class="source-notice">${ICON.shield}<div><strong>Este .eml se guardó desde Outlook</strong>, que elimina las cabeceras de autenticación (DKIM, DMARC) al exportar. ${s.msAuth === '1' ? 'Se usa en su lugar el veredicto que Microsoft dejó en el mensaje: <b>remitente autenticado</b>.' : s.msAuth === '0' ? 'Se usa en su lugar el veredicto que Microsoft dejó en el mensaje: <b>remitente no autenticado</b>.' : ''}
        Para el análisis completo, arrastra el correo desde Outlook al escritorio (.msg) o descárgalo desde Outlook en la web (··· › Descargar).</div></div>`;
    }
    return '';
  }

  // Resultado de cada fuente de reputación en línea (Safe Browsing, Cloudflare 1.1.1.2, listas negras,
  // WHOIS…), también cuando no encuentran nada, para ver de un vistazo qué se consultó y qué salió.
  function reputationCard(entry) {
    const o = entry.online;
    const head = '<div class="card-head"><h2>Reputación</h2><span class="muted">comprobaciones en línea</span></div>';
    if (!o) return head + `<div class="card-body"><p class="muted" style="margin:0 0 10px">No se han ejecutado las comprobaciones en línea.</p><button class="btn small" data-action="online-run">Ejecutar comprobaciones</button></div>`;
    if (o.running) return head + '<div class="card-body muted"><span class="spinner"></span> Consultando Safe Browsing, Cloudflare, listas negras y WHOIS…</div>';
    if (o.error) return head + `<div class="card-body"><p class="notice" style="margin:0">No se pudieron completar: ${esc(o.error)}</p></div>`;

    const hostOf = u => { try { return new URL(/^[a-z][\w+.-]*:/i.test(u) ? u : 'http://' + u).hostname; } catch (_) { return String(u).slice(0, 60); } };
    const list = xs =>xs.slice(0, 3).join(', ') + (xs.length > 3 ? ` y ${xs.length - 3} más` : '');
    const domains = Object.values(o.domains);
    const ips = Object.values(o.ips);
    const rows = [];
    const row = (label, value, tone, detail) => rows.push({ label, value, tone, detail });

    // Google Safe Browsing
    const sb = o.safeBrowsing;
    if (!sb || sb.skipped === 'sin clave') row('Google Safe Browsing', 'No activado', '', 'Falta la clave de API (config.js o pestaña DNS y WHOIS).');
    else if (sb.error) row('Google Safe Browsing', 'Error', 'medium', sb.error);
    else if (sb.skipped) row('Google Safe Browsing', 'Nada que consultar', '', 'El correo no tiene enlaces web ni dominios que comprobar.');
    else if (sb.matches.length) {
      const threats = [...new Set([].concat(...sb.matches.map(m => m.threats)))].map(SafeBrowsing.label).join(', ');
      row('Google Safe Browsing', plural(sb.matches.length, 'coincidencia', 'coincidencias'), 'high',
        `${threats}: ${list([...new Set(sb.matches.map(m => m.domain || hostOf(m.url)))])}`);
    } else row('Google Safe Browsing', 'Sin coincidencias', 'ok', `${plural(sb.urls, 'URL', 'URLs')} y ${plural(sb.domains || 0, 'dominio', 'dominios')} del remitente.`);

    // Cloudflare 1.1.1.2
    const cf = domains.map(d => [d, (d.dnsbl || []).find(x => x.list === 'Cloudflare 1.1.1.2')]).filter(([, x]) => x);
    const cfListed = cf.filter(([, x]) => x.status === 'listed').map(([d]) => d.domain);
    const cfErr = cf.filter(([, x]) => x.status === 'error').length;
    if (!cf.length) row('Cloudflare 1.1.1.2', 'Sin consultar', '', 'No hay dominios que comprobar.');
    else if (cfListed.length) row('Cloudflare 1.1.1.2', `${plural(cfListed.length, 'dominio bloqueado', 'dominios bloqueados')}`, 'high', `Clasificados como maliciosos: ${list(cfListed)}.`);
    else if (cfErr === cf.length) row('Cloudflare 1.1.1.2', 'Error', 'medium', 'No respondió; repite las comprobaciones.');
    else row('Cloudflare 1.1.1.2', 'Sin bloqueos', 'ok', `${plural(cf.length - cfErr, 'dominio consultado', 'dominios consultados')}${cfErr ? ` (${cfErr} con error)` : ''}.`);

    // Listas negras DNSBL de dominios (sin Cloudflare) y de IPs
    const dnsblRow = (label, items, nameOf, emptyText) => {
      const lists = items.map(it => [it, (it.dnsbl || []).filter(x => x.list !== 'Cloudflare 1.1.1.2')]);
      const listed = lists.filter(([, ls]) => ls.some(x => x.status === 'listed'))
        .map(([it, ls]) => `${nameOf(it)} (${ls.filter(x => x.status === 'listed').map(x => x.list).join(', ')})`);
      const all = [].concat(...lists.map(([, ls]) => ls));
      const answered = all.filter(x => x.status === 'clean' || x.status === 'listed');
      const refused = [...new Set(all.filter(x => x.status === 'refused').map(x => x.list))];
      if (!items.length) row(label, 'Sin consultar', '', emptyText);
      else if (listed.length) row(label, `${plural(listed.length, 'en lista', 'en listas')}`, 'high', list(listed) + '.');
      else if (!answered.length) row(label, 'No consultable', '', refused.length ? `${refused.join(', ')} no ${refused.length === 1 ? 'responde' : 'responden'} a resolvedores DNS públicos.` : 'Las listas no respondieron.');
      else row(label, 'Sin coincidencias', 'ok', `${[...new Set(answered.map(x => x.list))].join(', ')}${refused.length ? `; ${refused.join(', ')} no consultable` : ''}.`);
    };
    dnsblRow('Listas negras de dominios', domains, d => d.org, 'No hay dominios que comprobar.');
    dnsblRow('Listas negras de IPs', ips, i => i.ip + (i.roles.includes('Origen') ? ' (origen)' : ''), 'No hay IPs públicas que comprobar.');

    // Antigüedad por WHOIS (un registro por dominio registrable)
    const byOrg = new Map();
    domains.forEach(d => { if (d.rdap && d.rdap.ageDays != null && !byOrg.has(d.org)) byOrg.set(d.org, d); });
    const young = [...byOrg.values()].filter(d => d.rdap.ageDays < 180).sort((x, y) => x.rdap.ageDays - y.rdap.ageDays);
    const fromD = domains.find(d => d.roles.includes('From') && d.rdap && d.rdap.ageDays != null);
    if (young.length) row('Antigüedad (WHOIS)', `${plural(young.length, 'dominio reciente', 'dominios recientes')}`, young[0].rdap.ageDays < 30 ? 'high' : 'medium',
      list(young.map(d => `${d.org} (${d.rdap.ageDays} días)`)) + '.');
    else if (byOrg.size) row('Antigüedad (WHOIS)', 'Sin dominios recientes', 'ok',
      fromD ? `El del remitente, ${fromD.org}, tiene ${plural(Math.floor(fromD.rdap.ageDays / 365), 'año', 'años')}.` : `${plural(byOrg.size, 'dominio consultado', 'dominios consultados')}, todos con más de 180 días.`);
    else row('Antigüedad (WHOIS)', 'No disponible', '', 'Los registros de estos dominios no publican RDAP.');

    // Dominios inexistentes y suspendidos: sólo si hay alguno.
    const nx = [...new Set(domains.filter(d => d.dns && d.dns.nx).map(d => d.org))];
    if (nx.length) row('Dominios inexistentes', plural(nx.length, 'dominio', 'dominios'), domains.some(d => d.dns && d.dns.nx && d.mail) ? 'high' : 'medium', `NXDOMAIN: ${list(nx)}.`);
    const hold = [...new Set(domains.filter(d => d.rdap && d.rdap.status && d.rdap.status.some(x => /hold/i.test(x))).map(d => d.org))];
    if (hold.length) row('Dominios suspendidos', plural(hold.length, 'dominio', 'dominios'), 'medium', `Suspendidos por el registro: ${list(hold)}.`);

    const TONE_BADGE = { high: 'high', medium: 'medium', ok: 'ok', '': '' };
    const sbShown = sb && !sb.skipped && !sb.error;
    return head + `<ul class="findings rep-summary">${rows.map(r => `<li><button class="finding" data-tab="reputacion" data-scroll="1" title="Ver detalle en DNS y WHOIS">
        <span class="f-body"><span class="f-title">${esc(r.label)}</span>${r.detail ? `<span class="f-detail">${esc(r.detail)}</span>` : ''}</span>
        <span class="badge ${TONE_BADGE[r.tone]}">${esc(r.value)}</span>${ICON.chevron}</button></li>`).join('')}</ul>
      ${sbShown ? `<p class="muted rep-note">${sbAttribution()}. Que un indicador no figure en las listas no garantiza que sea seguro.</p>` : ''}`;
  }

  function tabResumen(entry) {
    const a = entry.analysis;
    const c = Analysis.conclusion(entry);
    const reasons = Analysis.topReasons(entry.findings);
    const v = entry.ai.verdict;
    const facts = [
      ['De', addr(a.from)],
      a.relay ? ['Remitente real', `${a.relay.original.address} (vía ${a.relay.service})`] : null,
      a.sender ? ['Sender', addr(a.sender)] : null,
      a.replyTo.length ? ['Responder a', a.replyTo.map(addr).join(', ')] : null,
      ['Return-Path', a.returnPath || '—'],
      ['Para', a.to.map(addr).join(', ') || '—'],
      a.cc.length ? ['CC', a.cc.map(addr).join(', ')] : null,
      ['Fecha', fmtDate(a.date)],
      ['IP de origen', a.iocs.originIP || '—'],
      a.iocs.declaredIP ? ['IP del primer salto', `${a.iocs.declaredIP} (declarada por el remitente)`] : null,
      ['Message-ID', a.messageId || '—'],
      a.mailer ? ['Cliente', a.mailer] : null,
      ['Fichero', entry.name],
    ].filter(Boolean);
    return `${sourceNotice(entry)}<section class="hero risk-${entry.level}" aria-label="Conclusión">
        <div class="hero-gauge">${gauge(entry.score, entry.level, 96)}<span class="hero-lvl">${LEVEL_LABEL[entry.level]}${riskDelta(entry)}</span></div>
        <div class="hero-body">
          <div class="hero-kicker">Conclusión${onlineApplied(entry) ? ' · incluye DNS y WHOIS' : ''}${v ? ` · IA: <span class="badge ${VERDICT_CLASS[v.veredicto] || 'info'}">${esc(VERDICT_LABEL[v.veredicto] || v.veredicto)}</span>` : ''}</div>
          <h2>${esc(c.title)}</h2>
          <p>${esc(c.text)}</p>
          ${reasons.length ? `<ul class="hero-reasons">${reasons.map(f => `<li><button data-tab="${CAT_TAB[f.category] || 'resumen'}" data-scroll="1"><span class="dot ${f.sev}"></span>${esc(f.title)}</button></li>`).join('')}</ul>` : ''}
        </div>
        <div class="hero-actions"><h3>Qué hacer</h3><ul>${c.actions.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>
      </section>
      ${statChips(entry)}
      <div class="grid-2">
        <section class="card">
          <div class="card-head"><h2>Hallazgos</h2><span class="muted">${entry.findings.length} · pulsa uno para ver el detalle</span></div>
          ${scoreBreakdown(entry)}
          ${findingsList(entry.findings, entry.trustVoided)}
        </section>
        <div class="stack">
          <section class="card" id="rep-card">${reputationCard(entry)}</section>
          <section class="card" id="ai-card">${aiCard(entry)}</section>
          <section class="card">
            <div class="card-head"><h2>Datos clave</h2></div>
            <div class="card-body"><dl class="facts">${facts.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('')}</dl></div>
          </section>
        </div>
      </div>`;
  }

  function aiAvailable() {
    const p = state.ai.status && state.ai.status.prompt;
    return p === 'available' || p === 'downloadable' || p === 'downloading';
  }

  function aiCard(entry) {
    const st = state.ai.status;
    const ai = entry.ai;
    const head = `<div class="card-head"><h2>Análisis con IA local</h2><span class="muted">${MODEL}</span></div>`;
    if (!st) return head + '<div class="card-body muted"><span class="spinner"></span> Comprobando disponibilidad…</div>';
    if (!aiAvailable()) {
      const canSummarize = st.summarizer === 'available' || st.summarizer === 'downloadable';
      return head + `<div class="card-body">
        <p class="ai-off">${ICON.spark}<span><strong>${MODEL} no está disponible</strong> en este navegador${st.prompt === 'unavailable' ? ' (el equipo no cumple los requisitos o está desactivado)' : ''}. El análisis técnico no depende de la IA.</span></p>
        <div class="ai-actions">
          <button class="btn" data-action="ai-help">Cómo activarla</button>
          ${canSummarize ? (ai.ctrl.summary ? busyButton(entry, 'summary', 'Resumiendo…', AI.LIMITS.summary.max) : '<button class="btn" data-action="ai-summary">Resumir</button>') : ''}
        </div>
        ${summaryBlock(ai)}
      </div>`;
    }
    const v = ai.verdict;
    const needsDownload = st.prompt !== 'available';
    const L = AI.LIMITS;
    let verdictBtn;
    if (ai.ctrl.verdict) verdictBtn = busyButton(entry, 'verdict', 'Analizando…', L.verdict.max);
    else if (v) verdictBtn = '<button class="btn primary" disabled title="El veredicto se solicita una sola vez por correo">✓ Veredicto emitido</button>';
    else verdictBtn = `<button class="btn primary" data-action="ai-verdict">${ai.verdictError ? 'Reintentar veredicto' : 'Veredicto con IA'}</button>`;
    const summaryBtn = ai.ctrl.summary ? busyButton(entry, 'summary', 'Resumiendo…', L.summary.max)
      : `<button class="btn" data-action="ai-summary">${ai.summary ? 'Volver a resumir' : 'Resumir'}</button>`;
    return head + `<div class="card-body">
      <div class="ai-actions">${verdictBtn}${summaryBtn}</div>
      ${needsDownload ? `<p class="ai-note">La primera vez el navegador descargará el modelo (varios GB). Mientras la descarga avance no se corta; si se detiene ${L.download} s, se cancela.</p>` : ''}
      <div class="progress" id="ai-progress" ${state.ai.progress == null ? 'hidden' : ''}><i style="width:${Math.round((state.ai.progress || 0) * 100)}%"></i></div>
      ${ai.verdictError ? `<p class="notice">${esc(ai.verdictError)}</p>` : ''}
      ${v ? verdictBlock(v) : ''}
      ${summaryBlock(ai)}
      <div class="chat">
        <div class="suggestions">${['¿Es phishing? ¿Por qué?', '¿Qué me pide hacer este correo?', '¿Quién lo envía realmente?', 'Explica los resultados de SPF, DKIM y DMARC', 'Redacta un aviso breve para mis compañeros']
          .map(q => `<button type="button" data-action="chat-suggest" data-q="${esc(q)}" ${ai.ctrl.chat ? 'disabled' : ''}>${esc(q)}</button>`).join('')}</div>
        <div class="chat-log" id="chat-log">${ai.chatLog.map(chatMsg).join('')}</div>
        <form class="chat-form" id="chat-form" autocomplete="off">
          <input type="text" name="q" placeholder="Pregunta algo sobre este correo…" ${ai.ctrl.chat ? 'disabled' : ''}>
          ${ai.ctrl.chat ? `<button class="btn" type="button" data-action="ai-cancel" data-op="chat">Detener · <span class="elapsed" data-since="${ai.started.chat}">0 s</span></button>` : '<button class="btn" type="submit">Enviar</button>'}
        </form>
        <p class="ai-note">Las respuestas del modelo pueden contener errores. Contrástalas con el análisis técnico. Límite por respuesta: ${L.chat.max} s.</p>
      </div>
    </div>`;
  }

  function busyButton(entry, op, label, max) {
    return `<button class="btn" disabled><span class="spinner"></span> ${label} <span class="elapsed" data-since="${entry.ai.started[op]}">0 s</span><span class="muted">&nbsp;/ ${max} s</span></button>
      <button class="btn" data-action="ai-cancel" data-op="${op}">Cancelar</button>`;
  }

  // Actualiza los contadores de tiempo de las operaciones en curso.
  setInterval(() => {
    document.querySelectorAll('.elapsed[data-since]').forEach(el => {
      el.textContent = Math.max(0, Math.round((Date.now() - +el.dataset.since) / 1000)) + ' s';
    });
  }, 1000);

  const VERDICT_CLASS = { legitimo: 'ok', spam: 'low', sospechoso: 'medium', phishing: 'high', malware: 'high', fraude: 'high' };
  const VERDICT_LABEL = { legitimo: 'Legítimo', spam: 'Spam', sospechoso: 'Sospechoso', phishing: 'Phishing', malware: 'Malware', fraude: 'Fraude' };

  function verdictBlock(v) {
    const cls = VERDICT_CLASS[v.veredicto] || 'info';
    return `<div class="verdict">
      <div class="verdict-top">
        <span class="badge ${cls}">${esc(VERDICT_LABEL[v.veredicto] || v.veredicto)}</span>
        <span class="v">${esc(v.tipo || '')}</span>
      </div>
      <div class="verdict-top" style="margin-top:8px"><span class="muted" style="font-size:12.5px">Confianza ${esc(v.confianza)}%</span>
        <span class="meter" style="color:var(--${cls === 'info' ? 'accent' : cls})"><i style="width:${Math.max(0, Math.min(100, +v.confianza || 0))}%"></i></span></div>
      <p>${esc(v.resumen)}</p>
      ${v.razones && v.razones.length ? `<ul>${v.razones.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
      ${v.accion ? `<p><strong>Qué hacer:</strong> ${esc(v.accion)}</p>` : ''}
    </div>`;
  }

  function summaryBlock(ai) {
    if (!ai.summary && !ai.summaryError) return '';
    return `<div class="ai-output" id="ai-summary"><h3>Resumen</h3>
      ${ai.summaryError ? `<p class="notice">${esc(ai.summaryError)}</p>` : `<div class="md">${md(ai.summary)}</div>`}</div>`;
  }

  function chatMsg(m) {
    return m.role === 'user' ? `<div class="msg user">${esc(m.text)}</div>` : `<div class="msg bot md">${m.text ? md(m.text) : '<span class="spinner"></span>'}</div>`;
  }

  function refreshAICard(entry) {
    if (entry !== current() || state.tab !== 'resumen') return;
    const card = $('#ai-card');
    if (!card) return;
    const input = card.querySelector('#chat-form input');
    const draft = input ? input.value : '';
    const hadFocus = input && document.activeElement === input;
    card.innerHTML = aiCard(entry);
    const ni = card.querySelector('#chat-form input');
    if (ni) { ni.value = draft; if (hadFocus) ni.focus(); }
    const log = card.querySelector('#chat-log');
    if (log) log.scrollTop = log.scrollHeight;
  }

  function onProgress(p) {
    state.ai.progress = p >= 1 ? null : p;
    const bar = $('#ai-progress');
    if (bar) { bar.hidden = state.ai.progress == null; bar.firstElementChild.style.width = Math.round(p * 100) + '%'; }
    const help = $('#ai-help-progress');
    if (help) help.textContent = Math.round(p * 100) + '%';
    setChip(p >= 1 ? 'Preparando modelo…' : `Descargando ${MODEL}… ${Math.round(p * 100)}%`, 'pending');
    if (p >= 1) setTimeout(checkAI, 1500);
  }

  function aiError(e) {
    if (e && e.name === 'TimeoutError') return `⏱ ${e.message}. Se ha cancelado; puedes reintentarlo. Si pasa a menudo, el equipo puede ir justo de recursos: revisa chrome://on-device-internals.`;
    if (e && e.name === 'AbortError') return 'Cancelado.';
    if (e && e.name === 'NotAllowedError') return 'El navegador ha bloqueado la IA (requiere una acción del usuario o no está permitida en este contexto).';
    if (e && e.name === 'QuotaExceededError') return 'El correo es demasiado largo para la ventana de contexto del modelo.';
    if (e && e.name === 'NotSupportedError') return 'El modelo no admite esta combinación de idioma u opciones.';
    return 'Error de la IA: ' + ((e && e.message) || e);
  }

  // Ejecuta una operación de IA con su AbortController (para cancelar) y su hora de inicio.
  async function runAIOp(entry, op, fn) {
    const ai = entry.ai;
    if (ai.ctrl[op]) return;
    const ctrl = new AbortController();
    ai.ctrl[op] = ctrl;
    ai.started = ai.started || {};
    ai.started[op] = Date.now();
    refreshAICard(entry);
    try { await fn(ctrl.signal); }
    finally {
      ai.ctrl[op] = null;
      state.ai.progress = null;
      refreshAICard(entry);
    }
  }

  function cancelAI(entry, op) {
    const c = entry.ai.ctrl[op];
    if (c) c.abort();
  }

  function runVerdict(entry) {
    if (entry.ai.verdict) return; // sólo una vez por correo
    return runAIOp(entry, 'verdict', async signal => {
      entry.ai.verdictError = '';
      try {
        entry.ai.verdict = await AI.assess(aiView(entry), { onProgress, signal });
      } catch (e) {
        console.error(e);
        entry.ai.verdictError = aiError(e);
      }
      checkAI();
    });
  }

  function runSummary(entry) {
    return runAIOp(entry, 'summary', async signal => {
      entry.ai.summaryError = '';
      entry.ai.summary = '';
      try {
        await AI.summarize(aiView(entry), {
          onProgress,
          signal,
          onChunk: text => {
            entry.ai.summary = text;
            const el = $('#ai-summary .md');
            if (el && entry === current()) el.innerHTML = md(text); else refreshAICard(entry);
          },
        });
      } catch (e) {
        console.error(e);
        entry.ai.summaryError = aiError(e);
      }
    });
  }

  function askChat(entry, question) {
    question = question.trim();
    const ai = entry.ai;
    if (!question || ai.ctrl.chat) return;
    ai.chatLog.push({ role: 'user', text: question });
    const answer = { role: 'bot', text: '' };
    ai.chatLog.push(answer);
    return runAIOp(entry, 'chat', async signal => {
      try {
        if (!ai.chat) ai.chat = await AI.createChat(aiView(entry), { onProgress, signal });
        await ai.chat.ask(question, text => {
          answer.text = text;
          const log = $('#chat-log');
          if (log && entry === current() && state.tab === 'resumen') {
            log.lastElementChild.innerHTML = md(text);
            log.scrollTop = log.scrollHeight;
          }
        }, signal);
      } catch (e) {
        console.error(e);
        answer.text = (answer.text ? answer.text + '\n\n' : '') + '⚠ ' + aiError(e);
        // Tras un corte la sesión puede quedar en mal estado: se recrea en la siguiente pregunta.
        if (ai.chat && e && e.name !== 'AbortError') { ai.chat.destroy(); ai.chat = null; }
      }
    }).then(() => {
      const input = $('#chat-form input');
      if (input) input.focus();
    });
  }

  async function detectLanguage(entry) {
    const text = entry.analysis.bodyText;
    if (!text || text.length < 20) return;
    const lang = await AI.detectLanguage(text);
    if (!lang) return;
    entry.lang = lang;
    if (entry === current() && state.tab === 'contenido') renderTabOnly();
  }

  async function runTranslate(entry) {
    if (entry.ai.ctrl.translate) return;
    const ctrl = new AbortController();
    entry.ai.ctrl.translate = ctrl;
    entry.view.mode = 'trad';
    entry.ai.translation = '';
    renderTabOnly();
    try {
      await AI.translate(entry.analysis.bodyText, entry.lang || 'en', 'es', {
        onProgress,
        signal: ctrl.signal,
        onChunk: t => {
          entry.ai.translation = t;
          const pre = $('#trad-pre');
          if (pre && entry === current()) pre.textContent = t;
        },
      });
    } catch (e) {
      console.error(e);
      entry.ai.translation = (entry.ai.translation ? entry.ai.translation + '\n\n' : '') + aiError(e);
    }
    entry.ai.ctrl.translate = null;
    state.ai.progress = null;
    if (entry === current() && state.tab === 'contenido') renderTabOnly();
  }

  // ---------- pestaña Contenido ----------

  function tabContenido(entry) {
    const { email } = entry;
    const v = entry.view;
    const hasText = !!email.text, hasHtml = !!email.html;
    if (!hasText && !hasHtml) return '<div class="card card-body muted">El correo no tiene cuerpo de texto ni HTML.</div>';
    if (v.mode === 'html' && !hasHtml) v.mode = 'text';
    const canTranslate = entry.lang && entry.lang !== 'es' && (AI.has('Translator') || aiAvailable());
    const remoteCount = entry.analysis.html.remoteImages.length;
    let body;
    if (v.mode === 'html') {
      body = `${!v.remote && remoteCount ? `<div class="notice">Se ${remoteCount === 1 ? 'ha' : 'han'} bloqueado ${plural(remoteCount, 'imagen remota', 'imágenes remotas')}: cargarlas avisaría al remitente de que has abierto el correo.</div>` : ''}
        <div class="viewer"><iframe id="mail-frame" sandbox="allow-same-origin" referrerpolicy="no-referrer" title="Vista del correo"></iframe>
        <div class="statusbar" id="statusbar">Pasa el ratón sobre un enlace para ver su destino real. Los enlaces están desactivados.</div></div>`;
    } else if (v.mode === 'trad') {
      body = `<div class="viewer"><pre class="plain" id="trad-pre">${entry.ai.ctrl.translate && !entry.ai.translation ? 'Traduciendo…' : esc(entry.ai.translation || '')}</pre></div>`;
    } else {
      const text = email.text || entry.analysis.bodyText;
      body = `<div class="viewer"><pre class="plain">${highlightUrls(text)}</pre></div>`;
    }
    return `<div class="toolbar">
        <div class="seg">
          <button data-action="view-mode" data-mode="html" class="${v.mode === 'html' ? 'active' : ''}" ${hasHtml ? '' : 'disabled'}>HTML</button>
          <button data-action="view-mode" data-mode="text" class="${v.mode === 'text' ? 'active' : ''}">Texto${hasText ? '' : ' (extraído)'}</button>
          ${entry.ai.translation !== undefined ? `<button data-action="view-mode" data-mode="trad" class="${v.mode === 'trad' ? 'active' : ''}">Traducción</button>` : ''}
        </div>
        ${v.mode === 'html' && remoteCount ? `<label class="toggle"><input type="checkbox" data-action="toggle-remote" ${v.remote ? 'checked' : ''}> Cargar imágenes remotas</label>` : ''}
        <span class="spacer"></span>
        ${entry.lang ? `<span class="muted" style="font-size:12.5px">Idioma detectado: ${esc(LANG_NAMES[entry.lang] || entry.lang)}</span>` : ''}
        ${canTranslate ? (entry.ai.ctrl.translate ? '<button class="btn small" disabled><span class="spinner"></span> Traduciendo…</button><button class="btn small" data-action="ai-cancel" data-op="translate">Cancelar</button>' : '<button class="btn small" data-action="translate">Traducir al español</button>') : ''}
      </div>${body}`;
  }

  function highlightUrls(text) {
    const re = /\b(?:https?:\/\/|www\.)[^\s<>"'()\[\]{}]+[^\s<>"'()\[\]{}.,;:!?]/gi;
    let out = '', last = 0, m;
    while ((m = re.exec(text))) {
      out += esc(text.slice(last, m.index)) + '<mark>' + esc(m[0]) + '</mark>';
      last = re.lastIndex;
    }
    return out + esc(text.slice(last));
  }

  const PLACEHOLDER = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40"><rect width="40" height="40" fill="#e5e7eb"/><path d="M12 27l6-7 5 5 3-3 4 5z" fill="#9ca3af"/><circle cx="26" cy="15" r="3" fill="#9ca3af"/></svg>');

  function dataUrlOf(node) {
    if (!node._dataUrl) {
      const type = /^image\//.test(node.contentType) ? node.contentType : 'application/octet-stream';
      node._dataUrl = `data:${type};base64,` + btoa(MIME.bytesToBinary(MIME.getBytes(node)));
    }
    return node._dataUrl;
  }

  // Prepara el HTML para mostrarlo sin scripts, sin enlaces navegables y con
  // imágenes remotas bloqueadas por CSP salvo que el usuario las permita.
  function prepareHtml(entry) {
    const { email } = entry;
    const doc = new DOMParser().parseFromString(email.html, 'text/html');
    doc.querySelectorAll('script, noscript, iframe, frame, frameset, object, embed, applet, base, meta, link, portal').forEach(n => n.remove());
    const URL_ATTRS = ['href', 'src', 'action', 'formaction', 'xlink:href', 'background', 'poster', 'srcset', 'data'];
    for (const el of doc.querySelectorAll('*')) {
      for (const at of [...el.attributes]) {
        const n = at.name.toLowerCase();
        if (n.startsWith('on')) el.removeAttribute(at.name);
        else if (URL_ATTRS.includes(n) && /^\s*(javascript|vbscript|data:text\/html)/i.test(at.value)) el.removeAttribute(at.name);
      }
    }
    doc.querySelectorAll('a[href], area[href]').forEach(a => {
      a.setAttribute('data-href', a.getAttribute('href'));
      a.removeAttribute('href');
      a.removeAttribute('target');
    });
    doc.querySelectorAll('form').forEach(f => { f.removeAttribute('action'); f.setAttribute('data-form', '1'); });
    const resolveCid = v => {
      const node = email.inlineByCid[v.replace(/^cid:/i, '').replace(/^<|>$/g, '').toLowerCase()];
      return node ? dataUrlOf(node) : PLACEHOLDER;
    };
    doc.querySelectorAll('[src], [background]').forEach(el => {
      ['src', 'background'].forEach(attr => {
        const v = el.getAttribute(attr);
        if (!v) return;
        if (/^cid:/i.test(v)) el.setAttribute(attr, resolveCid(v));
        else if (/^(https?:)?\/\//i.test(v) && !entry.view.remote) {
          el.setAttribute('data-blocked-' + attr, v);
          if (attr === 'src') el.setAttribute('src', PLACEHOLDER); else el.removeAttribute(attr);
        }
      });
    });
    if (!entry.view.remote) doc.querySelectorAll('[srcset]').forEach(el => el.removeAttribute('srcset'));
    const csp = doc.createElement('meta');
    csp.setAttribute('http-equiv', 'Content-Security-Policy');
    csp.setAttribute('content', `default-src 'none'; img-src data: ${entry.view.remote ? 'https: http:' : ''}; style-src 'unsafe-inline'; font-src data:; form-action 'none'`);
    const style = doc.createElement('style');
    style.textContent = '[data-href]{cursor:pointer;text-decoration:underline;} [data-href]:hover{outline:2px solid #2f5bd3;outline-offset:1px;} body{margin:12px;}';
    doc.head.prepend(style);
    doc.head.prepend(csp);
    return '<!doctype html>' + doc.documentElement.outerHTML;
  }

  function mountHtml(entry) {
    const frame = $('#mail-frame');
    if (!frame) return;
    const status = $('#statusbar');
    const linkByHref = new Map(entry.analysis.links.map(l => [l.href, l]));
    frame.addEventListener('load', () => {
      let d;
      try { d = frame.contentDocument; } catch (_) { d = null; }
      if (!d) return;
      const fit = () => { frame.style.height = Math.max(300, d.documentElement.scrollHeight + 8) + 'px'; };
      fit();
      setTimeout(fit, 300);
      d.addEventListener('load', fit, true);
      d.addEventListener('mouseover', e => {
        const a = e.target.closest && e.target.closest('[data-href]');
        if (!a) return;
        const href = a.getAttribute('data-href');
        const info = linkByHref.get(href.trim());
        const bad = info && info.flags.some(f => f.sev === 'high' || f.sev === 'medium');
        status.classList.toggle('warn', !!bad);
        status.textContent = '→ ' + href + (info && info.flags.length ? '   ⚠ ' + info.flags.map(f => f.msg).join(' · ') : '');
      });
      d.addEventListener('click', e => {
        const a = e.target.closest && e.target.closest('[data-href]');
        if (a) { e.preventDefault(); toast('Enlace desactivado. Destino: ' + a.getAttribute('data-href').slice(0, 90)); }
      });
      d.addEventListener('submit', e => e.preventDefault(), true);
    }, { once: true });
    frame.srcdoc = prepareHtml(entry);
  }

  // ---------- pestaña Cabeceras ----------

  const HL_HEADERS = new Set(['from', 'reply-to', 'return-path', 'sender', 'to', 'subject', 'date', 'message-id', 'authentication-results',
    'received-spf', 'dkim-signature', 'x-originating-ip', 'x-sender-ip', 'x-mailer', 'user-agent', 'x-ms-exchange-organization-authas',
    'arc-authentication-results', 'x-spam-status', 'x-spam-score', 'x-forefront-antispam-report', 'list-unsubscribe']);

  function headerRows(entry) {
    const q = state.headerFilter.toLowerCase();
    return entry.email.headers.list
      .filter(h => !q || h.name.toLowerCase().includes(q) || h.value.toLowerCase().includes(q))
      .map(h => `<tr class="${HL_HEADERS.has(h.key) ? 'hl' : ''}"><td class="name">${esc(h.name)}</td><td class="val">${esc(h.value)}${h.raw !== h.value ? `<div class="url-full">${esc(h.raw)}</div>` : ''}</td></tr>`)
      .join('') || '<tr><td colspan="2" class="muted">Ninguna cabecera coincide.</td></tr>';
  }

  function tabCabeceras(entry) {
    return `<div class="toolbar">
        <input type="search" id="hdr-filter" placeholder="Filtrar cabeceras…" value="${esc(state.headerFilter)}" style="width:280px;max-width:100%">
        <span class="spacer"></span>
        <button class="btn small" data-action="copy-headers">Copiar cabeceras</button>
      </div>
      <div class="card table-wrap"><table><thead><tr><th style="width:220px">Cabecera</th><th>Valor</th></tr></thead><tbody id="hdr-body">${headerRows(entry)}</tbody></table></div>`;
  }

  // ---------- pestaña Ruta ----------

  function tabRuta(entry) {
    const route = entry.analysis.route;
    if (!route.length) return '<div class="card card-body muted">El correo no tiene cabeceras Received (puede ser un borrador o un correo enviado desde el propio cliente).</div>';
    const delivery = entry.analysis.deliveryHop;
    const declared = route.find(h => h.ips.some(ip => !Analysis.isPrivateIP(ip)));
    const hopBadge = h => h === delivery ? '<span class="badge ok" title="El servidor de tu proveedor anotó esta IP al recibir el correo: es fiable">Entrega a tu proveedor</span>'
      : h === declared ? `<span class="badge" title="${delivery ? 'Escrito antes de llegar a tu proveedor: puede ser real o inventado' : 'Primer salto con IP pública'}">${delivery ? 'Origen declarado' : 'Origen probable'}</span>` : '';
    const first = route.find(h => h.date), last = [...route].reverse().find(h => h.date);
    const total = first && last ? (last.date - first.date) / 1000 : null;
    return `<p class="muted" style="margin-top:0">${route.length} saltos${total != null ? ` · tiempo total ${fmtDelay(total)}` : ''}. Orden cronológico: del emisor al buzón. Los primeros saltos los escribe el emisor y pueden estar falsificados; los últimos, añadidos por tu proveedor, son los fiables.</p>
      <ol class="timeline">${route.map(h => `<li>
        <span class="num">${h.hop}</span>
        <div class="hop ${h === (delivery || declared) ? 'origin' : ''}">
          <div class="hop-top">
            <span class="srv"><span class="muted">de</span> ${esc(h.from || '?')} <span class="muted">→ por</span> ${esc(h.by || '?')}</span>
            ${hopBadge(h)}
          </div>
          <div class="hop-meta">
            ${h.ips.map(ip => `<span class="badge ${Analysis.isPrivateIP(ip) ? '' : 'ok'}">${esc(ip)}${Analysis.isPrivateIP(ip) ? ' · privada' : ''}</span>`).join('')}
            ${h.with ? `<span class="badge">${esc(h.with)}</span>` : ''}
            ${h.tls ? '<span class="badge pass">TLS</span>' : ''}
            <span>${fmtDate(h.date)}</span>
            ${h.delay != null ? `<span class="${h.delay > 600 || h.delay < -60 ? 'badge medium' : ''}">+${fmtDelay(h.delay)}</span>` : ''}
          </div>
          <details><summary class="muted">Cabecera original</summary><pre>${esc(h.raw)}</pre></details>
        </div></li>`).join('')}
      </ol>`;
  }

  // ---------- pestaña Autenticación ----------

  function tabAuth(entry) {
    const a = entry.analysis, au = a.auth;
    const card = (title, r, extra) => `<div class="auth-card"><h3>${title} ${r ? authResult(r.result) : '<span class="badge none">sin datos</span>'}</h3>
      ${r && r.server ? `<p>Evaluado por ${esc(r.server)}</p>` : ''}
      ${r ? Object.entries(r.props).map(([k, v]) => `<p><span class="mono">${esc(k)}</span> = ${esc(v)}</p>`).join('') : ''}
      ${r && r.comment ? `<p>${esc(r.comment)}</p>` : ''}${extra || ''}</div>`;
    const dkimD = au.dkimSigs.map(s => s.domain);
    const rows = [
      ['From (header.from)', a.fromDomain, true],
      ['Return-Path (smtp.mailfrom)', Analysis.domainOf(a.returnPath), Analysis.orgDomain(Analysis.domainOf(a.returnPath)) === Analysis.orgDomain(a.fromDomain)],
      ...dkimD.map(d => ['DKIM d=', d, Analysis.orgDomain(d) === Analysis.orgDomain(a.fromDomain)]),
      ...a.replyTo.map(r => ['Reply-To', Analysis.domainOf(r.address), Analysis.orgDomain(Analysis.domainOf(r.address)) === Analysis.orgDomain(a.fromDomain)]),
    ];
    return `${sourceNotice(entry)}${a.summary.noAuthHeaders ? '<div class="notice">Este correo no contiene cabeceras Authentication-Results ni Received-SPF, así que no hay veredicto del servidor receptor.</div>' : ''}
      <div class="auth-grid">
        ${card('SPF', au.spf)}
        ${card('DKIM', au.dkim, au.dkimAll.length > 1 ? `<p>${au.dkimAll.length} firmas evaluadas: ${au.dkimAll.map(r => esc(authText(r.result))).join(', ')}</p>` : '')}
        ${card('DMARC', au.dmarc)}
        ${au.arc ? card('ARC', au.arc) : ''}
        ${au.compauth ? card('Microsoft compauth', au.compauth) : ''}
      </div>
      ${relaySection(a)}
      ${dkimCryptoSection(entry)}
      ${antispamSection(entry)}
      <section class="card" style="margin-top:16px">
        <div class="card-head"><h2>Alineación de dominios</h2><span class="muted">DMARC exige que SPF o DKIM coincidan con el dominio del From</span></div>
        <div class="table-wrap"><table><thead><tr><th>Identidad</th><th>Dominio</th><th>Alineado con From</th></tr></thead><tbody>
          ${rows.filter(r => r[1]).map(([k, d, ok]) => `<tr><td>${esc(k)}</td><td class="val">${esc(d)}</td><td>${k.startsWith('From') ? '—' : `<span class="badge ${ok ? 'pass' : 'medium'}">${ok ? 'Sí' : 'No'}</span>`}</td></tr>`).join('')}
        </tbody></table></div>
      </section>
      ${au.dkimSigs.length ? `<section class="card" style="margin-top:16px"><div class="card-head"><h2>Firmas DKIM</h2></div>
        <div class="table-wrap"><table><thead><tr><th>Dominio (d=)</th><th>Selector (s=)</th><th>Algoritmo</th><th>Cabeceras firmadas</th></tr></thead><tbody>
        ${au.dkimSigs.map(s => `<tr><td class="val">${esc(s.domain)}</td><td class="val">${esc(s.selector)}</td><td class="val">${esc(s.algorithm)}</td><td class="val">${esc(s.headers)}</td></tr>`).join('')}
        </tbody></table></div></section>` : ''}
      ${au.authResults.length ? `<section class="card" style="margin-top:16px"><div class="card-head"><h2>Authentication-Results</h2><span class="muted">sólo cuenta el del receptor final, si aparece en la ruta</span></div>
        <div class="card-body">${entry.email.headers.getAll('authentication-results').map((v, i) => {
          const set = au.authResults[i];
          const tag = au.trustedResults.includes(set) ? '<span class="badge pass">se tiene en cuenta</span>'
            : !set.inRoute ? '<span class="badge medium">ignorado: su servidor no aparece en la ruta</span>'
            : '<span class="badge">ignorado: de un servidor intermedio</span>';
          return `${tag}<pre class="plain" style="padding:8px 0;max-height:none">${esc(v)}</pre>`;
        }).join('<hr style="border:0;border-top:1px solid var(--border)">')}</div></section>` : ''}`;
  }

  // Autenticación del remitente real que Apple comprobó antes de reenviar el correo.
  function relaySection(a) {
    const r = a.relay;
    if (!r) return '';
    const aligned = d => Analysis.orgDomain(d) === Analysis.orgDomain(r.domain);
    const rows = [
      ...r.dkim.map(x => ['DKIM d=', x.domain, x.result]),
      r.spf ? ['SPF (smtp.mailfrom)', r.spf.domain, r.spf.result] : null,
    ].filter(Boolean);
    return `<section class="card" style="margin-top:16px">
      <div class="card-head"><h2>Remitente real · ${esc(r.service)}</h2><span class="muted">${esc(r.original.address)}</span></div>
      <div class="card-body" style="font-size:13px">Apple sustituye la dirección del remitente por una de <span class="mono">${esc(r.relayDomain)}</span> para no revelar la tuya, así que los resultados de arriba son los del reenvío. Estos son los que Apple comprobó al recibir el correo (cabeceras de <span class="mono">icloud.com</span>).</div>
      ${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Identidad</th><th>Dominio</th><th>Resultado</th><th>Alineado con ${esc(r.domain)}</th></tr></thead><tbody>
        ${rows.map(([k, d, res]) => `<tr><td>${esc(k)}</td><td class="val">${esc(d)}</td><td>${authResult(res)}</td><td><span class="badge ${aligned(d) ? 'pass' : 'medium'}">${aligned(d) ? 'Sí' : 'No'}</span></td></tr>`).join('')}
      </tbody></table></div>` : '<div class="card-body muted">Apple no dejó resultados de autenticación del remitente real.</div>'}
    </section>`;
  }

  // ---------- DKIM criptográfico y antispam (pestaña Autenticación) ----------

  const RESULT_LABEL = { pass: 'válida', fail: 'inválida', permerror: 'no verificable', temperror: 'error temporal', neutral: 'neutral', skipped: 'no verificada aquí' };

  function dkimCryptoSection(entry) {
    const a = entry.analysis;
    const o = entry.online;
    const head = '<div class="card-head"><h2>Verificación criptográfica DKIM</h2><span class="muted">clave pública obtenida por DNS · firma comprobada en tu navegador</span></div>';
    if (entry.email.sourceFormat === 'msg') return `<section class="card" style="margin-top:16px">${head}<div class="card-body muted">No se puede verificar en un correo convertido desde .msg: Outlook guarda el cuerpo en su propio formato y ya no coincide byte a byte con lo que se firmó.${a.auth.dkimSigs.length ? ` Firmas presentes: ${esc(a.auth.dkimSigs.map(x => 'd=' + x.domain).join(', '))}.` : ''}</div></section>`;
    if (!a.auth.dkimSigs.length) return `<section class="card" style="margin-top:16px">${head}<div class="card-body muted">${a.summary.outlookExport ? 'Outlook eliminó las firmas DKIM-Signature al exportar este correo, así que no hay nada que verificar.' : 'El correo no tiene firmas DKIM-Signature.'}</div></section>`;
    if (!o) {
      return `<section class="card" style="margin-top:16px">${head}<div class="card-body">
        <p style="margin-top:0">Hay ${plural(a.auth.dkimSigs.length, 'firma', 'firmas')}. Para comprobarlas hay que consultar por DNS la clave pública de cada selector (<span class="mono">${esc(a.auth.dkimSigs.map(x => x.selector + '._domainkey.' + x.domain).join(', '))}</span>). Sólo se envía ese nombre; el mensaje se verifica en local.</p>
        <button class="btn primary" data-action="online-run">Verificar firmas DKIM</button>
        <span class="muted" style="font-size:12.5px;margin-left:8px">También lanza las comprobaciones de DNS y WHOIS.</span></div></section>`;
    }
    if (!o.dkim) return `<section class="card" style="margin-top:16px">${head}<div class="card-body muted"><span class="spinner"></span> Consultando claves y verificando…</div></section>`;
    return `<section class="card" style="margin-top:16px">${head}
      <div class="table-wrap"><table><thead><tr><th>Dominio (d=)</th><th>Selector</th><th>Algoritmo</th><th>Canon.</th><th>Hash cuerpo</th><th>Clave</th><th>Firma</th></tr></thead><tbody>
      ${o.dkim.map(r => `<tr>
        <td class="val">${esc(r.domain)}${r.domain && Analysis.orgDomain(r.domain) === Analysis.orgDomain(a.senderDomain || a.fromDomain) ? ' <span class="badge pass">alineado</span>'
          : a.relay && r.domain && Analysis.orgDomain(r.domain) === Analysis.orgDomain(a.relay.relayDomain) ? ' <span class="badge">reenvío de Apple</span>' : ''}</td>
        <td class="val">${esc(r.selector)}</td>
        <td class="val">${esc(r.algorithm || '')}</td>
        <td class="val">${esc(r.canon || '')}</td>
        <td>${r.bodyHashOk == null ? '—' : r.bodyHashOk ? '<span class="badge pass">coincide</span>' : '<span class="badge fail">no coincide</span>'}${r.partialBody ? ` <span class="badge fail">+${r.partialBody} B sin firmar</span>` : ''}</td>
        <td class="val">${r.keyBits ? r.keyBits + ' bits' : '—'}${r.testing ? ' <span class="badge low">t=y</span>' : ''}</td>
        <td><span class="badge ${esc(r.result)}">${esc(RESULT_LABEL[r.result] || r.result)}</span><div class="url-full" style="margin-top:4px">${esc(r.reason)}</div>
          ${r.keyRecord ? `<details style="margin-top:4px"><summary class="muted" style="font-size:12px">Registro DNS</summary><div class="url-full">${esc(r.keyRecord)}</div></details>` : ''}</td>
      </tr>`).join('')}
      </tbody></table></div>
      ${o.dkim.some(r => r.result === 'skipped') && !o.running ? `<div class="card-body" style="font-size:12.5px;border-top:1px solid var(--border)">
        <p style="margin:0 0 8px">Las firmas <b>no verificadas aquí</b> ya las comprobó tu proveedor o llevan tu dirección. Verificarlas obliga a pedir la clave al DNS del firmante, que vería que alguien analiza el correo; si el selector es único para ti, sabría que eres tú. Sirve sobre todo para detectar un .eml modificado al exportarlo.</p>
        <button class="btn small" data-action="dkim-verify-all">Verificar todas las firmas</button></div>` : ''}
      <div class="card-body muted" style="font-size:12.5px;border-top:1px solid var(--border)">Una firma que el servidor receptor dio por buena puede fallar aquí si el .eml se alteró al exportarlo o reenviarlo, o si el remitente ya rotó la clave. Lo que vale como prueba de origen es una firma válida y alineada con el From.</div>
    </section>`;
  }

  function antispamSection(entry) {
    const list = entry.analysis.antispam || [];
    if (!list.length) return '';
    return `<section class="card" style="margin-top:16px"><div class="card-head"><h2>Veredictos antispam de los servidores</h2><span class="muted">cabeceras X-Forefront, X-Spam-Status…</span></div>
      <div class="table-wrap"><table><thead><tr><th>Filtro</th><th>Campo</th><th>Valor</th></tr></thead><tbody>
      ${list.map(x => `<tr><td>${esc(x.source)}</td><td>${esc(x.label)}</td><td class="val">${x.sev !== 'info' ? `<span class="badge ${x.sev}">${esc(x.value)}</span>` : esc(x.value)}</td></tr>`).join('')}
      </tbody></table></div></section>`;
  }

  // ---------- pestaña DNS y WHOIS ----------

  const fmtDay = d => d && !isNaN(d) ? d.toLocaleDateString('es-ES', { dateStyle: 'medium' }) : '—';
  function ageBadge(days) {
    if (days == null) return '<span class="muted">desconocida</span>';
    const txt = days < 60 ? `${days} días` : days < 730 ? `${Math.round(days / 30)} meses` : `${(days / 365).toFixed(1).replace('.0', '')} años`;
    return `<span class="badge ${days < 30 ? 'high' : days < 180 ? 'medium' : 'ok'}">${txt}</span>`;
  }
  const BL_LABEL = { clean: 'limpia', listed: 'LISTADA', refused: 'no consultable', error: 'error' };
  const BL_CLASS = { clean: 'ok', listed: 'high', refused: '', error: '' };
  function blacklists(list) {
    if (!list) return '<span class="spinner"></span>';
    return `<div class="flags">${list.map(x => `<span class="badge ${BL_CLASS[x.status]}" title="${esc(x.zone)}${x.code ? ' → ' + esc(x.code) : ''}${x.status === 'refused' ? ' · esta lista no responde a resolvedores DNS públicos' : ''}">${esc(x.list)}: ${BL_LABEL[x.status]}</span>`).join('')}</div>`;
  }
  const pending = v => v == null ? '<span class="spinner"></span>' : v;
  const extLink = (href, label) => `<a class="btn small" href="${esc(href)}" target="_blank" rel="noopener noreferrer">${label}</a>`;

  // Ajustes de las comprobaciones en línea, en un desplegable para no mezclarlos con los resultados.
  function onlineSettings() {
    return `<details class="menu settings-menu" ${state.settingsOpen ? 'open' : ''}>
      <summary class="btn small">${ICON.gear}Ajustes</summary>
      <div class="menu-pop settings-pop">
        <label class="toggle field">Resolvedor DNS
          <select id="set-provider">${Object.entries(Online.providers).map(([k, v]) => `<option value="${k}" ${state.settings.provider === k ? 'selected' : ''}>${esc(v.label)}</option>`).join('')}</select></label>
        <label class="toggle"><input type="checkbox" id="set-auto" ${state.settings.autoOnline ? 'checked' : ''}> Ejecutar al abrir cada correo</label>
        <div>
          <label class="toggle field">Clave de Safe Browsing
            <input type="password" id="set-sbkey" value="${esc(state.settings.sbKey || '')}" placeholder="${configSbKey() ? 'usando config.js' : sbProxy() ? 'usando la del servidor' : 'opcional'}" autocomplete="off" spellcheck="false"></label>
          <p class="muted settings-hint">Clave de API de Google Cloud con la Safe Browsing API activada. Se guarda sólo en este navegador; si se deja vacía, se usa la de <code>config.js</code> o, en la versión publicada, la del servidor.</p>
        </div>
      </div>
    </details>`;
  }

  // Resultado de Google Safe Browsing, con la atribución y el aviso que exigen sus condiciones.
  const SB_DISCLAIMER = 'Google trabaja para ofrecer información precisa y actualizada sobre recursos web peligrosos, pero no puede garantizar que sea completa ni que no contenga errores: algunos sitios peligrosos pueden no estar identificados y algunos sitios seguros pueden identificarse por error.';
  const sbAttribution = () => `<a href="${SafeBrowsing.ADVISORY_URL}" target="_blank" rel="noopener noreferrer">Aviso proporcionado por Google</a>`;

  function safeBrowsingCard(o) {
    const sb = o.safeBrowsing;
    let body;
    if (!sb) body = '<span class="spinner"></span> Consultando…';
    else if (sb.skipped === 'sin clave') {
      body = `No está activado. Para usarlo, crea una clave de API en <a href="https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com" target="_blank" rel="noopener noreferrer">Google Cloud</a> (activa la Safe Browsing API), pégala en «Clave de Safe Browsing» o en <code>config.js</code> y repite las comprobaciones. Es gratuita para uso no comercial.`;
    } else if (sb.skipped) body = 'El correo no tiene enlaces web que comprobar.';
    else if (sb.error) body = `<span class="badge fail">Error</span> ${esc(sb.error)}`;
    else if (!sb.matches.length) body = `<span class="badge ok">Sin coincidencias</span> Ninguna de las ${sb.urls} URL${sb.urls === 1 ? '' : 's'} figura en las listas de malware, phishing o software no deseado. ${sbAttribution()}.`;
    else {
      body = `<span class="badge high">${sb.matches.length} URL${sb.matches.length === 1 ? '' : 's'} en las listas</span>
        <ul style="margin:8px 0">${sb.matches.map(m => `<li><span class="mono" style="overflow-wrap:anywhere">${esc(m.url.slice(0, 200))}</span> — <strong>${esc(m.threats.map(SafeBrowsing.label).join(', '))}</strong>${m.embedded ? ' <span class="muted">(destino dentro de un redireccionador)</span>' : ''}</li>`).join('')}</ul>
        ${sbAttribution()}.`;
    }
    return `<section class="card" style="margin-bottom:16px"><div class="card-head"><h2>Google Safe Browsing</h2>
        <span class="muted">sólo se envían prefijos de hash de 4 bytes, no las URLs</span></div>
      <div class="card-body" style="font-size:13px">${body}
        ${sb && !sb.skipped ? `<p class="muted" style="margin:8px 0 0;font-size:12px">${SB_DISCLAIMER}</p>` : ''}</div></section>`;
  }

  // WHOIS por RDAP: vista legible en el cliente web de rdap.org y JSON del mismo
  // servidor oficial del que se sacaron los datos (o rdap.org, que redirige a él).
  function rdapLinks(type, object, r) {
    if (r && r.unsupported) return '';
    const q = encodeURIComponent(object);
    const json = r && r.source ? `${r.source}${type}/${q}` : `https://rdap.org/${type}/${q}`;
    return extLink(`https://client.rdap.org/?type=${type}&object=${q}`, 'WHOIS (RDAP)') + extLink(json, 'RDAP (JSON)');
  }

  function domainCard(d) {
    const r = d.rdap;
    const dn = d.dns;
    const rows = [];
    if (r == null) rows.push(['WHOIS', '<span class="spinner"></span>']);
    else if (r.error) rows.push(['WHOIS', `<span class="muted">${esc(r.error)}</span>`]);
    else if (r.notFound) rows.push(['WHOIS', '<span class="badge medium">No registrado</span>']);
    else {
      rows.push(['Antigüedad', ageBadge(r.ageDays) + (r.created ? ` <span class="muted">desde ${fmtDay(r.created)}</span>` : '')]);
      rows.push(['Caduca', fmtDay(r.expires)]);
      if (r.registrar) rows.push(['Registrador', esc(r.registrar)]);
      if (r.registrantOrg || r.registrantCountry) rows.push(['Titular', esc([r.registrantOrg, r.registrantCountry].filter(Boolean).join(' · '))]);
      if (r.status.length) rows.push(['Estado', `<div class="flags">${r.status.map(x => `<span class="badge ${/hold/i.test(x) ? 'high' : ''}">${esc(x)}</span>`).join('')}</div>`]);
      if (r.nameservers.length) rows.push(['Servidores DNS', `<span class="mono">${esc(r.nameservers.join(', '))}</span>`]);
      if (r.dnssec != null) rows.push(['DNSSEC', r.dnssec ? '<span class="badge pass">firmado</span>' : '<span class="badge">no</span>']);
      if (r.abuseEmail) rows.push(['Abuso', `<span class="mono">${esc(r.abuseEmail)}</span>`]);
    }
    if (dn == null) rows.push(['DNS', '<span class="spinner"></span>']);
    else if (dn.error) rows.push(['DNS', `<span class="muted">${esc(dn.error)}</span>`]);
    else if (dn.nx) rows.push(['DNS', '<span class="badge high">NXDOMAIN: no existe</span>']);
    else {
      if (d.mail) {
        rows.push(['MX', dn.mx.length ? `<span class="mono">${esc(dn.mx.map(m => m.host).join(', '))}</span>` : '<span class="badge medium">sin MX</span>']);
        rows.push(['SPF', dn.spf ? `<span class="mono">${esc(dn.spf)}</span>` : '<span class="badge low">sin SPF</span>']);
        rows.push(['DMARC', dn.dmarc ? `<span class="badge ${dn.dmarc.policy === 'reject' ? 'pass' : dn.dmarc.policy === 'quarantine' ? 'ok' : 'low'}">p=${esc(dn.dmarc.policy || '?')}</span>${dn.dmarc.from !== d.domain ? ` <span class="muted">(de ${esc(dn.dmarc.from)})</span>` : ''}<div class="url-full">${esc(dn.dmarc.record)}</div>` : '<span class="badge low">sin DMARC</span>']);
      }
      rows.push(['Resuelve a', dn.a.length ? `<span class="mono">${esc(dn.a.slice(0, 4).join(', '))}</span>` : '<span class="muted">sin registro A</span>']);
    }
    rows.push(['Listas negras', blacklists(d.dnsbl)]);
    return `<section class="card rep-card">
      <div class="card-head"><h2 class="mono">${esc(d.domain)}</h2><div class="flags">${d.roles.map(x => `<span class="badge">${esc(x)}</span>`).join('')}</div></div>
      <div class="card-body">
        ${d.masked ? `<p class="notice" style="margin:0 0 8px;font-size:12.5px">El nombre completo, <span class="mono">${esc(d.masked)}</span>, incluye tu dirección: es único para ti y consultarlo le diría al remitente que abres el correo. Se consulta sólo <span class="mono">${esc(d.domain)}</span>.</p>` : ''}
        ${d.org !== d.domain ? `<p class="muted" style="margin:0 0 8px;font-size:12.5px">WHOIS y listas del dominio registrable <span class="mono">${esc(d.org)}</span></p>` : ''}
        <dl class="facts">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>
        <div class="att-actions">${rdapLinks('domain', d.org, r)}${extLink('https://www.virustotal.com/gui/domain/' + encodeURIComponent(d.org), 'VirusTotal')}${extLink('https://urlscan.io/domain/' + encodeURIComponent(d.org), 'urlscan.io')}</div>
      </div></section>`;
  }

  function ipCard(i) {
    const r = i.rdap, p = i.ptr;
    const rows = [];
    rows.push(['DNS inverso', p == null ? '<span class="spinner"></span>' : p.skipped ? '<span class="muted" title="La zona inversa de una IP elegida por el remitente puede ser suya: consultarla le diría que alguien analiza el correo">no se consulta (IP elegida por el remitente)</span>'
      : p.error ? `<span class="muted">${esc(p.error)}</span>` : p.ptr
      ? `<span class="mono">${esc(p.ptr)}</span> ${p.fcrdns === true ? '<span class="badge pass">confirmado</span>' : p.fcrdns === false ? '<span class="badge low">no confirma</span>' : ''}`
      : '<span class="badge low">sin PTR</span>']);
    if (r == null) rows.push(['Titular', '<span class="spinner"></span>']);
    else if (r.error) rows.push(['Titular', `<span class="muted">${esc(r.error)}</span>`]);
    else {
      if (r.org || r.name) rows.push(['Titular', esc([...new Set([r.name, r.org].filter(Boolean))].join(' · '))]);
      if (r.country) rows.push(['País', esc(r.country)]);
      if (r.range) rows.push(['Rango', `<span class="mono">${esc(r.range)}</span>`]);
      if (r.abuseEmail) rows.push(['Abuso', `<span class="mono">${esc(r.abuseEmail)}</span>`]);
    }
    rows.push(['Listas negras', blacklists(i.dnsbl)]);
    return `<section class="card rep-card">
      <div class="card-head"><h2 class="mono">${esc(i.ip)}</h2><div class="flags">${i.roles.map(x => `<span class="badge">${esc(x)}</span>`).join('')}</div></div>
      <div class="card-body"><dl class="facts">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>
        <div class="att-actions">${rdapLinks('ip', i.ip, r)}${extLink('https://www.abuseipdb.com/check/' + encodeURIComponent(i.ip), 'AbuseIPDB')}${extLink('https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(i.ip), 'VirusTotal')}</div>
      </div></section>`;
  }

  function tabReputacion(entry) {
    const o = entry.online;
    if (!o) {
      return `<section class="card"><div class="card-head"><h2>Comprobaciones en línea</h2></div><div class="card-body">
        <p style="margin-top:0">Consultan servicios públicos para completar el análisis:</p>
        <ul>
          <li><strong>DKIM:</strong> descarga la clave pública de cada firma y la verifica criptográficamente en tu navegador.</li>
          <li><strong>WHOIS (RDAP):</strong> antigüedad, registrador y estado de los dominios del remitente y de los enlaces. Un dominio de pocos días es una señal fuerte de phishing.</li>
          <li><strong>DNS:</strong> si los dominios existen, MX, SPF y política DMARC del remitente, y DNS inverso de la IP de origen.</li>
          <li><strong>Listas negras:</strong> SpamCop, Barracuda, URIBL y otras, para la IP de origen y los dominios.</li>
          <li><strong>Titular de la IP de origen:</strong> organización, país y contacto de abuso.</li>
          <li><strong>Google Safe Browsing</strong> (opcional, con clave de API): si algún enlace, o el destino que lleva dentro un redireccionador, está en las listas de malware o phishing de Google.</li>
        </ul>
        <p class="notice" style="color:var(--text);background:var(--surface-2)">Privacidad: sólo se envían <strong>nombres de dominio, IPs y selectores DKIM</strong> al resolvedor DNS elegido y a los servidores RDAP de cada registro. El contenido del correo nunca sale del equipo. De los enlaces se consulta sólo el dominio registrable, no la URL ni el subdominio, para no delatar que se ha abierto el correo. A Safe Browsing sólo se envían prefijos de 4 bytes del hash de cada URL, que comparten miles de direcciones.</p>
        <div class="toolbar" style="margin:0"><button class="btn primary" data-action="online-run">Ejecutar comprobaciones</button><span class="spacer"></span>${onlineSettings()}</div>
      </div></section>`;
    }
    const domains = Object.values(o.domains || {});
    const ips = Object.values(o.ips || {});
    const findings = o.findings || [];
    return `<div class="toolbar">
        ${o.running ? '<span class="muted"><span class="spinner"></span> Consultando…</span>' : `<span class="muted" style="font-size:12.5px">Completado ${o.finishedAt ? 'a las ' + o.finishedAt.toLocaleTimeString('es-ES') : ''} · DNS: ${esc((Online.providers[o.provider] || {}).label || o.provider || '')}</span>`}
        <button class="btn small" data-action="online-run" ${o.running ? 'disabled' : ''}>Repetir</button>
        <span class="spacer"></span>${onlineSettings()}
      </div>
      ${o.error ? `<p class="notice">${esc(o.error)}</p>` : ''}
      ${(o.errors || []).map(e => `<p class="notice">${esc(e)}</p>`).join('')}
      ${rescoreBanner(entry)}
      ${safeBrowsingCard(o)}
      ${findings.length ? `<section class="card" style="margin-bottom:16px"><div class="card-head"><h2>Hallazgos en línea</h2><span class="muted">${findings.length}</span></div>
        ${findingsList(findings, entry.trustVoided)}</section>` : ''}
      <h3 class="section-title">Dominios</h3>
      <div class="rep-grid">${domains.map(domainCard).join('') || '<p class="muted">Sin dominios que consultar.</p>'}</div>
      <h3 class="section-title">Direcciones IP</h3>
      <div class="rep-grid">${ips.map(ipCard).join('') || '<p class="muted">No hay IP de origen pública identificada.</p>'}</div>`;
  }

  // ---------- pestaña Enlaces ----------

  function tabEnlaces(entry) {
    const a = entry.analysis;
    const links = state.linkFilter ? a.links.filter(l => l.flags.some(f => f.sev !== 'info')) : a.links;
    const worst = l => ['high', 'medium', 'low', 'info'].find(s => l.flags.some(f => f.sev === s)) || '';
    const html = a.html;
    return `${html.forms.length ? `<div class="notice">El HTML contiene ${plural(html.forms.length, 'formulario', 'formularios')}: ${esc(html.forms.map(f => f.action).join(', '))}</div>` : ''}
      <div class="toolbar">
        <label class="toggle"><input type="checkbox" data-action="link-filter" ${state.linkFilter ? 'checked' : ''}> Sólo enlaces con alertas</label>
        <span class="spacer"></span>
        <span class="muted" style="font-size:12.5px">${plural(a.links.length, 'enlace', 'enlaces')} · ${plural(new Set(a.links.map(l => l.host)).size, 'dominio', 'dominios')} · ${plural(html.remoteImages.length, 'imagen remota', 'imágenes remotas')}${html.trackingPixels ? ` · ${plural(html.trackingPixels, 'píxel', 'píxeles')} de seguimiento` : ''}</span>
        ${a.links.length ? '<button class="btn small" data-action="copy-urls">Copiar URLs</button>' : ''}
      </div>
      ${links.length ? `<div class="card table-wrap"><table><thead><tr><th>Texto visible</th><th>Destino real</th><th>Alertas</th><th></th></tr></thead><tbody>
        ${links.map(l => `<tr>
          <td style="max-width:260px;overflow-wrap:anywhere">${esc(l.text || '—')}<div class="url-full">${esc(l.source)}</div></td>
          <td><div class="host">${esc(l.host || l.scheme + ':')}</div><div class="url-full">${esc(l.href.length > 300 ? l.href.slice(0, 300) + '…' : l.href)}</div></td>
          <td><div class="flags">${l.flags.map(f => `<span class="badge ${f.sev}">${esc(f.msg)}</span>`).join('') || `<span class="badge ok">Sin alertas</span>`}</div></td>
          <td><button class="copy-btn" data-copy="${esc(l.href)}">Copiar</button></td></tr>`).join('')}
      </tbody></table></div>` : `<div class="card card-body muted">${a.links.length ? 'Ningún enlace tiene alertas.' : 'El correo no contiene enlaces.'}</div>`}
      ${a.links.some(l => l.flags.some(f => /^Google Safe Browsing/.test(f.msg))) ? `<p class="muted" style="font-size:12px">Las alertas de Google Safe Browsing: ${sbAttribution()}. ${SB_DISCLAIMER}</p>` : ''}`;
  }

  // ---------- pestaña Adjuntos ----------

  function tabAdjuntos(entry) {
    const atts = entry.analysis.attachments;
    if (!atts.length) return '<div class="card card-body muted">El correo no tiene adjuntos.</div>';
    return `<div class="attachments">${atts.map((x, i) => {
      const danger = x.flags.some(f => f.sev === 'high');
      const isImg = /^image\/(png|jpe?g|gif|webp|bmp)$/.test(x.contentType) && ['PNG', 'JPEG', 'GIF', ''].includes(x.magic);
      const isText = /^text\/(plain|csv|calendar)$/.test(x.contentType) || /^(txt|csv|ics|log)$/.test(x.ext);
      return `<div class="card att">
        <div class="ico ${danger ? 'danger' : ''}">${esc((x.ext || '?').slice(0, 5))}</div>
        <div>
          <div class="att-name">${esc(x.name)}</div>
          <div class="att-meta"><span>${esc(x.contentType)}</span><span>${fmtBytes(x.size)}</span>${x.magic ? `<span>Contenido real: ${esc(x.magic)}</span>` : ''}${x.inline ? '<span>inline</span>' : ''}${x.contentId ? `<span class="mono">cid:${esc(x.contentId)}</span>` : ''}</div>
          ${x.flags.length ? `<div class="flags" style="margin-top:8px">${x.flags.map(f => `<span class="badge ${f.sev}">${esc(f.msg)}</span>`).join('')}</div>` : ''}
          ${entry.qr.filter(q => q.attachment === x).map(q => `<div class="notice" style="margin:8px 0 0">Código QR: <span class="mono">${esc(q.text.slice(0, 300))}</span>${q.link && q.link.flags.length ? ' · ' + q.link.flags.map(f => esc(f.msg)).join(' · ') : ''}</div>`).join('')}
          <div class="hash"><b>SHA-256</b><span>${esc(x.sha256)}</span><button class="copy-btn" data-copy="${esc(x.sha256)}">Copiar</button></div>
          <div class="hash"><b>SHA-1</b><span>${esc(x.sha1)}</span><button class="copy-btn" data-copy="${esc(x.sha1)}">Copiar</button></div>
          ${x.zip && x.zip.names.length ? `<details style="margin-top:6px"><summary class="muted" style="font-size:12.5px">Contenido del ZIP (${x.zip.names.length})</summary><ul class="zip-list">${x.zip.names.map(n => `<li>${esc(n)}</li>`).join('')}</ul></details>` : ''}
          <div class="att-actions">
            <button class="btn small" data-action="att-download" data-idx="${i}">Descargar</button>
            ${x.isEmail ? `<button class="btn small" data-action="att-open" data-idx="${i}">Analizar como correo</button>` : ''}
            ${isImg || isText ? `<button class="btn small" data-action="att-preview" data-idx="${i}">Vista previa</button>` : ''}
            ${x.sha256 ? `<a class="btn small" href="https://www.virustotal.com/gui/file/${esc(x.sha256)}" target="_blank" rel="noopener noreferrer" title="Busca sólo el hash; no sube el fichero">Buscar hash en VirusTotal</a>` : ''}
          </div>
          <div class="preview" id="preview-${i}"></div>
        </div>
      </div>`;
    }).join('')}</div>`;
  }

  // ---------- pestaña Estructura ----------

  function tabEstructura(entry) {
    const nodeHtml = n => {
      const size = n.isEmbeddedMessage ? n.embeddedRaw.length : n.children.length ? n.rawBody.length : MIME.getBytes(n).length;
      const meta = [
        n.path.length ? 'parte ' + n.path.join('.') : 'raíz',
        n.charset && 'charset=' + n.charset,
        n.cte && n.cte,
        n.disposition && n.disposition,
        n.filename && '«' + n.filename + '»',
        n.contentId && 'cid:' + n.contentId,
        n.params.boundary && 'boundary=' + n.params.boundary,
        fmtBytes(size),
      ].filter(Boolean);
      return `<li><span class="node"><span class="ct">${esc(n.contentType)}</span><span class="meta">${meta.map(esc).join(' · ')}</span>
        ${n.warnings.map(w => `<span class="badge low">${esc(w)}</span>`).join('')}</span>
        ${n.children.length ? `<ul>${n.children.map(nodeHtml).join('')}</ul>` : ''}</li>`;
    };
    return `<div class="card card-body"><ul class="tree">${nodeHtml(entry.email.root)}</ul></div>`;
  }

  // ---------- pestaña IOCs ----------

  // Defang: neutraliza los IOCs para que no sean clicables ni resolubles al pegarlos.
  const defang = v => String(v).replace(/\./g, '[.]');
  const iocValue = v => state.settings.defang ? defang(v) : v;

  // Qué se ha consultado de los IOCs y con qué resultado (resumen de la pestaña IOCs).
  function iocCoverage(entry, st) {
    const o = entry.online;
    if (!o) return 'Reputación sin consultar: ejecuta las comprobaciones en línea (pestaña DNS y WHOIS).';
    if (o.running) return '<span class="spinner"></span> Consultando la reputación de los indicadores…';
    if (!st.ran) return 'No se pudieron completar las comprobaciones en línea.';
    const sb = st.safeBrowsing || {};
    const sbText = sb.matches ? `Google Safe Browsing: ${sb.urls} URL${sb.urls === 1 ? '' : 's'} y ${sb.domains || 0} dominio${sb.domains === 1 ? '' : 's'} del remitente (${sbAttribution()})`
      : sb.skipped === 'sin clave' ? 'Google Safe Browsing: desactivado (sin clave)' : sb.error ? `Google Safe Browsing: error (${esc(sb.error)})` : 'Google Safe Browsing: nada que consultar';
    return `Consultado: listas negras y DNS inverso de la IP de origen · DNS, WHOIS y listas negras de los dominios · ${sbText}. Los correos y los hashes no se consultan.`;
  }

  function tabIocs(entry) {
    const i = entry.analysis.iocs;
    const st = Online.iocStatus(entry);
    // Alertas del indicador, «sin coincidencias» si se consultó y no salió nada, o nada si no se consultó.
    // En gris, no en verde: no figurar en las listas no significa que sea seguro.
    const rep = s => !s ? '' : s.issues.length ? s.issues.map(x => ` <span class="badge ${x.sev}">${esc(x.msg)}</span>`).join('')
      : ' <span class="badge" title="Consultado sin resultados en las listas y registros. No prueba que sea seguro: revisa también los hallazgos del análisis.">sin coincidencias</span>';
    const group = (title, key, items, render) => `<div class="ioc-group">
      <h3>${title} <span class="muted">${items.length}</span>${items.length ? `<button class="copy-btn" data-action="copy-group" data-group="${key}">Copiar todo</button>` : ''}</h3>
      ${items.length ? `<ul class="ioc-list">${items.map(render).join('')}</ul>` : '<p class="muted" style="margin:0">Ninguno.</p>'}</div>`;
    const simple = (v, s) => `<li><span>${esc(iocValue(v))}${rep(s)}</span><span class="tools"><button class="copy-btn" data-copy="${esc(iocValue(v))}">Copiar</button></span></li>`;
    return `<div class="toolbar"><span class="muted">Indicadores extraídos para búsqueda en SIEM, listas de bloqueo o servicios de reputación.</span><span class="spacer"></span>
        <label class="toggle" title="Sustituye cada punto por [.] (evil.com → evil[.]com) al copiar y en el CSV"><input type="checkbox" id="set-defang" ${state.settings.defang ? 'checked' : ''}> Defang al copiar (. → [.])</label>
        <button class="btn small" data-action="export-csv">Exportar CSV</button>
        <button class="btn small" data-action="export-json">Exportar JSON</button></div>
      <p class="muted" style="font-size:12.5px;margin:0 0 10px">${iocCoverage(entry, st)}</p>
      <div class="card card-body">
        ${group('Direcciones IP públicas', 'ips', i.ips, ip => `<li><span>${esc(iocValue(ip))}${ip === i.originIP ? ' <span class="badge">origen</span>' : ''}${rep(st.ips[ip])}</span><span class="tools"><button class="copy-btn" data-copy="${esc(iocValue(ip))}">Copiar</button></span></li>`)}
        ${group('Dominios', 'domains', i.domains, d => simple(d, st.domains[d]))}
        ${group('Direcciones de correo', 'emails', i.emails, e => simple(e))}
        ${group('URLs', 'urls', i.urls, u => simple(u, st.urls[u]))}
        ${group('Hashes de adjuntos (SHA-256)', 'hashes', i.hashes, h => `<li><span>${esc(h.sha256)}<br><span class="muted">${esc(h.name)}</span></span><span class="tools"><button class="copy-btn" data-copy="${esc(h.sha256)}">Copiar</button></span></li>`)}
      </div>`;
  }

  function iocGroupText(i, key) {
    return key === 'hashes' ? i.hashes.map(h => h.sha256).join('\n') : i[key].map(iocValue).join('\n');
  }

  // ---------- pestaña Fuente ----------

  const RAW_LIMIT = 400 * 1024;
  function tabFuente(entry) {
    const raw = entry.email.raw;
    const all = entry.view.rawAll || raw.length <= RAW_LIMIT;
    const text = MIME.decodeBytes(MIME.binaryToBytes(all ? raw : raw.slice(0, RAW_LIMIT)));
    return `<div class="toolbar"><span class="muted">${fmtBytes(raw.length)}</span><span class="spacer"></span>
        ${all ? '' : '<button class="btn small" data-action="raw-all">Mostrar todo</button>'}
        <button class="btn small" data-action="raw-copy">Copiar</button>
        <button class="btn small" data-action="raw-download">Descargar .eml</button></div>
      <div class="viewer"><pre class="plain">${esc(text)}${all ? '' : '\n\n[… truncado …]'}</pre></div>`;
  }

  // ---------- exportación ----------

  function reportJSON(entry) {
    const a = entry.analysis;
    return JSON.stringify({
      fichero: entry.name,
      generado: new Date().toISOString(),
      asunto: a.subject,
      de: a.from, responderA: a.replyTo, returnPath: a.returnPath, para: a.to, cc: a.cc,
      reenvio: a.relay ? { servicio: a.relay.service, remitenteReal: a.relay.original, autenticado: a.relay.authenticated, dkim: a.relay.dkim, spf: a.relay.spf } : null,
      fecha: a.date ? a.date.toISOString() : null,
      messageId: a.messageId,
      riesgo: { puntuacion: entry.score, nivel: entry.level },
      autenticacion: a.summary,
      hallazgos: entry.findings.map(f => ({ severidad: f.sev, categoria: f.category, titulo: f.title, detalle: f.detail, enLinea: !!f.online })),
      ruta: a.route.map(h => ({ salto: h.hop, de: h.from, por: h.by, ips: h.ips, protocolo: h.with, tls: h.tls, fecha: h.date ? h.date.toISOString() : null, retrasoSeg: h.delay })),
      enlaces: a.links.map(l => ({ texto: l.text, url: l.href, host: l.host, alertas: l.flags.map(f => f.msg) })),
      adjuntos: a.attachments.map(x => ({ nombre: x.name, tipo: x.contentType, tamano: x.size, contenidoReal: x.magic, sha256: x.sha256, sha1: x.sha1, alertas: x.flags.map(f => f.msg) })),
      iocs: a.iocs,
      reputacionIocs: (({ ips, domains, urls }) => ({ ips, dominios: domains, urls }))(Online.iocStatus(entry)),
      qr: entry.qr.map(q => ({ adjunto: q.attachment.name, contenido: q.text })),
      antispam: a.antispam,
      enLinea: entry.online && !entry.online.running ? {
        fecha: entry.online.finishedAt,
        dkim: (entry.online.dkim || []).map(r => ({ dominio: r.domain, selector: r.selector, algoritmo: r.algorithm, resultado: r.result, motivo: r.reason, hashCuerpo: r.bodyHashOk, bitsClave: r.keyBits })),
        dominios: Object.values(entry.online.domains).map(d => ({
          dominio: d.domain, roles: d.roles,
          whois: d.rdap && !d.rdap.error ? { creado: d.rdap.created, caduca: d.rdap.expires, antiguedadDias: d.rdap.ageDays, registrador: d.rdap.registrar, estado: d.rdap.status } : (d.rdap && d.rdap.error) || null,
          dns: d.dns && !d.dns.error ? { existe: !d.dns.nx, mx: d.dns.mx.map(m => m.host), spf: d.dns.spf || null, dmarc: d.dns.dmarc ? d.dns.dmarc.record : null } : null,
          listasNegras: (d.dnsbl || []).filter(x => x.status === 'listed').map(x => x.list),
        })),
        ips: Object.values(entry.online.ips).map(i => ({ ip: i.ip, roles: i.roles, ptr: i.ptr && i.ptr.ptr, titular: i.rdap && (i.rdap.org || i.rdap.name), pais: i.rdap && i.rdap.country, listasNegras: (i.dnsbl || []).filter(x => x.status === 'listed').map(x => x.list) })),
      } : null,
      ia: entry.ai.verdict ? { modelo: MODEL, veredicto: entry.ai.verdict, resumen: entry.ai.summary || null } : null,
    }, null, 2);
  }

  function reportCSV(entry) {
    const i = entry.analysis.iocs;
    // Un valor que empieza por = + - @ se ejecutaría como fórmula al abrir el CSV en Excel
    // (p. ej. un adjunto llamado «=HYPERLINK(…)»): se antepone ' para que quede como texto.
    const q = v => '"' + String(v).replace(/^[=+\-@\t\r]/, "'$&").replace(/"/g, '""') + '"';
    const st = Online.iocStatus(entry);
    // reputacion: alertas separadas por «; », «sin coincidencias» si se consultó, vacío si no se consultó.
    const rep = s => !s ? '' : s.issues.length ? s.issues.map(x => x.msg).join('; ') : 'sin coincidencias';
    const rows = [['tipo', 'valor', 'nota', 'reputacion']];
    i.ips.forEach(ip => rows.push(['ip', iocValue(ip), ip === i.originIP ? 'origen' : '', rep(st.ips[ip])]));
    i.domains.forEach(d => rows.push(['dominio', iocValue(d), '', rep(st.domains[d])]));
    i.emails.forEach(e => rows.push(['email', iocValue(e), '', '']));
    i.urls.forEach(u => rows.push(['url', iocValue(u), '', rep(st.urls[u])]));
    i.hashes.forEach(h => { rows.push(['sha256', h.sha256, h.name, '']); rows.push(['sha1', h.sha1, h.name, '']); });
    return rows.map(r => r.map(q).join(',')).join('\r\n');
  }

  function reportMarkdown(entry) {
    const a = entry.analysis;
    const L = [];
    L.push(`# Informe de análisis de correo`, '', `**Fichero:** ${entry.name}  `, `**Generado:** ${new Date().toLocaleString('es-ES')}`, '');
    L.push(`## Resumen`, '', `| Campo | Valor |`, `|---|---|`);
    [['Asunto', a.subject], ['De', addr(a.from)], ['Remitente real', a.relay ? `${a.relay.original.address} (vía ${a.relay.service})` : ''], ['Responder a', a.replyTo.map(addr).join(', ')], ['Return-Path', a.returnPath],
      ['Para', a.to.map(addr).join(', ')], ['Fecha', a.date ? a.date.toISOString() : ''], ['Message-ID', a.messageId], ['IP de origen', a.iocs.originIP],
      ['SPF / DKIM / DMARC', `${a.summary.spf} / ${a.summary.dkim} / ${a.summary.dmarc}`], ['Riesgo', `${entry.score}/100 (${entry.level})`]]
      .forEach(([k, v]) => v && L.push(`| ${k} | ${String(v).replace(/\|/g, '\\|')} |`));
    if (entry.ai.verdict) {
      const v = entry.ai.verdict;
      L.push('', `## Veredicto de la IA (${MODEL})`, '', `**${VERDICT_LABEL[v.veredicto] || v.veredicto}** — ${v.tipo} (confianza ${v.confianza}%)`, '', v.resumen, '');
      (v.razones || []).forEach(r => L.push(`- ${r}`));
      if (v.accion) L.push('', `**Acción recomendada:** ${v.accion}`);
    }
    L.push('', '## Hallazgos', '');
    entry.findings.forEach(f => L.push(`- **[${SEV_LABEL[f.sev]}] ${f.title}**${f.detail ? ' — ' + f.detail : ''}`));
    if (a.route.length) {
      L.push('', '## Ruta de entrega', '', '| # | De | Por | IPs | Fecha |', '|---|---|---|---|---|');
      a.route.forEach(h => L.push(`| ${h.hop} | ${h.from} | ${h.by} | ${h.ips.join(', ')} | ${h.date ? h.date.toISOString() : ''} |`));
    }
    const flagged = a.links.filter(l => l.flags.some(f => f.sev !== 'info'));
    if (flagged.length) {
      L.push('', '## Enlaces con alertas', '');
      flagged.forEach(l => L.push(`- \`${l.href}\` — ${l.flags.map(f => f.msg).join('; ')}`));
    }
    if (a.attachments.length) {
      L.push('', '## Adjuntos', '', '| Nombre | Tipo | Tamaño | SHA-256 | Alertas |', '|---|---|---|---|---|');
      a.attachments.forEach(x => L.push(`| ${x.name} | ${x.contentType} | ${x.size} | \`${x.sha256}\` | ${x.flags.map(f => f.msg).join('; ')} |`));
    }
    const o = entry.online;
    if (o && !o.running) {
      if (o.dkim && o.dkim.length) {
        L.push('', '## Verificación DKIM (criptográfica)', '', '| Dominio | Selector | Algoritmo | Resultado | Detalle |', '|---|---|---|---|---|');
        o.dkim.forEach(r => L.push(`| ${r.domain} | ${r.selector} | ${r.algorithm || ''} | ${r.result} | ${(r.reason || '').replace(/\|/g, '\\|')} |`));
      }
      const doms = Object.values(o.domains);
      if (doms.length) {
        L.push('', '## Dominios (WHOIS y DNS)', '', '| Dominio | Rol | Creado | Antigüedad | Registrador | DMARC | Listas negras |', '|---|---|---|---|---|---|---|');
        doms.forEach(d => {
          const r = d.rdap || {};
          L.push(`| ${d.domain} | ${d.roles.join(', ')} | ${r.created ? r.created.toISOString().slice(0, 10) : '—'} | ${r.ageDays != null ? r.ageDays + ' días' : '—'} | ${r.registrar || '—'} | ${d.dns && d.dns.dmarc ? 'p=' + d.dns.dmarc.policy : d.mail ? 'sin DMARC' : '—'} | ${(d.dnsbl || []).filter(x => x.status === 'listed').map(x => x.list).join(', ') || 'ninguna'} |`);
        });
      }
      Object.values(o.ips).forEach(i => L.push('', `**IP ${i.ip}** (${i.roles.join(', ')}): ${[i.rdap && (i.rdap.org || i.rdap.name), i.rdap && i.rdap.country, i.ptr && i.ptr.ptr && 'PTR ' + i.ptr.ptr].filter(Boolean).join(' · ')}. Listas negras: ${(i.dnsbl || []).filter(x => x.status === 'listed').map(x => x.list).join(', ') || 'ninguna'}.`));
    }
    if (entry.qr.length) {
      L.push('', '## Códigos QR', '');
      entry.qr.forEach(q => L.push(`- En «${q.attachment.name}»: \`${q.text}\``));
    }
    L.push('', '## IOCs', '');
    if (a.iocs.ips.length) L.push('**IPs:** ' + a.iocs.ips.join(', '), '');
    if (a.iocs.domains.length) L.push('**Dominios:** ' + a.iocs.domains.join(', '), '');
    if (a.iocs.emails.length) L.push('**Correos:** ' + a.iocs.emails.join(', '), '');
    return L.join('\n');
  }

  const baseName = entry => entry.name.replace(/\.[^.]+$/, '') || 'correo';

  // ---------- eventos ----------

  async function onAction(el, entry) {
    const action = el.dataset.action;
    const a = entry && entry.analysis;
    switch (action) {
      case 'load-samples': return loadSamples();
      case 'ai-help': return openAIHelp();
      case 'ai-verdict': return runVerdict(entry);
      case 'ai-summary': return runSummary(entry);
      case 'ai-cancel': return cancelAI(entry, el.dataset.op);
      case 'online-run': return runOnline(entry);
      case 'dkim-verify-all': entry.verifyAllDkim = true; return runOnline(entry);
      case 'chat-suggest': return askChat(entry, el.dataset.q);
      case 'view-mode': entry.view.mode = el.dataset.mode; return renderTabOnly();
      case 'toggle-remote': entry.view.remote = el.checked; return renderTabOnly();
      case 'translate': return runTranslate(entry);
      case 'link-filter': state.linkFilter = el.checked; return renderTabOnly();
      case 'copy-headers': return copy(entry.email.headers.list.map(h => `${h.name}: ${h.value}`).join('\n'));
      case 'copy-urls': return copy(a.links.map(l => l.href).join('\n'));
      case 'copy-group': return copy(iocGroupText(a.iocs, el.dataset.group));
      case 'export-json': return download(baseName(entry) + '.analisis.json', reportJSON(entry), 'application/json');
      case 'export-csv': return download(baseName(entry) + '.iocs.csv', reportCSV(entry), 'text/csv');
      case 'export-md': return download(baseName(entry) + '.informe.md', reportMarkdown(entry), 'text/markdown');
      case 'raw-all': entry.view.rawAll = true; return renderTabOnly();
      case 'raw-copy': return copy(MIME.decodeBytes(MIME.binaryToBytes(entry.email.raw)));
      case 'raw-download': return download(entry.name.endsWith('.eml') ? entry.name : baseName(entry) + '.eml', MIME.binaryToBytes(entry.email.raw), 'message/rfc822');
      case 'att-download': {
        const x = a.attachments[+el.dataset.idx];
        if (x.flags.some(f => f.sev === 'high') &&
            !confirm(`«${x.name}» tiene alertas de seguridad:\n\n- ${x.flags.filter(f => f.sev === 'high').map(f => f.msg).join('\n- ')}\n\n¿Descargarlo igualmente? No lo abras fuera de un entorno aislado.`)) return;
        return download(x.name, new Blob([MIME.getBytes(x.node)], { type: 'application/octet-stream' }));
      }
      case 'att-open': {
        const x = a.attachments[+el.dataset.idx];
        return addEmail(MIME.getBytes(x.node), /\.(eml|msg)$/i.test(x.name) ? x.name : x.name + '.eml', entry.id);
      }
      case 'att-preview': {
        const idx = +el.dataset.idx;
        const x = a.attachments[idx];
        const box = $('#preview-' + idx);
        if (box.innerHTML) { box.innerHTML = ''; return; }
        if (/^image\//.test(x.contentType)) box.innerHTML = `<img alt="${esc(x.name)}" src="${dataUrlOf(x.node)}">`;
        else box.innerHTML = `<pre class="plain" style="max-height:320px;border:1px solid var(--border);border-radius:6px">${esc(MIME.getText(x.node).slice(0, 50000))}</pre>`;
        return;
      }
    }
  }

  function bindEvents() {
    const fileInput = $('#file-input');
    fileInput.addEventListener('change', () => { loadFiles([...fileInput.files]); fileInput.value = ''; });

    $('#file-list').addEventListener('click', e => {
      const close = e.target.closest('[data-close]');
      if (close) { e.stopPropagation(); removeEntry(+close.dataset.close); return; }
      const li = e.target.closest('li[data-id]');
      if (li) selectEntry(+li.dataset.id);
    });
    $('#file-list').addEventListener('keydown', e => {
      const li = e.target.closest('li[data-id]');
      if (li && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); selectEntry(+li.dataset.id); }
      if (li && e.key === 'Delete') removeEntry(+li.dataset.id);
    });
    $('#clear-all').addEventListener('click', () => {
      if (!confirm(`¿Quitar los ${state.entries.length} correos de la lista?`)) return;
      state.entries.forEach(e => { Object.values(e.ai.ctrl).forEach(c => c && c.abort()); if (e.ai.chat) e.ai.chat.destroy(); });
      state.entries = [];
      state.currentId = null;
      render();
    });

    const main = $('#main');
    main.addEventListener('click', e => {
      // El evento toggle llega en otra tarea: si la pestaña se re-renderiza antes, se perdería.
      const sum = e.target.closest('details.f-group[data-group] > summary');
      if (sum) { state.openGroups[sum.parentElement.dataset.group] = !sum.parentElement.open; return; }
      const tab = e.target.closest('[data-tab]');
      if (tab) { setTab(tab.dataset.tab, { scroll: !!tab.dataset.scroll }); return; }
      const cp = e.target.closest('[data-copy]');
      if (cp) { copy(cp.dataset.copy); return; }
      const act = e.target.closest('[data-action]');
      if (act && act.type !== 'checkbox') onAction(act, current());
    });
    main.addEventListener('change', e => {
      if (e.target.matches('[data-file-input]')) { loadFiles([...e.target.files]); e.target.value = ''; return; }
      if (e.target.id === 'set-provider') { state.settings.provider = e.target.value; Online.setProvider(e.target.value); saveSettings(); return; }
      if (e.target.id === 'set-auto') { state.settings.autoOnline = e.target.checked; saveSettings(); return; }
      if (e.target.id === 'set-sbkey') { state.settings.sbKey = e.target.value.trim(); saveSettings(); toast(state.settings.sbKey ? 'Clave guardada: repite las comprobaciones para consultar Safe Browsing' : configSbKey() ? 'Se usará la clave de config.js' : sbProxy() ? 'Se usará la clave del servidor' : 'Safe Browsing desactivado'); return; }
      if (e.target.id === 'set-defang') { state.settings.defang = e.target.checked; saveSettings(); renderTabOnly(); return; }
      if (e.target.matches('input[type=checkbox][data-action]')) onAction(e.target, current());
    });
    main.addEventListener('input', e => {
      if (e.target.id === 'hdr-filter') {
        state.headerFilter = e.target.value;
        $('#hdr-body').innerHTML = headerRows(current());
      }
    });
    // Recuerda qué desplegables están abiertos para que no se cierren al re-renderizar.
    main.addEventListener('toggle', e => {
      const d = e.target;
      if (d.matches('details.f-group[data-group]')) state.openGroups[d.dataset.group] = d.open;
      else if (d.matches('details.settings-menu')) state.settingsOpen = d.open;
    }, true);
    main.addEventListener('submit', e => {
      if (e.target.id !== 'chat-form') return;
      e.preventDefault();
      const input = e.target.elements.q;
      const q = input.value;
      input.value = '';
      askChat(current(), q);
    });

    // Arrastrar y soltar en toda la ventana.
    const overlay = $('#drop-overlay');
    let depth = 0;
    const hasFiles = e => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
    window.addEventListener('dragenter', e => { if (!hasFiles(e)) return; e.preventDefault(); depth++; overlay.hidden = false; });
    window.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
    window.addEventListener('dragleave', e => { if (!hasFiles(e)) return; depth = Math.max(0, depth - 1); if (!depth) overlay.hidden = true; });
    window.addEventListener('drop', e => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      depth = 0;
      overlay.hidden = true;
      loadFiles([...e.dataTransfer.files]);
    });

    // Pegar el código fuente de un correo con Ctrl+V.
    window.addEventListener('paste', e => {
      if (e.target.closest && e.target.closest('input, textarea')) return;
      const text = e.clipboardData && e.clipboardData.getData('text/plain');
      if (text && /^[A-Za-z-]+:\s/m.test(text.slice(0, 2000)) && /\n\r?\n/.test(text)) {
        addEmail(new TextEncoder().encode(text), 'pegado-' + new Date().toISOString().slice(11, 19).replace(/:/g, '') + '.eml');
      }
    });

    // Navegación por teclado dentro de la barra de pestañas (flechas, Inicio, Fin).
    main.addEventListener('keydown', e => {
      const btn = e.target.closest('.tabs [role=tab]');
      if (!btn) return;
      const ids = TAB_GROUPS.map(g => g.id);
      let i = ids.indexOf(btn.dataset.tab);
      if (e.key === 'ArrowRight') i = (i + 1) % ids.length;
      else if (e.key === 'ArrowLeft') i = (i - 1 + ids.length) % ids.length;
      else if (e.key === 'Home') i = 0;
      else if (e.key === 'End') i = ids.length - 1;
      else return;
      e.preventDefault();
      setTab(ids[i], { focus: true });
    });

    $('#sidebar-filter').addEventListener('input', e => { state.sidebarFilter = e.target.value; renderSidebar(); });
    $('#sidebar-toggle').addEventListener('click', () => { state.sidebarOpen = !state.sidebarOpen; renderSidebar(); });

    // Cierra los menús desplegables al pulsar fuera o con Escape.
    document.addEventListener('click', e => {
      document.querySelectorAll('details.menu[open]').forEach(d => { if (!d.contains(e.target)) d.open = false; });
      if (e.target.closest('.menu-pop button')) e.target.closest('details.menu').open = false;
    });

    // Los botones de abrir ficheros son <label> (para abrir el selector sin JS): Intro y Espacio los activan.
    document.addEventListener('keydown', e => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target.matches && e.target.matches('label[role=button]')) {
        e.preventDefault();
        $('#file-input').click();
      }
    });

    // Menús desplegables: flechas, Inicio y Fin recorren las opciones (patrón de menú de ARIA).
    document.addEventListener('keydown', e => {
      const menu = e.target.closest && e.target.closest('details.menu');
      if (!menu || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
      const items = [...menu.querySelectorAll('[role=menuitem]')];
      if (!items.length) return;
      e.preventDefault();
      menu.open = true;
      let i = items.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') i = (i + 1) % items.length;
      else if (e.key === 'ArrowUp') i = i < 0 ? items.length - 1 : (i - 1 + items.length) % items.length;
      else i = e.key === 'Home' ? 0 : items.length - 1;
      items[i].focus();
    });

    // Atajos de teclado globales.
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        const inMenu = document.activeElement && document.activeElement.closest('details.menu[open]');
        document.querySelectorAll('details.menu[open]').forEach(d => { d.open = false; });
        if (inMenu) inMenu.querySelector('summary').focus();
      }
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.target.closest('input, textarea, select, [contenteditable]') || document.querySelector('dialog[open]')) return;
      const k = e.key;
      if (k === '?') { e.preventDefault(); $('#shortcuts').showModal(); }
      else if (k === 'o' || k === 'O') { e.preventDefault(); $('#file-input').click(); }
      else if (k === '/') { e.preventDefault(); const f = $('#sidebar-filter'); if (!f.closest('[hidden]')) f.focus(); }
      else if (k === 'j' || k === 'k') { e.preventDefault(); moveEntry(k === 'j' ? 1 : -1); }
      else if (/^[1-8]$/.test(k) && current()) { e.preventDefault(); setTab(TAB_GROUPS[+k - 1].id); }
      else if ((k === 'e' || k === 'E') && current()) { e.preventDefault(); const m = $('details.menu'); if (m) { m.open = true; m.querySelector('.menu-pop button').focus(); } }
    });
    $('#shortcuts-btn').addEventListener('click', () => $('#shortcuts').showModal());

    $('#ai-chip').addEventListener('click', openAIHelp);
    $('#ai-download').addEventListener('click', downloadModel);
    $('#theme-toggle').addEventListener('click', toggleTheme);
  }

  function selectEntry(id) {
    state.currentId = id;
    state.sidebarOpen = false;
    render();
  }

  function moveEntry(delta) {
    const list = visibleEntries();
    if (!list.length) return;
    const i = list.findIndex(e => e.id === state.currentId);
    const next = list[Math.max(0, Math.min(list.length - 1, (i < 0 ? 0 : i + delta)))];
    if (next && next.id !== state.currentId) {
      selectEntry(next.id);
      const li = $(`#file-list li[data-id="${next.id}"]`);
      if (li) li.scrollIntoView({ block: 'nearest' });
    }
  }

  async function loadSamples() {
    const files = ['samples/phishing-banco.eml', 'samples/newsletter-legitima.eml', 'samples/factura-adjunto.eml', 'samples/multa-qr.eml'];
    let ok = 0;
    for (const [i, f] of files.entries()) {
      setLoading(i, files.length, f.split('/').pop());
      try {
        const r = await fetch(f);
        if (!r.ok) throw new Error(r.status);
        if (await addEmail(new Uint8Array(await r.arrayBuffer()), f.split('/').pop(), undefined, !ok)) ok++;
      } catch (_) { /* se informa abajo */ }
    }
    setLoading(null);
    if (!ok) toast('No se pudieron cargar: abre la página desde un servidor local (ver README) o arrastra los ficheros de /samples.');
  }

  // ---------- tema ----------

  function applyTheme(t) {
    if (t) document.documentElement.setAttribute('data-theme', t);
    else document.documentElement.removeAttribute('data-theme');
  }
  function toggleTheme() {
    const cur = document.documentElement.getAttribute('data-theme') ||
      (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    try { localStorage.setItem('eml-theme', next); } catch (_) { /* sin almacenamiento */ }
  }

  // ---------- estado de la IA ----------

  function setChip(label, cls) {
    const chip = $('#ai-chip');
    chip.className = 'chip' + (cls ? ' ' + cls : '');
    chip.querySelector('.label').textContent = label;
    // En móvil sólo se ve «IA» y el punto de color: el estado completo va en el nombre accesible y en el title.
    chip.setAttribute('aria-label', label);
    chip.title = label + ' · pulsa para ver detalles';
  }

  const STATUS_TEXT = {
    'no-api': 'API no presente',
    unavailable: 'No disponible en este equipo',
    downloadable: 'Disponible, requiere descarga',
    downloading: 'Descargando…',
    available: 'Listo',
    api: 'API presente',
  };

  async function checkAI() {
    let st;
    try { st = await AI.status(); } catch (_) { st = { prompt: 'no-api', summarizer: 'no-api', detector: 'no-api', translator: 'no-api' }; }
    state.ai.status = st;
    if (st.prompt === 'available') setChip(`${MODEL} listo`, 'ready');
    else if (st.prompt === 'downloadable') setChip(`${MODEL}: descargar`, 'pending');
    else if (st.prompt === 'downloading') setChip(`Descargando ${MODEL}…`, 'pending');
    else setChip('IA local no disponible', '');
    renderAIHelpStatus();
    const entry = current();
    if (entry) refreshAICard(entry);
    return st;
  }

  function renderAIHelpStatus() {
    const st = state.ai.status;
    const box = $('#ai-help-status');
    if (!st) { box.textContent = 'Comprobando…'; return; }
    box.innerHTML = [
      ['Prompt API (veredicto y chat)', st.prompt],
      ['Summarizer API (resumen)', st.summarizer],
      ['Language Detector API', st.detector],
      ['Translator API', st.translator],
    ].map(([k, v]) => `<span>${k}</span><strong>${esc(STATUS_TEXT[v] || v)}</strong>`).join('') +
      (state.ai.progress != null ? `<span>Descarga</span><strong id="ai-help-progress">${Math.round(state.ai.progress * 100)}%</strong>` : '') +
      (!window.isSecureContext ? '<span>Contexto</span><strong>No seguro: abre la página desde http://localhost</strong>' : '');
    $('#ai-download').hidden = !(st.prompt === 'downloadable' || st.prompt === 'downloading');
  }

  function openAIHelp() {
    renderAIHelpStatus();
    $('#ai-help').showModal();
    checkAI();
  }

  async function downloadModel() {
    const btn = $('#ai-download');
    btn.disabled = true;
    btn.textContent = 'Descargando…';
    try {
      await AI.download({ onProgress });
      toast(`${MODEL} está listo`);
    } catch (e) {
      toast(aiError(e));
    }
    btn.disabled = false;
    btn.textContent = 'Descargar modelo';
    state.ai.progress = null;
    checkAI();
  }

  // ---------- inicio ----------

  try { applyTheme(localStorage.getItem('eml-theme')); } catch (_) { /* sin almacenamiento */ }
  bindEvents();
  render();
  checkAI();
})();

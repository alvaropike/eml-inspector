/*
 * Informe que se devuelve por correo: versión HTML (con estilos en línea, que es lo único que
 * respetan todos los clientes de correo) y versión de texto.
 * Todo lo que viene del correo analizado se escapa y se «desactiva» (hxxp://, dominio[.]com)
 * para que el informe no sirva para colar enlaces pulsables.
 */
import { Analysis } from './core.js';

const LEVEL = {
  alto: { label: 'Riesgo alto', color: '#b42318', bg: '#fef3f2' },
  medio: { label: 'Riesgo medio', color: '#b54708', bg: '#fffaeb' },
  bajo: { label: 'Riesgo bajo', color: '#067647', bg: '#ecfdf3' },
};
const SEV = {
  high: { label: 'Grave', color: '#b42318' },
  medium: { label: 'Medio', color: '#b54708' },
  low: { label: 'Leve', color: '#475467' },
  ok: { label: 'A favor', color: '#067647' },
};
const RESULT = { pass: 'correcto', fail: 'falla', softfail: 'softfail', none: 'sin datos', neutral: 'neutral', permerror: 'error permanente', temperror: 'error temporal' };

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Desactiva URLs, dominios e IPs para que ningún cliente de correo los convierta en enlaces.
export function defang(s) {
  return String(s == null ? '' : s)
    .replace(/\b(h)(ttps?)(:\/\/)/gi, (_, h, t, sep) => `${h}${t.replace(/t/gi, 'x')}[:]//`)
    .replace(/\b((?:[a-z0-9_-]+\.)+[a-z]{2,63})\b/gi, m => m.replace(/\./g, '[.]'))
    .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\b/g, '$1[.]$2');
}
const safe = s => esc(defang(s));
const cut = (s, n) => { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
const addr = a => (a ? (a.name && a.name !== a.address ? `${a.name} <${a.address}>` : a.address) : '') || '—';

function fmtDate(d) {
  if (!d || isNaN(d)) return '—';
  return d.toLocaleString('es-ES', { timeZone: 'Europe/Madrid', dateStyle: 'medium', timeStyle: 'short' });
}

function authLine(a) {
  const s = a.summary;
  if (s.outlookExport && s.msAuth) return s.msAuth === '1' ? 'validada por Microsoft (exportado desde Outlook)' : 'Microsoft no la superó (exportado desde Outlook)';
  if (s.noAuthHeaders) return 'sin datos del proveedor que lo recibió';
  return `SPF ${RESULT[s.spf] || s.spf} · DKIM ${RESULT[s.dkim] || s.dkim} · DMARC ${RESULT[s.dmarc] || s.dmarc}`;
}

// Qué comprobaciones en línea se hicieron, para no dar a entender más de lo que se consultó.
function onlineNote(entry, stats) {
  const o = entry.online;
  if (!o) return 'No se hicieron comprobaciones en línea.';
  if (o.error) return `Las comprobaciones en línea fallaron (${o.error}).`;
  const parts = [`${plural(Object.keys(o.domains).length, 'dominio', 'dominios')} y ${plural(Object.keys(o.ips).length, 'IP', 'IPs')} consultados en DNS, WHOIS y listas negras`];
  const sb = o.safeBrowsing;
  if (sb && sb.matches) parts.push(`Google Safe Browsing: ${plural(sb.urls || 0, 'URL', 'URLs')}`);
  let note = parts.join('; ') + '.';
  if (stats && stats.skipped) note += ` Algunas consultas no se hicieron porque el buzón tiene un límite por correo (${plural(stats.skipped, 'omitida', 'omitidas')}); en la web se hacen todas.`;
  return note;
}

function suspiciousLinks(a) {
  const bad = f => f.sev === 'high' || f.sev === 'medium';
  return a.links.filter(l => l.flags.some(bad)).map(l => ({
    text: (l.text || '').trim(),
    href: l.href,
    flags: [...new Set(l.flags.filter(bad).map(f => f.msg))],
  }));
}

function suspiciousAttachments(a) {
  const bad = f => f.sev === 'high' || f.sev === 'medium';
  return a.attachments.filter(x => x.flags.some(bad)).map(x => ({ name: x.name, sha256: x.sha256, flags: x.flags.filter(bad).map(f => f.msg) }));
}

// ---------- un correo analizado ----------

function entryModel(entry) {
  const a = entry.analysis;
  const c = Analysis.conclusion(entry);
  const pts = f => Analysis.pointsOf(f, entry.trustVoided);
  const bad = entry.findings.filter(f => f.sev === 'high' || f.sev === 'medium');
  const low = entry.findings.filter(f => f.sev === 'low');
  const favor = entry.findings.filter(f => f.sev === 'ok' && pts(f) < 0);
  return {
    a, c, pts,
    subject: a.subject || '(sin asunto)',
    reasons: bad.slice(0, 10), moreReasons: Math.max(0, bad.length - 10),
    low: low.slice(0, 5), moreLow: Math.max(0, low.length - 5),
    favor,
    links: suspiciousLinks(a),
    attachments: suspiciousAttachments(a),
    facts: [
      ['De', addr(a.from)],
      a.relay ? ['Remitente real', `${a.relay.original.address} (vía ${a.relay.service})`] : null,
      a.replyTo.length ? ['Responder a', a.replyTo.map(addr).join(', ')] : null,
      ['Return-Path', a.returnPath || '—'],
      ['Fecha', fmtDate(a.date)],
      ['Autenticación', authLine(a)],
      ['IP de origen', a.iocs.originIP || '—'],
      ['Enlaces', a.links.length ? `${a.links.length}` : 'ninguno'],
      ['Adjuntos', a.attachments.length ? a.attachments.map(x => x.name).join(', ') : 'ninguno'],
    ].filter(Boolean),
  };
}

function entryText(entry, stats) {
  const m = entryModel(entry);
  const L = LEVEL[entry.level];
  const out = [];
  out.push(`ANÁLISIS DE «${defang(cut(m.subject, 120))}»`, '');
  out.push(`${L.label.toUpperCase()} · ${entry.score}/100`, m.c.title, defang(m.c.text), '');
  out.push('Qué hacer:', ...m.c.actions.map(x => `  - ${x}`), '');
  if (m.reasons.length) {
    out.push('Motivos:');
    m.reasons.forEach(f => out.push(`  [${SEV[f.sev].label}] ${defang(f.title)}${f.detail ? '\n      ' + defang(cut(f.detail, 300)) : ''}`));
    if (m.moreReasons) out.push(`  … y ${plural(m.moreReasons, 'motivo más', 'motivos más')}`);
    out.push('');
  }
  if (m.low.length) {
    out.push('Señales leves:', ...m.low.map(f => `  - ${defang(f.title)}`));
    if (m.moreLow) out.push(`  … y ${m.moreLow} más`);
    out.push('');
  }
  if (m.favor.length) out.push('A favor:', ...m.favor.map(f => `  ${m.pts(f)} ${defang(f.title)}`), '');
  if (m.links.length) {
    out.push('Enlaces sospechosos (desactivados, no los abras):');
    m.links.slice(0, 5).forEach(l => out.push(`  - ${defang(cut(l.href, 160))}${l.text ? `\n      texto visible: «${defang(cut(l.text, 80))}»` : ''}\n      ${defang(l.flags.join(' · '))}`));
    out.push('');
  }
  if (m.attachments.length) {
    out.push('Adjuntos sospechosos:');
    m.attachments.forEach(x => out.push(`  - ${defang(x.name)}: ${defang(x.flags.join(' · '))}${x.sha256 ? `\n      SHA-256 ${x.sha256}` : ''}`));
    out.push('');
  }
  out.push('Datos del correo:', ...m.facts.map(([k, v]) => `  ${k}: ${defang(cut(v, 200))}`), '');
  out.push(onlineNote(entry, stats));
  return out.join('\n');
}

function entryHtml(entry, stats) {
  const m = entryModel(entry);
  const L = LEVEL[entry.level];
  const row = (k, v) => `<tr><td style="padding:3px 12px 3px 0;color:#667085;vertical-align:top;white-space:nowrap">${esc(k)}</td><td style="padding:3px 0;word-break:break-word">${safe(cut(v, 200))}</td></tr>`;
  const finding = f => `<li style="margin:0 0 8px"><span style="display:inline-block;min-width:54px;font-size:12px;font-weight:600;color:${SEV[f.sev].color}">${SEV[f.sev].label}</span> <strong>${safe(f.title)}</strong>${f.detail ? `<br><span style="color:#475467;font-size:13px">${safe(cut(f.detail, 300))}</span>` : ''}</li>`;
  const h3 = t => `<h3 style="font-size:15px;margin:22px 0 8px;color:#101828">${t}</h3>`;
  return `
<div style="border:1px solid #eaecf0;border-radius:10px;overflow:hidden;margin:0 0 24px">
  <div style="background:${L.bg};border-bottom:1px solid #eaecf0;padding:16px 20px">
    <div style="font-size:13px;color:#475467;margin-bottom:4px">Análisis de «${safe(cut(m.subject, 120))}»</div>
    <div style="font-size:22px;font-weight:700;color:${L.color}">${L.label} · ${entry.score}/100</div>
    <div style="font-size:17px;font-weight:600;color:#101828;margin-top:6px">${esc(m.c.title)}</div>
    <p style="margin:6px 0 0;color:#344054">${safe(m.c.text)}</p>
  </div>
  <div style="padding:4px 20px 18px">
    ${h3('Qué hacer')}
    <ul style="margin:0;padding-left:20px">${m.c.actions.map(x => `<li style="margin:0 0 4px">${esc(x)}</li>`).join('')}</ul>
    ${m.reasons.length ? h3('Motivos') + `<ul style="margin:0;padding:0;list-style:none">${m.reasons.map(finding).join('')}</ul>${m.moreReasons ? `<p style="color:#667085;margin:0">… y ${plural(m.moreReasons, 'motivo más', 'motivos más')}</p>` : ''}` : ''}
    ${m.low.length ? h3('Señales leves') + `<ul style="margin:0;padding-left:20px;color:#475467">${m.low.map(f => `<li>${safe(f.title)}</li>`).join('')}${m.moreLow ? `<li>… y ${m.moreLow} más</li>` : ''}</ul>` : ''}
    ${m.favor.length ? h3('A favor') + `<ul style="margin:0;padding-left:20px;color:#067647">${m.favor.map(f => `<li>${safe(f.title)} (${m.pts(f)})</li>`).join('')}</ul>` : ''}
    ${m.links.length ? h3('Enlaces sospechosos') + `<p style="margin:0 0 8px;color:#667085;font-size:13px">Desactivados a propósito: no los copies en el navegador.</p><ul style="margin:0;padding-left:20px">${m.links.slice(0, 5).map(l =>
      `<li style="margin:0 0 8px"><code style="word-break:break-all">${safe(cut(l.href, 160))}</code>${l.text ? `<br><span style="color:#475467;font-size:13px">Texto visible: «${safe(cut(l.text, 80))}»</span>` : ''}<br><span style="color:#b42318;font-size:13px">${safe(l.flags.join(' · '))}</span></li>`).join('')}</ul>` : ''}
    ${m.attachments.length ? h3('Adjuntos sospechosos') + `<ul style="margin:0;padding-left:20px">${m.attachments.map(x =>
      `<li style="margin:0 0 8px"><strong>${safe(x.name)}</strong><br><span style="color:#b42318;font-size:13px">${safe(x.flags.join(' · '))}</span>${x.sha256 ? `<br><code style="font-size:12px;color:#667085;word-break:break-all">SHA-256 ${esc(x.sha256)}</code>` : ''}</li>`).join('')}</ul>` : ''}
    ${h3('Datos del correo')}
    <table style="border-collapse:collapse;font-size:14px">${m.facts.map(([k, v]) => row(k, v)).join('')}</table>
    <p style="margin:14px 0 0;color:#667085;font-size:13px">${esc(onlineNote(entry, stats))}</p>
  </div>
</div>`;
}

// ---------- correo de respuesta ----------

function wrapHtml(inner, site) {
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#f9fafb">
<div style="max-width:640px;margin:0 auto;padding:20px 16px;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.5;color:#101828">
<div style="font-size:14px;font-weight:700;color:#475467;margin-bottom:14px">EML Inspector</div>
${inner}
<p style="color:#667085;font-size:12px;margin:20px 0 0">Análisis automático: orienta, pero no sustituye a tu criterio ni al de tu equipo de seguridad. El correo se ha procesado en memoria y no se guarda.
Para ver el análisis completo (contenido, ruta de entrega, cabeceras, IOCs), abre el .eml en <a href="${esc(site)}" style="color:#475467">${esc(site.replace(/^https?:\/\//, ''))}</a>.</p>
</div></body></html>`;
}

function textFooter(site) {
  return `\n--\nAnálisis automático de EML Inspector: orienta, pero no sustituye a tu criterio ni al de tu equipo de seguridad. El correo se ha procesado en memoria y no se guarda.\nPara ver el análisis completo, abre el .eml en ${site}`;
}

// items: [{ name, entry } | { name, error }]; extra: adjuntos que no se analizaron por el límite.
export function buildReport(items, { site, stats, extra = 0 } = {}) {
  const ok = items.filter(x => x.entry);
  const worst = ok.slice().sort((x, y) => y.entry.score - x.entry.score)[0];
  const subject = ok.length === 1
    ? `${LEVEL[ok[0].entry.level].label} (${ok[0].entry.score}/100): ${defang(cut(ok[0].entry.analysis.subject || '(sin asunto)', 80))}`
    : ok.length ? `${plural(ok.length, 'correo analizado', 'correos analizados')} · el peor, ${LEVEL[worst.entry.level].label.toLowerCase()} (${worst.entry.score}/100)`
    : 'No se pudo analizar el correo adjunto';
  const errors = items.filter(x => x.error);
  const errText = errors.map(x => `No se pudo analizar «${defang(x.name)}»: ${x.error}.`);
  const extraText = extra ? [`Sólo se analizan ${items.length} correos por mensaje; ${plural(extra, 'adjunto más se ha', 'adjuntos más se han')} quedado sin analizar.`] : [];
  const text = [...ok.map(x => entryText(x.entry, stats)), ...errText, ...extraText].join('\n\n' + '─'.repeat(40) + '\n\n') + textFooter(site);
  const html = wrapHtml(
    ok.map(x => entryHtml(x.entry, stats)).join('') +
    [...errText, ...extraText].map(t => `<p style="color:#b42318">${esc(t)}</p>`).join(''), site);
  return { subject, text, html };
}

// Respuesta cuando el mensaje no trae ningún correo adjunto.
export function helpReport({ site, address }) {
  const steps = [
    ['Gmail', 'abre el correo › ⋮ › «Descargar mensaje» y adjunta el .eml, o ⋮ › «Reenviar como archivo adjunto».'],
    ['Outlook en la web', 'abre el correo › ··· › «Descargar» y adjunta el .eml, o ··· › «Reenviar como datos adjuntos».'],
    ['Outlook de escritorio', 'arrastra el correo a un mensaje nuevo (se adjunta como .msg).'],
  ];
  const intro = `No he encontrado ningún correo adjunto en tu mensaje. Para analizar un correo sospechoso, envíalo a ${address} como archivo adjunto (.eml o .msg). Si lo reenvías en el cuerpo del mensaje se pierden las cabeceras que hacen falta para saber quién lo envió de verdad.`;
  return {
    subject: 'Adjunta el correo que quieres analizar',
    text: [intro, '', 'Cómo adjuntarlo:', ...steps.map(([k, v]) => `  - ${k}: ${v}`)].join('\n') + textFooter(site),
    html: wrapHtml(`<p>${esc(intro)}</p><h3 style="font-size:15px;margin:18px 0 8px">Cómo adjuntarlo</h3><ul style="padding-left:20px">${steps.map(([k, v]) => `<li style="margin:0 0 6px"><strong>${esc(k)}</strong>: ${esc(v)}</li>`).join('')}</ul>`, site),
  };
}

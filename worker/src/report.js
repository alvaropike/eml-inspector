/*
 * Informe que se devuelve por correo: versión HTML y versión de texto.
 * El HTML usa tablas y estilos en línea, que es lo único que respetan todos los clientes de
 * correo (Outlook de escritorio incluido); la hoja <style> sólo añade ajustes para móvil.
 * Todo lo que viene del correo analizado se escapa y se «desactiva» (hxxp://, dominio[.]com)
 * para que el informe no sirva para colar enlaces pulsables.
 */
import { Analysis } from './core.js';

// Los mismos colores que la web (css/styles.css, tema claro).
const C = {
  bg: '#f5f6f8', surface: '#ffffff', surface2: '#f0f2f5', border: '#dfe3e8', line: '#eceef1',
  text: '#1a1d23', muted: '#5f6773', accent: '#2f5bd3',
  high: '#c62828', highSoft: '#fdecec', medium: '#b45309', mediumSoft: '#fdf3e2',
  low: '#7c6f12', lowSoft: '#f8f5dc', ok: '#1e7a45', okSoft: '#e4f4ea', info: '#4a5568', infoSoft: '#eceff3',
};
const SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif";
const MONO = "ui-monospace,'Cascadia Code',Consolas,'Liberation Mono',Menlo,monospace";

const LEVEL = {
  alto: { label: 'Riesgo alto', color: C.high, soft: C.highSoft },
  medio: { label: 'Riesgo medio', color: C.medium, soft: C.mediumSoft },
  bajo: { label: 'Riesgo bajo', color: C.ok, soft: C.okSoft },
};
const SEV = {
  high: { label: 'Grave', color: C.high, soft: C.highSoft },
  medium: { label: 'Medio', color: C.medium, soft: C.mediumSoft },
  low: { label: 'Leve', color: C.low, soft: C.lowSoft },
  ok: { label: 'A favor', color: C.ok, soft: C.okSoft },
};
const TONE = {
  high: { color: C.high, soft: C.highSoft }, medium: { color: C.medium, soft: C.mediumSoft }, low: { color: C.low, soft: C.lowSoft },
  ok: { color: C.ok, soft: C.okSoft }, '': { color: C.info, soft: C.infoSoft },
};
const RESULT = { pass: 'correcto', fail: 'falla', softfail: 'softfail', none: 'sin datos', neutral: 'neutral', permerror: 'error permanente', temperror: 'error temporal' };
const RESULT_TONE = { pass: 'ok', fail: 'high', softfail: 'medium', none: '', neutral: 'low', permerror: 'medium', temperror: 'low' };

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Desactiva URLs, dominios e IPs para que ningún cliente de correo los convierta en enlaces.
export function defang(s) {
  return String(s == null ? '' : s)
    .replace(/\b(h)(ttps?)(:\/\/)/gi, (_, h, t) => `${h}${t.replace(/t/gi, 'x')}[:]//`)
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

const isBad = f => f.sev === 'high' || f.sev === 'medium';

function suspiciousLinks(a) {
  return a.links.filter(l => l.flags.some(isBad)).map(l => ({
    text: (l.text || '').trim(),
    href: l.href,
    flags: [...new Set(l.flags.filter(isBad).map(f => f.msg))],
  }));
}

function suspiciousAttachments(a) {
  return a.attachments.filter(x => x.flags.some(isBad)).map(x => ({ name: x.name, sha256: x.sha256, flags: x.flags.filter(isBad).map(f => f.msg) }));
}

// Resumen por áreas, como las fichas del Resumen de la web.
function statCards(entry) {
  const a = entry.analysis, s = a.summary, o = entry.online;
  const fails = ['spf', 'dkim', 'dmarc'].filter(k => s[k] === 'fail' || s[k] === 'softfail').length;
  const susLinks = a.links.filter(l => l.flags.some(isBad)).length;
  const badAtt = a.attachments.filter(x => x.flags.some(isBad)).length;
  const onlineBad = o && !o.error ? (o.findings || []).filter(isBad) : [];
  return [
    s.outlookExport && s.msAuth
      ? { label: 'Autenticación', value: s.msAuth === '1' ? 'Validada por Microsoft' : 'Microsoft: no superada', tone: s.msAuth === '1' ? 'ok' : 'high' }
      : s.relay
      ? { label: 'Autenticación', value: s.senderAuth ? 'Correcta · vía Apple' : 'Remitente sin autenticar', tone: s.senderAuth ? 'ok' : 'medium' }
      : { label: 'Autenticación', value: s.noAuthHeaders ? 'Sin datos' : fails ? `${fails} de 3 fallan` : s.dmarc === 'pass' ? 'Correcta' : 'Incompleta',
        tone: s.noAuthHeaders ? '' : fails ? 'high' : s.dmarc === 'pass' ? 'ok' : 'low' },
    { label: 'Enlaces', value: a.links.length ? (susLinks ? `${susLinks} de ${a.links.length} sospechosos` : `${a.links.length} sin alertas`) : 'Ninguno',
      tone: susLinks ? 'high' : a.links.length ? 'ok' : '' },
    { label: 'Adjuntos', value: a.attachments.length ? (badAtt ? `${badAtt} de ${a.attachments.length} sospechosos` : `${a.attachments.length} sin alertas`) : 'Ninguno',
      tone: badAtt ? 'high' : a.attachments.length ? 'ok' : '' },
    { label: 'DNS y WHOIS', value: !o ? 'Sin consultar' : o.error ? 'No disponible' : onlineBad.length ? plural(onlineBad.length, 'alerta', 'alertas') : 'Sin alertas',
      tone: !o || o.error ? '' : onlineBad.some(f => f.sev === 'high') ? 'high' : onlineBad.length ? 'medium' : 'ok' },
  ];
}

// ---------- un correo analizado ----------

function entryModel(entry) {
  const a = entry.analysis;
  const c = Analysis.conclusion(entry);
  const pts = f => Analysis.pointsOf(f, entry.trustVoided);
  const bad = entry.findings.filter(isBad);
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

// ---------- piezas HTML ----------

const font = (size, color, weight = 400, extra = '') => `font-family:${SANS};font-size:${size}px;line-height:1.5;color:${color};font-weight:${weight};${extra}`;
const pill = (text, color, soft) => `<span style="display:inline-block;padding:2px 8px;border-radius:999px;background:${soft};${font(11, color, 700, 'line-height:16px;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap')}">${esc(text)}</span>`;
const chip = (text, color, soft) => `<span style="display:inline-block;margin:4px 4px 0 0;padding:2px 8px;border-radius:6px;background:${soft};${font(12, color, 600, 'line-height:18px')}">${text}</span>`;
const section = (title, body, count) => `
<tr><td class="px" style="padding:22px 28px 0">
  <div style="${font(12, C.muted, 700, 'letter-spacing:.06em;text-transform:uppercase;margin:0 0 10px')}">${esc(title)}${count ? ` <span style="color:${C.text}">· ${count}</span>` : ''}</div>
  ${body}
</td></tr>`;

function verdictBlock(entry, m) {
  const L = LEVEL[entry.level];
  return `
<tr><td style="height:4px;line-height:4px;font-size:0;background:${L.color}">&nbsp;</td></tr>
<tr><td class="px" style="padding:20px 28px 0">
  <div style="${font(12, C.muted, 700, 'letter-spacing:.06em;text-transform:uppercase')}">Correo analizado</div>
  <div style="${font(16, C.text, 700, 'margin-top:2px;word-break:break-word')}">${safe(cut(m.subject, 140))}</div>
  <div style="${font(13, C.muted, 400, 'word-break:break-word')}">${safe(cut(addr(m.a.from), 120))}${m.a.date ? ' · ' + esc(fmtDate(m.a.date)) : ''}</div>
</td></tr>
<tr><td class="px" style="padding:16px 28px 0">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${L.soft};border-radius:12px">
    <tr>
      <td class="gauge-cell" width="96" valign="middle" align="center" style="padding:18px 0 18px 18px">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
          <td width="72" height="72" align="center" valign="middle" style="width:72px;height:72px;border-radius:50%;border:5px solid ${L.color};background:${C.surface};${font(26, L.color, 800, 'line-height:26px')}">${entry.score}<div style="${font(10, C.muted, 600, 'line-height:12px')}">de 100</div></td>
        </tr></table>
      </td>
      <td valign="middle" style="padding:18px 20px 18px 16px">
        ${pill(L.label, C.surface, L.color)}
        <div style="${font(20, L.color, 700, 'line-height:1.3;margin-top:8px')}">${esc(m.c.title)}</div>
        <div style="${font(14, C.text, 400, 'margin-top:4px')}">${safe(m.c.text)}</div>
      </td>
    </tr>
  </table>
</td></tr>`;
}

function actionsBlock(entry, m) {
  const L = LEVEL[entry.level];
  const rows = m.c.actions.map((x, i) => `
    <tr>
      <td width="30" valign="top" style="padding:4px 0">
        <div style="width:22px;height:22px;border-radius:50%;background:${L.color};text-align:center;${font(12, C.surface, 700, 'line-height:22px')}">${i + 1}</div>
      </td>
      <td valign="top" style="padding:4px 0;${font(14, C.text, 500, 'line-height:22px')}">${esc(x)}</td>
    </tr>`).join('');
  return section('Qué hacer', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${rows}</table>`);
}

function statsBlock(entry) {
  const cards = statCards(entry);
  const card = c => {
    const t = TONE[c.tone || ''];
    return `<td class="stat" width="50%" valign="top" style="padding:0 4px 8px">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid ${C.border};border-radius:10px;background:${C.surface}">
        <tr><td style="padding:10px 12px;border-left:4px solid ${t.color};border-radius:10px">
          <div style="${font(11, C.muted, 700, 'letter-spacing:.05em;text-transform:uppercase')}">${esc(c.label)}</div>
          <div style="${font(14, t.color, 700, 'margin-top:2px')}">${esc(c.value)}</div>
        </td></tr>
      </table>
    </td>`;
  };
  return `
<tr><td class="px" style="padding:18px 24px 0">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr>${card(cards[0])}${card(cards[1])}</tr>
    <tr>${card(cards[2])}${card(cards[3])}</tr>
  </table>
</td></tr>`;
}

function reasonsBlock(m) {
  if (!m.reasons.length) return '';
  const item = f => {
    const s = SEV[f.sev];
    return `<tr><td style="padding:0 0 8px">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${C.surface2};border-radius:8px">
        <tr><td style="padding:10px 14px;border-left:4px solid ${s.color};border-radius:8px">
          ${pill(s.label, s.color, s.soft)}
          <div style="${font(14, C.text, 700, 'margin-top:4px;word-break:break-word')}">${safe(f.title)}</div>
          ${f.detail ? `<div style="${font(13, C.muted, 400, 'word-break:break-word')}">${safe(cut(f.detail, 280))}</div>` : ''}
        </td></tr>
      </table>
    </td></tr>`;
  };
  // Los 5 más graves en detalle; el resto, sólo el título, para que el informe no sea interminable.
  const shown = m.reasons.slice(0, 5), rest = m.reasons.slice(5);
  const dot = f => `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${SEV[f.sev].color};margin-right:5px"></span>`;
  const more = rest.length ? `<div style="${font(13, C.muted, 400, 'margin-top:2px')}"><strong style="color:${C.text}">También:</strong> ${rest.map(f => `<span style="white-space:nowrap">${dot(f)}</span>${safe(f.title)}`).join(' · ')}${m.moreReasons ? ` · y ${plural(m.moreReasons, 'motivo más', 'motivos más')} en el análisis completo` : ''}</div>` : '';
  return section('Por qué', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${shown.map(item).join('')}</table>${more}`,
    m.reasons.length + m.moreReasons);
}

function minorBlock(m) {
  if (!m.low.length && !m.favor.length) return '';
  const low = m.low.length ? `<div style="${font(13, C.muted)}"><strong style="color:${C.text}">Señales leves:</strong> ${m.low.map(f => safe(f.title)).join(' · ')}${m.moreLow ? ` · y ${m.moreLow} más` : ''}</div>` : '';
  const favor = m.favor.length ? `<div style="${font(13, C.muted, 400, low ? 'margin-top:6px' : '')}"><strong style="color:${C.ok}">A favor:</strong> ${m.favor.map(f => `${safe(f.title)} <span style="color:${C.ok};font-weight:700;white-space:nowrap">(${m.pts(f)})</span>`).join(' · ')}</div>` : '';
  return `<tr><td class="px" style="padding:10px 28px 0">${low}${favor}</td></tr>`;
}

function linksBlock(m) {
  if (!m.links.length) return '';
  const item = l => `<tr><td style="padding:0 0 12px">
    <div style="background:${C.surface2};border:1px solid ${C.border};border-radius:8px;padding:8px 10px;font-family:${MONO};font-size:12px;line-height:1.5;color:${C.text};word-break:break-all">${safe(cut(l.href, 200))}</div>
    ${l.text ? `<div style="${font(12, C.muted, 400, 'margin-top:4px;word-break:break-word')}">Texto visible: «${safe(cut(l.text, 90))}»</div>` : ''}
    <div>${l.flags.map(x => chip(safe(x), C.high, C.highSoft)).join('')}</div>
  </td></tr>`;
  return section('Enlaces sospechosos',
    `<div style="${font(12, C.muted, 400, 'margin:-4px 0 10px')}">Desactivados a propósito: no los copies en el navegador.</div>
     <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${m.links.slice(0, 5).map(item).join('')}</table>`,
    m.links.length);
}

function attachmentsBlock(m) {
  if (!m.attachments.length) return '';
  const item = x => `<tr><td style="padding:0 0 12px">
    <div style="${font(14, C.text, 700, 'word-break:break-all')}">${safe(x.name)}</div>
    <div>${x.flags.map(f => chip(safe(f), C.high, C.highSoft)).join('')}</div>
    ${x.sha256 ? `<div style="margin-top:6px;font-family:${MONO};font-size:11px;line-height:1.5;color:${C.muted};word-break:break-all">SHA-256 ${esc(x.sha256)}</div>` : ''}
  </td></tr>`;
  return section('Adjuntos sospechosos', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${m.attachments.map(item).join('')}</table>`, m.attachments.length);
}

function authBadges(a) {
  const s = a.summary;
  if ((s.outlookExport && s.msAuth) || s.noAuthHeaders) return safe(authLine(a));
  return ['spf', 'dkim', 'dmarc'].map(k => {
    const t = TONE[RESULT_TONE[s[k]] || ''];
    return `<span style="display:inline-block;margin:0 4px 4px 0;padding:1px 8px;border-radius:6px;background:${t.soft};${font(12, t.color, 700, 'line-height:18px;white-space:nowrap')}">${k.toUpperCase()} ${esc(RESULT[s[k]] || s[k])}</span>`;
  }).join('');
}

function factsBlock(entry, m, stats) {
  // El número de enlaces ya está en las fichas del resumen.
  const rows = m.facts.filter(([k]) => k !== 'Enlaces').map(([k, v], i) => `<tr>
    <td class="fact-k" width="120" valign="top" style="padding:7px 12px 7px 0;${i ? `border-top:1px solid ${C.line};` : ''}${font(13, C.muted)}">${esc(k)}</td>
    <td valign="top" style="padding:7px 0;${i ? `border-top:1px solid ${C.line};` : ''}${font(13, C.text, 400, 'word-break:break-word')}">${k === 'Autenticación' ? authBadges(m.a) : safe(cut(v, 200))}</td>
  </tr>`).join('');
  return section('Datos del correo', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${rows}</table>
    <div style="${font(12, C.muted, 400, 'margin-top:10px')}">${esc(onlineNote(entry, stats))}</div>`);
}

function entryHtml(entry, stats) {
  const m = entryModel(entry);
  return `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${C.surface};border:1px solid ${C.border};border-radius:14px;overflow:hidden;margin:0 0 20px">
  ${verdictBlock(entry, m)}
  ${statsBlock(entry)}
  ${actionsBlock(entry, m)}
  ${reasonsBlock(m)}
  ${minorBlock(m)}
  ${linksBlock(m)}
  ${attachmentsBlock(m)}
  ${factsBlock(entry, m, stats)}
  <tr><td style="height:24px;line-height:24px;font-size:0">&nbsp;</td></tr>
</table>`;
}

// ---------- correo de respuesta ----------

function wrapHtml(inner, { site, preheader = '', cta = true }) {
  const host = site.replace(/^https?:\/\//, '');
  const button = cta ? `
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto">
    <tr><td align="center" bgcolor="${C.accent}" style="border-radius:8px;background:${C.accent}">
      <a href="${esc(site)}" style="display:inline-block;padding:12px 22px;border-radius:8px;${font(14, '#ffffff', 700, 'text-decoration:none')}">Ver el análisis completo en la web</a>
    </td></tr>
  </table>
  <div style="${font(12, C.muted, 400, 'text-align:center;margin-top:8px')}">Abre el .eml en ${esc(host)} para ver el contenido, la ruta de entrega, las cabeceras y los IOCs.</div>` : '';
  return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light only"><meta name="supported-color-schemes" content="light">
<title>EML Inspector</title>
<style>
  @media (max-width: 620px) {
    .wrap { padding: 12px 8px !important; }
    .px { padding-left: 16px !important; padding-right: 16px !important; }
    .gauge-cell { width: 84px !important; padding-left: 12px !important; }
    .fact-k { width: 96px !important; }
  }
</style></head>
<body style="margin:0;padding:0;background:${C.bg};-webkit-text-size-adjust:100%">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">${esc(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${C.bg}">
<tr><td class="wrap" align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px">
  <tr><td style="padding:0 4px 14px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td valign="middle">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
          <td width="30" height="30" align="center" valign="middle" style="width:30px;height:30px;border-radius:8px;background:${C.accent};${font(13, '#ffffff', 800, 'line-height:30px')}">@</td>
          <td style="padding-left:10px;${font(16, C.text, 700)}">EML Inspector</td>
        </tr></table>
      </td>
      <td align="right" valign="middle" style="${font(12, C.muted, 600)}">Informe de análisis</td>
    </tr></table>
  </td></tr>
  <tr><td>${inner}</td></tr>
  <tr><td style="padding:8px 4px 0">${button}</td></tr>
  <tr><td style="padding:22px 12px 0;${font(12, C.muted, 400, 'text-align:center')}">
    Análisis automático: orienta, pero no sustituye a tu criterio ni al de tu equipo de seguridad.<br>
    El correo se ha procesado en memoria y no se guarda.
  </td></tr>
</table>
</td></tr></table>
</body></html>`;
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
  // Texto de vista previa en la bandeja de entrada: la conclusión del peor correo.
  const preheader = worst ? (() => { const c = Analysis.conclusion(worst.entry); return `${c.title}. ${defang(c.text)}`; })() : errText.join(' ');
  const notices = [...errText, ...extraText].map(t => `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px"><tr><td style="padding:12px 16px;border-radius:10px;background:${C.highSoft};border-left:4px solid ${C.high};${font(14, C.high, 600)}">${esc(t)}</td></tr></table>`).join('');
  const html = wrapHtml(ok.map(x => entryHtml(x.entry, stats)).join('') + notices, { site, preheader });
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
  const rows = steps.map(([k, v], i) => `<tr>
    <td width="34" valign="top" style="padding:6px 0"><div style="width:24px;height:24px;border-radius:50%;background:${C.accent};text-align:center;${font(12, '#ffffff', 700, 'line-height:24px')}">${i + 1}</div></td>
    <td valign="top" style="padding:6px 0;${font(14, C.text, 400, 'line-height:22px')}"><strong>${esc(k)}</strong>: ${esc(v)}</td>
  </tr>`).join('');
  const inner = `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${C.surface};border:1px solid ${C.border};border-radius:14px;overflow:hidden">
  <tr><td style="height:4px;line-height:4px;font-size:0;background:${C.accent}">&nbsp;</td></tr>
  <tr><td class="px" style="padding:22px 28px 0">
    <div style="${font(20, C.text, 700, 'line-height:1.3')}">Adjunta el correo que quieres analizar</div>
    <div style="${font(14, C.text, 400, 'margin-top:8px')}">${esc(intro)}</div>
  </td></tr>
  ${section('Cómo adjuntarlo', `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${rows}</table>`)}
  <tr><td style="height:24px;line-height:24px;font-size:0">&nbsp;</td></tr>
</table>`;
  return {
    subject: 'Adjunta el correo que quieres analizar',
    text: [intro, '', 'Cómo adjuntarlo:', ...steps.map(([k, v]) => `  - ${k}: ${v}`)].join('\n') + textFooter(site),
    html: wrapHtml(inner, { site, preheader: 'Envíalo como archivo adjunto (.eml o .msg) para poder analizarlo.', cta: false }),
  };
}

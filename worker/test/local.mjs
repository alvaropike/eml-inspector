// Prueba local del buzón: analiza correos como lo haría el Worker, mide la CPU y guarda los informes.
//   node test/local.mjs [carpeta o .eml…] [--online] [--out carpeta]
import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, basename } from 'node:path';
import { emailAttachments, analyzeEmail } from '../src/core.js';
import { buildReport } from '../src/report.js';
import { buildMime } from '../src/mime-out.js';

const args = process.argv.slice(2);
const online = args.includes('--online');
const outIdx = args.indexOf('--out');
const outDir = outIdx >= 0 ? args[outIdx + 1] : null;
const inputs = args.filter((a, i) => !a.startsWith('--') && !(outIdx >= 0 && i === outIdx + 1));
const files = (inputs.length ? inputs : [new URL('../../samples', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1')])
  .flatMap(p => statSync(p).isDirectory() ? readdirSync(p).filter(f => /\.(eml|msg)$/i.test(f)).map(f => join(p, f)) : [p]);

// Mensaje entrante simulado: el correo va como message/rfc822, igual que «reenviar como adjunto».
function wrap(bytes) {
  const head = 'From: <prueba@example.com>\r\nTo: <eml@eml.alvaropiquerastrenado.com>\r\nSubject: Fwd\r\nMIME-Version: 1.0\r\n' +
    'Content-Type: multipart/mixed; boundary="xx"\r\n\r\n--xx\r\nContent-Type: text/plain\r\n\r\nMira esto\r\n--xx\r\nContent-Type: message/rfc822\r\n\r\n';
  const tail = '\r\n--xx--\r\n';
  const enc = new TextEncoder();
  const out = new Uint8Array(head.length + bytes.length + tail.length);
  out.set(enc.encode(head)); out.set(bytes, head.length); out.set(enc.encode(tail), head.length + bytes.length);
  return out;
}

const cpu = () => { const u = process.cpuUsage(); return (u.user + u.system) / 1000; };
if (outDir) mkdirSync(outDir, { recursive: true });
const rows = [];
for (const file of files) {
  const bytes = new Uint8Array(readFileSync(file));
  const t0 = cpu();
  const found = emailAttachments(wrap(bytes));
  let entry, error;
  try { entry = await analyzeEmail(found[0].bytes, found[0].name, online ? { maxLinkDomains: 4 } : false); }
  catch (e) { error = e.message; }
  const report = buildReport([{ name: found[0].name, entry, error }].map(x => (x.entry ? { name: x.name, entry: x.entry } : { name: x.name, error: x.error })), { site: 'https://eml.alvaropiquerastrenado.com' });
  const ms = cpu() - t0;
  const mime = buildMime({ from: 'eml@eml.alvaropiquerastrenado.com', fromName: 'EML Inspector', to: 'prueba@example.com', subject: report.subject, text: report.text, html: report.html, inReplyTo: '<a@b>' });
  rows.push({ fichero: basename(file).slice(0, 45), kb: Math.round(bytes.length / 1024), adjuntos: found.length, riesgo: entry ? `${entry.score} ${entry.level}` : 'error: ' + error, cpu_ms: Math.round(ms), asunto: report.subject.slice(0, 60) });
  if (outDir) {
    const base = join(outDir, basename(file).replace(/\.(eml|msg)$/i, ''));
    writeFileSync(base + '.html', report.html);
    writeFileSync(base + '.txt', report.text);
    writeFileSync(base + '.reply.eml', mime);
  }
}
console.table(rows);

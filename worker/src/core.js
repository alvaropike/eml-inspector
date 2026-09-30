/*
 * Análisis de correos fuera del navegador: carga los mismos módulos que la web (scripts clásicos
 * que se registran en globalThis) y reproduce los pasos de app.js sin la interfaz.
 * Lo usan el Worker del buzón y las pruebas en Node.
 */
import { DOMParser } from 'linkedom';
import '../../js/mime.js';
import '../../js/analysis.js';
import '../../js/msg.js';
import '../../js/dkim.js';
import '../../js/safebrowsing.js';
import '../../js/online.js';

// analysis.js usa DOMParser para sacar los enlaces y el texto del HTML; sin él no encontraría enlaces.
if (typeof globalThis.DOMParser === 'undefined') globalThis.DOMParser = DOMParser;

export const { MIME, Analysis, MSG, Online } = globalThis;

// Adjuntos del correo recibido que son a su vez correos: message/rfc822 («reenviar como adjunto»),
// .eml descargados o .msg de Outlook.
export function emailAttachments(bytes) {
  const outer = MIME.parseEmail(bytes, 'recibido.eml');
  return outer.attachments
    .filter(n => n.isEmbeddedMessage || /\.(eml|msg)$/i.test(n.filename) || /^application\/(vnd\.ms-outlook|x-msg)$/i.test(n.contentType))
    .map((n, i) => {
      const subject = n.isEmbeddedMessage && n.children[0] ? MIME.decodeEncodedWords(n.children[0].headers.get('subject') || '') : '';
      return { name: n.filename || (subject ? subject.slice(0, 80) + '.eml' : `correo-${i + 1}.eml`), bytes: MIME.getBytes(n) };
    })
    .filter(x => x.bytes.length);
}

// Une los hallazgos locales y los de las comprobaciones en línea (como rescore() en app.js).
function rescore(entry) {
  const local = entry.analysis.findings;
  const list = [...local, ...((entry.online && entry.online.findings) || [])];
  Analysis.sortFindings(list);
  entry.findings = list;
  Object.assign(entry, Analysis.scoreFindings(list));
  entry.localScore = Analysis.scoreFindings(local).score;
}

// online: false para sólo el análisis local; si no, las opciones de Online.run.
export async function analyzeEmail(bytes, name, online) {
  let msgInfo = null;
  if (MSG.isMsg(bytes)) {
    const conv = MSG.toEml(bytes);
    bytes = conv.bytes;
    msgInfo = conv.info;
  }
  const email = MIME.parseEmail(bytes, name);
  if (msgInfo) { email.sourceFormat = 'msg'; email.msgInfo = msgInfo; }
  if (!email.headers.list.length) throw new Error('no parece un correo (no hay cabeceras)');
  const analysis = await Analysis.analyze(email);
  const entry = { name, email, analysis, online: null, qr: [], qrFindings: [] };
  rescore(entry);
  if (online) {
    try { entry.online = await Online.run(entry, online); }
    catch (e) { entry.online = { error: e.message, domains: {}, ips: {}, findings: [] }; }
    rescore(entry);
  }
  return entry;
}

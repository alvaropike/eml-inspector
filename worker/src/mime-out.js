/*
 * Construye el mensaje de respuesta (RFC 5322) con una parte de texto y otra HTML en UTF-8.
 */

const enc = new TextEncoder();

function base64(str) {
  const bytes = enc.encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/.{76}(?=.)/g, '$&\r\n');
}

// Cabecera con texto no ASCII: palabras codificadas RFC 2047 de como mucho 75 caracteres.
function encodeWord(str) {
  if (/^[\x20-\x7e]*$/.test(str)) return str;
  const words = [];
  let chunk = '';
  for (const ch of str) {
    // 45 bytes de UTF-8 dan 60 caracteres en base64, que con =?UTF-8?B?…?= quedan en 72.
    if (enc.encode(chunk + ch).length > 45) { words.push(chunk); chunk = ''; }
    chunk += ch;
  }
  if (chunk) words.push(chunk);
  return words.map(w => `=?UTF-8?B?${btoa(String.fromCharCode(...enc.encode(w)))}?=`).join('\r\n ');
}

// Sólo caracteres válidos en un Message-ID: lo que venga del correo recibido no puede meter cabeceras.
const cleanId = id => (String(id || '').match(/<[^<>\s]+@[^<>\s]+>/) || [''])[0];

export function buildMime({ from, fromName, replyTo, to, subject, text, html, inReplyTo, references }) {
  const domain = from.split('@')[1];
  const boundary = 'b' + crypto.randomUUID().replace(/-/g, '');
  const parent = cleanId(inReplyTo);
  const refs = [...String(references || '').matchAll(/<[^<>\s]+@[^<>\s]+>/g)].map(m => m[0]).slice(-20);
  if (parent && !refs.includes(parent)) refs.push(parent);
  const headers = [
    `From: ${fromName ? `${encodeWord(fromName)} ` : ''}<${from}>`,
    `To: <${to}>`,
    replyTo ? `Reply-To: <${replyTo}>` : '',
    `Subject: ${encodeWord(subject.replace(/[\r\n]+/g, ' '))}`,
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: <${crypto.randomUUID()}@${domain}>`,
    parent ? `In-Reply-To: ${parent}` : '',
    refs.length ? `References: ${refs.join('\r\n ')}` : '',
    // RFC 3834: respuesta automática, para que otros sistemas automáticos no contesten a su vez.
    'Auto-Submitted: auto-replied',
    'X-Auto-Response-Suppress: All',
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
  ].filter(Boolean);
  const part = (type, body) => [
    `--${boundary}`,
    `Content-Type: ${type}; charset=utf-8`,
    'Content-Transfer-Encoding: base64',
    '',
    base64(body),
  ].join('\r\n');
  return headers.join('\r\n') + '\r\n\r\n' + [part('text/plain', text), part('text/html', html), `--${boundary}--`, ''].join('\r\n');
}

/*
 * Lector de ficheros .msg de Outlook (MS-CFB + MS-OXMSG) y conversión a .eml.
 * Si el .msg conserva las cabeceras de Internet originales (PR_TRANSPORT_MESSAGE_HEADERS)
 * se usan tal cual; el cuerpo y los adjuntos se reconstruyen a partir de las propiedades MAPI.
 */
(function (global) {
  'use strict';

  const MIME = global.MIME;
  const END = 0xfffffffa; // a partir de aquí: ENDOFCHAIN, FREESECT, etc.
  const NOSTREAM = 0xffffffff;

  // ---------- Compound File Binary ----------

  function isMsg(bytes) {
    return bytes.length > 512 && bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0 &&
      bytes[4] === 0xa1 && bytes[5] === 0xb1 && bytes[6] === 0x1a && bytes[7] === 0xe1;
  }

  function readCFB(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const u32 = o => dv.getUint32(o, true);
    const secSize = 1 << dv.getUint16(0x1e, true);
    const miniSize = 1 << dv.getUint16(0x20, true);
    const firstDir = u32(0x30);
    const miniCutoff = u32(0x38);
    const firstMiniFat = u32(0x3c);
    const numMiniFat = u32(0x40);
    let difat = u32(0x44);
    const numDifat = u32(0x48);
    const off = s => (s + 1) * secSize;

    // Sectores de la FAT: 109 en la cabecera y el resto encadenados en sectores DIFAT.
    const fatSectors = [];
    for (let i = 0; i < 109; i++) { const v = u32(0x4c + i * 4); if (v < END) fatSectors.push(v); }
    for (let k = 0; k < numDifat && difat < END; k++) {
      const o = off(difat);
      for (let j = 0; j < secSize / 4 - 1; j++) { const v = u32(o + j * 4); if (v < END) fatSectors.push(v); }
      difat = u32(o + secSize - 4);
    }
    const perSec = secSize / 4;
    const fat = new Uint32Array(fatSectors.length * perSec);
    fatSectors.forEach((s, i) => {
      const o = off(s);
      for (let j = 0; j < perSec; j++) fat[i * perSec + j] = o + j * 4 + 4 <= bytes.length ? u32(o + j * 4) : NOSTREAM;
    });

    const chain = (start, table) => {
      const out = [];
      const seen = new Set();
      for (let s = start; s < END && !seen.has(s) && s < table.length; s = table[s]) { seen.add(s); out.push(s); }
      return out;
    };
    const readChain = (start, size) => {
      const secs = chain(start, fat);
      const buf = new Uint8Array(secs.length * secSize);
      secs.forEach((s, i) => buf.set(bytes.subarray(off(s), off(s) + secSize), i * secSize));
      return size == null ? buf : buf.subarray(0, Math.min(size, buf.length));
    };

    // Directorio: entradas de 128 bytes.
    const dirBytes = readChain(firstDir);
    const ddv = new DataView(dirBytes.buffer, dirBytes.byteOffset, dirBytes.byteLength);
    const entries = [];
    for (let o = 0; o + 128 <= dirBytes.length; o += 128) {
      const nameLen = ddv.getUint16(o + 0x40, true);
      const type = dirBytes[o + 0x42];
      const name = nameLen >= 2 ? new TextDecoder('utf-16le').decode(dirBytes.subarray(o, o + Math.min(64, nameLen) - 2)) : '';
      entries.push({
        name, type,
        left: ddv.getUint32(o + 0x44, true), right: ddv.getUint32(o + 0x48, true), child: ddv.getUint32(o + 0x4c, true),
        start: ddv.getUint32(o + 0x74, true), size: ddv.getUint32(o + 0x78, true),
      });
    }
    const root = entries[0];
    if (!root || root.type !== 5) throw new Error('Directorio del .msg dañado');

    const miniStream = readChain(root.start, root.size);
    const miniFatBytes = numMiniFat ? readChain(firstMiniFat, numMiniFat * secSize) : new Uint8Array(0);
    const miniFat = new Uint32Array(miniFatBytes.length / 4);
    const mdv = new DataView(miniFatBytes.buffer, miniFatBytes.byteOffset, miniFatBytes.byteLength);
    for (let i = 0; i < miniFat.length; i++) miniFat[i] = mdv.getUint32(i * 4, true);

    function data(e) {
      if (e.size < miniCutoff) {
        const secs = chain(e.start, miniFat);
        const buf = new Uint8Array(secs.length * miniSize);
        secs.forEach((s, i) => buf.set(miniStream.subarray(s * miniSize, s * miniSize + miniSize), i * miniSize));
        return buf.subarray(0, e.size);
      }
      return readChain(e.start, e.size);
    }

    // Hijos de un almacén: recorrido del árbol rojo-negro (izquierda, nodo, derecha).
    function children(e) {
      const out = [];
      const stack = [];
      const seen = new Set();
      let id = e.child;
      while ((id !== NOSTREAM && id < entries.length && !seen.has(id)) || stack.length) {
        while (id !== NOSTREAM && id < entries.length && !seen.has(id)) { stack.push(id); id = entries[id].left; }
        const cur = stack.pop();
        if (cur === undefined) break;
        seen.add(cur);
        out.push(entries[cur]);
        id = entries[cur].right;
      }
      return out;
    }

    return { root, children, data };
  }

  // ---------- propiedades MAPI ----------

  const CODEPAGES = { 1250: 'windows-1250', 1251: 'windows-1251', 1252: 'windows-1252', 1253: 'windows-1253', 1254: 'windows-1254', 1255: 'windows-1255',
    1256: 'windows-1256', 1257: 'windows-1257', 1258: 'windows-1258', 20127: 'us-ascii', 28591: 'iso-8859-1', 28592: 'iso-8859-2', 28595: 'iso-8859-5',
    28605: 'iso-8859-15', 65001: 'utf-8', 932: 'shift_jis', 936: 'gbk', 949: 'euc-kr', 950: 'big5', 866: 'ibm866', 874: 'windows-874', 50220: 'iso-2022-jp', 51932: 'euc-jp' };

  // Lee las propiedades de un almacén: streams __substg1.0_TTTTYYYY y valores fijos en __properties_version1.0.
  function readProps(cfb, storage, headerSize) {
    const props = {};
    let cpid = 0;
    const kids = cfb.children(storage);
    const fixed = kids.find(k => k.name === '__properties_version1.0' && k.type === 2);
    if (fixed) {
      const b = cfb.data(fixed);
      const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
      for (let o = headerSize; o + 16 <= b.length; o += 16) {
        const type = dv.getUint16(o, true);
        const id = dv.getUint16(o + 2, true).toString(16).toUpperCase().padStart(4, '0');
        if (type === 0x0003) props[id] = dv.getInt32(o + 8, true);
        else if (type === 0x000b) props[id] = !!dv.getUint16(o + 8, true);
        else if (type === 0x0040) {
          const ft = dv.getUint32(o + 8, true) + dv.getUint32(o + 12, true) * 4294967296;
          if (ft) props[id] = new Date(ft / 10000 - 11644473600000);
        }
      }
      cpid = props['3FDE'] || props['3FFD'] || 0;
    }
    const decoder = new TextDecoder(CODEPAGES[cpid] || 'windows-1252');
    kids.forEach(k => {
      const m = k.type === 2 && k.name.match(/^__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})(-[0-9A-Fa-f]{8})?$/);
      if (!m || m[3]) return;
      const id = m[1].toUpperCase(), type = m[2].toUpperCase();
      const raw = cfb.data(k);
      let v;
      if (type === '001F') v = new TextDecoder('utf-16le').decode(raw).replace(/\0+$/, '');
      else if (type === '001E') v = decoder.decode(raw).replace(/\0+$/, '');
      else if (type === '0102') v = raw;
      else return;
      if (props[id] === undefined || type === '001F') props[id] = v;
    });
    return { props, cpid, kids };
  }

  // ---------- RTF comprimido (MS-OXRTFCP) ----------

  const RTF_PREBUF = '{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx';

  function decompressRTF(src) {
    if (!src || src.length < 16) return null;
    const dv = new DataView(src.buffer, src.byteOffset, src.byteLength);
    const rawSize = dv.getUint32(4, true);
    const type = dv.getUint32(8, true);
    if (type === 0x414c454d) return src.subarray(16, 16 + rawSize); // 'MELA': sin comprimir
    if (type !== 0x75465a4c) return null; // 'LZFu'
    const dict = new Uint8Array(4096);
    for (let i = 0; i < RTF_PREBUF.length; i++) dict[i] = RTF_PREBUF.charCodeAt(i);
    let wp = RTF_PREBUF.length;
    const out = new Uint8Array(rawSize);
    let op = 0, ip = 16;
    while (ip < src.length && op < rawSize) {
      const ctrl = src[ip++];
      for (let bit = 0; bit < 8 && ip < src.length && op < rawSize; bit++) {
        if (ctrl & (1 << bit)) {
          const hi = src[ip++], lo = src[ip++];
          const offset = (hi << 4) | (lo >> 4);
          const len = (lo & 0x0f) + 2;
          if (offset === wp) return out.subarray(0, op); // fin del flujo
          for (let k = 0; k < len && op < rawSize; k++) {
            const c = dict[(offset + k) & 0xfff];
            out[op++] = c;
            dict[wp] = c;
            wp = (wp + 1) & 0xfff;
          }
        } else {
          const c = src[ip++];
          out[op++] = c;
          dict[wp] = c;
          wp = (wp + 1) & 0xfff;
        }
      }
    }
    return out.subarray(0, op);
  }

  // ---------- HTML/texto encapsulado en RTF (MS-OXRTFEX) ----------

  const RTF_SYMBOLS = { par: '\r\n', line: '\r\n', tab: '\t', lquote: '‘', rquote: '’', ldblquote: '“', rdblquote: '”', bullet: '•', endash: '–', emdash: '—', emspace: ' ', enspace: ' ', '~': ' ' };
  const RTF_SKIP = new Set(['fonttbl', 'colortbl', 'stylesheet', 'info', 'pict', 'header', 'footer', 'object', 'listtable', 'listoverridetable', 'themedata', 'datastore', 'generator', 'xmlnstbl', 'rsidtbl', 'latentstyles']);

  // Devuelve { kind: 'html'|'text'|'rtf', content }.
  function deencapsulateRTF(bytes) {
    const rtf = MIME.bytesToBinary(bytes);
    const kind = /\\fromhtml1/.test(rtf.slice(0, 2048)) ? 'html' : /\\fromtext/.test(rtf.slice(0, 2048)) ? 'text' : 'rtf';
    const cp = +(rtf.match(/\\ansicpg(\d+)/) || [])[1] || 1252;
    const decoder = new TextDecoder(CODEPAGES[cp] || 'windows-1252');
    let out = '';
    let pending = [];
    const flush = () => { if (pending.length) { out += decoder.decode(new Uint8Array(pending)); pending = []; } };
    const emit = t => { flush(); out += t; };

    // Estado por grupo: suprimido por \htmlrtf, dentro de \htmltag, grupo a ignorar, \uc.
    let st = { htmlrtf: false, htmltag: false, skip: false, uc: 1 };
    const stack = [];
    let skipChars = 0;
    let groupStart = false;
    const visible = () => !st.skip && (kind === 'rtf' || st.htmltag || !st.htmlrtf);

    for (let i = 0; i < rtf.length; i++) {
      const c = rtf[i];
      if (c === '{') { stack.push(st); st = Object.assign({}, st); groupStart = true; continue; }
      if (c === '}') { flush(); st = stack.pop() || st; groupStart = false; continue; }
      if (c === '\r' || c === '\n') continue;
      if (c === '\\') {
        const n = rtf[i + 1];
        if (n === '\\' || n === '{' || n === '}') { if (visible() && !skipChars) emit(n); else if (skipChars) skipChars--; i++; groupStart = false; continue; }
        if (n === "'") {
          const hex = rtf.substr(i + 2, 2);
          i += 3;
          if (skipChars) { skipChars--; continue; }
          if (visible()) pending.push(parseInt(hex, 16));
          groupStart = false;
          continue;
        }
        if (n === '*') {
          // Destino opcional: sólo interesan \htmltag (el HTML original); el resto se ignora.
          const m = rtf.slice(i + 2, i + 40).match(/^\\([a-z]+)(-?\d+)?/);
          if (m && m[1] === 'htmltag') { st.htmltag = true; st.htmlrtf = false; }
          else st.skip = true;
          i += 1;
          groupStart = false;
          continue;
        }
        const m = rtf.slice(i + 1, i + 40).match(/^([a-zA-Z]+)(-?\d+)? ?|^(.)/);
        if (!m) continue;
        i += m[0].length;
        if (m[3]) { if (visible() && RTF_SYMBOLS[m[3]]) emit(RTF_SYMBOLS[m[3]]); groupStart = false; continue; }
        const word = m[1], param = m[2] !== undefined ? +m[2] : null;
        if (groupStart && RTF_SKIP.has(word)) st.skip = true;
        groupStart = false;
        if (word === 'htmlrtf') { st.htmlrtf = param !== 0; continue; }
        if (word === 'uc') { st.uc = param == null ? 1 : param; continue; }
        if (word === 'u' && param != null) { if (visible()) emit(String.fromCharCode(param < 0 ? param + 65536 : param)); skipChars = st.uc; continue; }
        if (word === 'bin' && param) { i += param; continue; }
        if (RTF_SYMBOLS[word] && visible()) { emit(RTF_SYMBOLS[word]); continue; }
        continue;
      }
      groupStart = false;
      if (skipChars) { skipChars--; continue; }
      if (visible()) { flush(); out += c; }
    }
    flush();
    return { kind, content: out };
  }

  // ---------- conversión a .eml ----------

  const b64 = bytes => {
    const bin = MIME.bytesToBinary(bytes);
    return btoa(bin).replace(/.{76}(?=.)/g, '$&\r\n');
  };
  const utf8 = s => new TextEncoder().encode(s);
  const needsEncoding = s => /[^\x20-\x7e]/.test(s);
  const encodeWord = s => needsEncoding(s) ? '=?UTF-8?B?' + btoa(MIME.bytesToBinary(utf8(s))) + '?=' : s;
  const addrHeader = (name, email) => email ? (name && name !== email ? `${encodeWord(`"${name.replace(/"/g, '')}"`)} <${email}>` : `<${email}>`) : encodeWord(name || '');
  const quoteParam = v => needsEncoding(v) ? `*=UTF-8''${encodeURIComponent(v)}` : `="${v.replace(/"/g, '')}"`;
  const rfcDate = d => d instanceof Date && !isNaN(d) ? d.toUTCString().replace('GMT', '+0000') : '';
  const boundary = n => `----=_EMLInspector_${n}_${Math.random().toString(36).slice(2, 10)}`;

  // Cabeceras con UTF-8 en crudo que Outlook guardó como si fueran Latin-1 («juÅ¼» en vez de «już»):
  // si todos los caracteres caben en un byte y forman UTF-8 válido con algún multibyte, se corrige.
  function fixMojibake(s) {
    if (!/[\u00c2-\u00f4][\u0080-\u00bf]/.test(s) || /[^\u0000-\u00ff]/.test(s)) return s;
    try {
      const bytes = Uint8Array.from(s, ch => ch.charCodeAt(0));
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (_) { return s; }
  }

  // Quita de las cabeceras originales las de estructura MIME: el cuerpo se genera de nuevo.
  function cleanTransportHeaders(text) {
    const lines = text.replace(/\r?\n/g, '\r\n').replace(/(\r\n)+$/, '').split('\r\n');
    const out = [];
    let skip = false;
    for (const line of lines) {
      if (/^[ \t]/.test(line)) { if (!skip) out.push(line); continue; }
      skip = /^(content-[a-z-]+|mime-version)\s*:/i.test(line);
      if (!skip && line) out.push(line);
    }
    return out.join('\r\n');
  }

  function smtpOf(p) {
    const cands = [p['39FE'], p['5D01'], p['5D02'], p['3003'], p['0C1F'], p['0065']];
    return cands.find(v => typeof v === 'string' && /@/.test(v) && !/^\/o=/i.test(v)) || '';
  }

  function convert(cfb, storage, depth, headerSize) {
    const { props: p, kids } = readProps(cfb, storage, headerSize);
    const info = { transportHeaders: false, subject: p['0037'] || '', attachments: 0, embedded: 0 };

    // Destinatarios
    const rcpt = { 1: [], 2: [], 3: [] };
    kids.filter(k => k.type === 1 && /^__recip_version1\.0_#/.test(k.name)).forEach(r => {
      const rp = readProps(cfb, r, 8).props;
      const email = smtpOf(rp);
      const t = rp['0C15'] || 1;
      (rcpt[t] || rcpt[1]).push(addrHeader(rp['3001'] || rp['5FF6'] || '', email));
    });

    // Cabeceras
    let headers;
    const transport = typeof p['007D'] === 'string' ? p['007D'].trim() : '';
    if (transport && /^[A-Za-z-]+:/m.test(transport)) {
      headers = cleanTransportHeaders(fixMojibake(transport));
      info.transportHeaders = true;
    } else {
      const h = [];
      const fromEmail = smtpOf({ '5D01': p['5D01'], '0C1F': p['0C1F'], '0065': p['0065'], '5D02': p['5D02'] });
      h.push('From: ' + addrHeader(p['0C1A'] || p['0042'] || '', fromEmail));
      if (rcpt[1].length) h.push('To: ' + rcpt[1].join(', '));
      if (rcpt[2].length) h.push('Cc: ' + rcpt[2].join(', '));
      if (rcpt[3].length) h.push('Bcc: ' + rcpt[3].join(', '));
      h.push('Subject: ' + encodeWord(p['0037'] || ''));
      const date = rfcDate(p['0039'] || p['0E06'] || p['3007']);
      if (date) h.push('Date: ' + date);
      if (p['1035']) h.push('Message-ID: ' + p['1035']);
      if (p['1042']) h.push('In-Reply-To: ' + p['1042']);
      if (p['1039']) h.push('References: ' + p['1039']);
      headers = h.join('\r\n');
    }

    // Cuerpo: HTML (PR_HTML, binario en la página de códigos del mensaje) y texto (PR_BODY).
    let html = '';
    if (p['1013'] instanceof Uint8Array) html = MIME.decodeBytes(p['1013'], CODEPAGES[p['3FDE']] || '');
    else if (typeof p['1013'] === 'string') html = p['1013'];
    let text = typeof p['1000'] === 'string' ? p['1000'] : '';
    // Outlook suele guardar el HTML encapsulado en el RTF comprimido (PR_RTF_COMPRESSED).
    if (!html && p['1009'] instanceof Uint8Array) {
      try {
        const rtf = decompressRTF(p['1009']);
        if (rtf) {
          const d = deencapsulateRTF(rtf);
          if (d.kind === 'html') html = d.content;
          else if (!text) text = d.content;
          info.bodyFrom = 'rtf-' + d.kind;
        }
      } catch (_) { /* RTF dañado: se usa el texto plano */ }
    }

    // Adjuntos
    const parts = [];
    kids.filter(k => k.type === 1 && /^__attach_version1\.0_#/.test(k.name)).forEach(a => {
      const ap = readProps(cfb, a, 8);
      const q = ap.props;
      const name = q['3707'] || q['3704'] || q['3001'] || 'adjunto';
      const embedded = ap.kids.find(k => k.type === 1 && /^__substg1\.0_3701000D$/i.test(k.name));
      if (embedded && depth < 5) {
        const inner = convert(cfb, embedded, depth + 1, 24);
        info.embedded++;
        parts.push({ type: 'message/rfc822', name: name.replace(/(\.msg)?$/i, '.eml'), inline: false, raw: inner.eml });
        return;
      }
      if (!(q['3701'] instanceof Uint8Array)) return;
      info.attachments++;
      const cid = typeof q['3712'] === 'string' ? q['3712'] : '';
      parts.push({ type: q['370E'] || 'application/octet-stream', name, cid, inline: !!cid && (q['3714'] & 4 || /cid:/i.test(html)) && html.includes(cid), data: q['3701'] });
    });

    const inline = parts.filter(x => x.inline);
    const attached = parts.filter(x => !x.inline);
    const partHeader = x => {
      const h = [`Content-Type: ${x.type}; name${quoteParam(x.name)}`];
      if (x.raw) h[0] = 'Content-Type: message/rfc822';
      h.push(`Content-Disposition: ${x.inline ? 'inline' : 'attachment'}; filename${quoteParam(x.name)}`);
      if (x.cid) h.push(`Content-ID: <${x.cid.replace(/^<|>$/g, '')}>`);
      h.push(x.raw ? 'Content-Transfer-Encoding: 8bit' : 'Content-Transfer-Encoding: base64');
      return h.join('\r\n');
    };
    const partBody = x => x.raw ? x.raw : b64(x.data);

    // Árbol: mixed( related( alternative(text, html), inline... ), adjuntos... )
    let body = '';
    let ctype;
    const alt = [];
    if (text) alt.push('Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n' + b64(utf8(text)));
    if (html) alt.push('Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n' + b64(utf8(html)));
    if (!alt.length) alt.push('Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n' + b64(utf8('')));
    let core;
    if (alt.length === 1) core = alt[0];
    else {
      const b = boundary('alt' + depth);
      core = `Content-Type: multipart/alternative; boundary="${b}"\r\n\r\n` + alt.map(x => `--${b}\r\n${x}\r\n`).join('') + `--${b}--`;
    }
    if (inline.length) {
      const b = boundary('rel' + depth);
      core = `Content-Type: multipart/related; boundary="${b}"\r\n\r\n--${b}\r\n${core}\r\n` +
        inline.map(x => `--${b}\r\n${partHeader(x)}\r\n\r\n${partBody(x)}\r\n`).join('') + `--${b}--`;
    }
    if (attached.length) {
      const b = boundary('mix' + depth);
      core = `Content-Type: multipart/mixed; boundary="${b}"\r\n\r\n--${b}\r\n${core}\r\n` +
        attached.map(x => `--${b}\r\n${partHeader(x)}\r\n\r\n${partBody(x)}\r\n`).join('') + `--${b}--`;
    }
    const split = core.indexOf('\r\n\r\n');
    ctype = core.slice(0, split);
    body = core.slice(split + 4);
    const eml = `${headers}\r\nMIME-Version: 1.0\r\n${ctype}\r\n\r\n${body}\r\n`;
    return { eml, info };
  }

  // Devuelve { bytes, info } con el .eml equivalente. Las cadenas binarias se codifican byte a byte.
  function toEml(bytes) {
    if (!isMsg(bytes)) throw new Error('No es un fichero .msg de Outlook');
    const cfb = readCFB(bytes);
    const { eml, info } = convert(cfb, cfb.root, 0, 32);
    // Las cabeceras originales pueden traer UTF-8 en crudo: se codifican como UTF-8.
    return { bytes: utf8(eml), info };
  }

  const MSG = { isMsg, toEml, readCFB };
  if (typeof module !== 'undefined' && module.exports) module.exports = MSG;
  global.MSG = MSG;
})(typeof globalThis !== 'undefined' ? globalThis : this);

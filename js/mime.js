/*
 * Parser MIME / RFC 5322 sin dependencias.
 * Trabaja sobre "cadenas binarias" (1 carácter = 1 byte) para conservar los
 * índices de bytes y decodifica a texto sólo cuando hace falta.
 */
(function (global) {
  'use strict';

  // ---------- utilidades de bytes ----------

  function bytesToBinary(bytes) {
    let out = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return out;
  }

  function binaryToBytes(bin) {
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
    return out;
  }

  const CHARSET_ALIASES = {
    utf8: 'utf-8',
    'us-ascii': 'windows-1252',
    ascii: 'windows-1252',
    latin1: 'iso-8859-1',
    'ks_c_5601-1987': 'euc-kr',
    'x-sjis': 'shift_jis',
    cp1252: 'windows-1252',
    'cp-850': 'ibm866',
    gb2312: 'gbk',
  };

  function normalizeCharset(cs) {
    if (!cs) return '';
    cs = String(cs).trim().toLowerCase().replace(/^["']|["']$/g, '');
    return CHARSET_ALIASES[cs] || cs;
  }

  function decodeBytes(bytes, charset) {
    const cs = normalizeCharset(charset);
    if (!cs || cs === 'utf-8') {
      try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
      catch (_) { if (cs === 'utf-8') return new TextDecoder('utf-8').decode(bytes); }
      return new TextDecoder('windows-1252').decode(bytes);
    }
    try { return new TextDecoder(cs).decode(bytes); }
    catch (_) {
      try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
      catch (_) { return new TextDecoder('windows-1252').decode(bytes); }
    }
  }

  // ---------- codificaciones de transferencia ----------

  function decodeBase64Binary(str) {
    let clean = str.replace(/[^A-Za-z0-9+/]/g, '');
    const rem = clean.length % 4;
    if (rem === 1) clean = clean.slice(0, -1);
    else if (rem) clean += '='.repeat(4 - rem);
    try { return atob(clean); } catch (_) { return ''; }
  }

  function decodeQPBinary(str) {
    return str
      .replace(/[ \t]+(\r?\n)/g, '$1')
      .replace(/=\r?\n/g, '')
      .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }

  function decodeTransfer(bin, cte) {
    switch ((cte || '').toLowerCase()) {
      case 'base64': return decodeBase64Binary(bin);
      case 'quoted-printable': return decodeQPBinary(bin);
      default: return bin;
    }
  }

  // ---------- cabeceras ----------

  // Decodifica encoded-words RFC 2047, uniendo palabras adyacentes del mismo
  // charset antes de decodificar (evita romper caracteres multibyte).
  function decodeEncodedWords(str) {
    if (!str || str.indexOf('=?') < 0) return str;
    const re = /=\?([^?\s]+)\?([BbQq])\?([^?]*)\?=/g;
    const tokens = [];
    let last = 0, m;
    while ((m = re.exec(str))) {
      if (m.index > last) tokens.push({ text: str.slice(last, m.index) });
      const charset = m[1].split('*')[0];
      const bin = m[2].toUpperCase() === 'B'
        ? decodeBase64Binary(m[3])
        : m[3].replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      tokens.push({ charset, bin });
      last = re.lastIndex;
    }
    if (last < str.length) tokens.push({ text: str.slice(last) });

    // El espacio entre dos encoded-words se ignora.
    const merged = [];
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.text !== undefined && /^\s*$/.test(t.text) && tokens[i - 1] && tokens[i - 1].bin !== undefined &&
          tokens[i + 1] && tokens[i + 1].bin !== undefined) continue;
      const prev = merged[merged.length - 1];
      if (t.bin !== undefined && prev && prev.bin !== undefined &&
          normalizeCharset(prev.charset) === normalizeCharset(t.charset)) {
        prev.bin += t.bin;
      } else {
        merged.push(Object.assign({}, t));
      }
    }
    return merged.map(t => t.text !== undefined ? t.text : decodeBytes(binaryToBytes(t.bin), t.charset)).join('');
  }

  // Los valores de cabecera pueden llevar UTF-8 en crudo (RFC 6532).
  function decodeHeaderValue(bin) {
    const text = /[\x80-\xff]/.test(bin) ? decodeBytes(binaryToBytes(bin)) : bin;
    return decodeEncodedWords(text);
  }

  function parseHeaderBlock(bin) {
    const unfolded = bin.replace(/\r?\n(?=[ \t])/g, '');
    const list = [];
    for (const line of unfolded.split(/\r?\n/)) {
      if (!line) continue;
      const i = line.indexOf(':');
      if (i <= 0) {
        // Línea "From " de mbox o basura: se conserva como continuación.
        if (list.length && !/^From /.test(line)) list[list.length - 1].raw += ' ' + line.trim();
        continue;
      }
      const name = line.slice(0, i).trim();
      const raw = line.slice(i + 1).trim();
      list.push({ name, raw });
    }
    for (const h of list) {
      h.key = h.name.toLowerCase();
      h.value = decodeHeaderValue(h.raw);
    }
    return list;
  }

  function makeHeaderAccess(list) {
    return {
      list,
      get(name) {
        const k = name.toLowerCase();
        const h = list.find(x => x.key === k);
        return h ? h.value : '';
      },
      getRaw(name) {
        const k = name.toLowerCase();
        const h = list.find(x => x.key === k);
        return h ? h.raw : '';
      },
      getAll(name) {
        const k = name.toLowerCase();
        return list.filter(x => x.key === k).map(x => x.value);
      },
      has(name) {
        const k = name.toLowerCase();
        return list.some(x => x.key === k);
      },
    };
  }

  // Divide "a; b=c; d=\"e;f\"" respetando comillas y comentarios.
  function splitParams(str) {
    const out = [];
    let cur = '', q = false, depth = 0;
    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      if (q) {
        if (c === '\\' && i + 1 < str.length) { cur += c + str[++i]; continue; }
        if (c === '"') q = false;
        cur += c;
      } else if (c === '"') { q = true; cur += c; }
      else if (c === '(') { depth++; }
      else if (c === ')') { if (depth) depth--; }
      else if (depth) { /* comentario, se descarta */ }
      else if (c === ';') { out.push(cur); cur = ''; }
      else cur += c;
    }
    out.push(cur);
    return out.map(s => s.trim()).filter(Boolean);
  }

  function unquote(v) {
    v = v.trim();
    if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') {
      v = v.slice(1, -1).replace(/\\(.)/g, '$1');
    }
    return v;
  }

  // Parsea "tipo/subtipo; params" con soporte de RFC 2231 (continuaciones y charset).
  function parseStructuredHeader(raw) {
    const parts = splitParams(raw || '');
    const value = (parts.shift() || '').toLowerCase();
    const params = {};
    const ext = {};
    for (const p of parts) {
      const eq = p.indexOf('=');
      if (eq < 0) continue;
      const rawName = p.slice(0, eq).trim().toLowerCase();
      const rawVal = unquote(p.slice(eq + 1));
      const m = rawName.match(/^([^*]+)(?:\*(\d+))?(\*)?$/);
      if (!m) continue;
      const [, name, idx, star] = m;
      if (idx === undefined && !star) { params[name] = rawVal; continue; }
      (ext[name] = ext[name] || []).push({ idx: idx === undefined ? 0 : +idx, encoded: !!star, val: rawVal });
    }
    for (const name of Object.keys(ext)) {
      const segs = ext[name].sort((a, b) => a.idx - b.idx);
      let charset = 'utf-8';
      let bin = '';
      segs.forEach((s, i) => {
        let v = s.val;
        if (s.encoded) {
          if (i === 0) {
            const m = v.match(/^([^']*)'[^']*'(.*)$/);
            if (m) { charset = m[1] || charset; v = m[2]; }
          }
          bin += v.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
        } else {
          bin += v;
        }
      });
      params[name] = decodeBytes(binaryToBytes(bin), charset);
    }
    for (const k of Object.keys(params)) params[k] = decodeHeaderValue(params[k]);
    return { value, params };
  }

  // ---------- estructura MIME ----------

  function findHeaderEnd(bin) {
    const m = /\r?\n\r?\n/.exec(bin);
    if (!m) return { headerEnd: bin.length, bodyStart: bin.length };
    return { headerEnd: m.index, bodyStart: m.index + m[0].length };
  }

  function splitMultipart(body, boundary) {
    const delim = '--' + boundary;
    const isDelimAt = (i) => {
      if (body.substr(i, delim.length) !== delim) return false;
      const next = body[i + delim.length];
      return next === undefined || next === '-' || next === '\r' || next === '\n' || next === ' ' || next === '\t';
    };
    const findNext = (from) => {
      let i = from;
      while (true) {
        i = body.indexOf('\n' + delim, i);
        if (i < 0) return -1;
        if (isDelimAt(i + 1)) return i + 1;
        i += 1;
      }
    };
    let idx = isDelimAt(0) ? 0 : findNext(0);
    const preamble = idx > 0 ? body.slice(0, idx) : '';
    const marks = [];
    while (idx >= 0) {
      const after = idx + delim.length;
      const isClose = body.substr(after, 2) === '--';
      const lineEnd = body.indexOf('\n', after);
      marks.push({ idx, contentStart: lineEnd < 0 ? body.length : lineEnd + 1, isClose });
      if (isClose) break;
      idx = findNext(after);
    }
    const parts = [];
    for (let i = 0; i < marks.length; i++) {
      if (marks[i].isClose) break;
      let end = i + 1 < marks.length ? marks[i + 1].idx - 1 : body.length;
      if (i + 1 < marks.length && body[end - 1] === '\r') end--;
      parts.push(body.slice(marks[i].contentStart, Math.max(marks[i].contentStart, end)));
    }
    const closed = marks.length > 0 && marks[marks.length - 1].isClose;
    return { parts, preamble, closed };
  }

  const MAX_DEPTH = 40;

  function parseEntity(bin, path, depth, parentType) {
    const { headerEnd, bodyStart } = findHeaderEnd(bin);
    const headerList = parseHeaderBlock(bin.slice(0, headerEnd));
    const headers = makeHeaderAccess(headerList);

    const defaultType = parentType === 'multipart/digest' ? 'message/rfc822' : 'text/plain';
    const ctRaw = headers.getRaw('content-type');
    const ct = parseStructuredHeader(ctRaw || defaultType);
    if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(ct.value)) ct.value = defaultType;
    const disp = parseStructuredHeader(headers.getRaw('content-disposition'));
    const cte = (headers.get('content-transfer-encoding') || '').trim().toLowerCase();

    const node = {
      path,
      headers,
      contentType: ct.value,
      params: ct.params,
      charset: ct.params.charset || '',
      disposition: disp.value,
      dispParams: disp.params,
      filename: disp.params.filename || ct.params.name || '',
      cte,
      contentId: (headers.get('content-id') || '').replace(/^<|>$/g, '').trim(),
      contentLocation: headers.get('content-location') || '',
      rawBody: bin.slice(bodyStart),
      headerSize: bodyStart,
      children: [],
      warnings: [],
    };

    if (depth > MAX_DEPTH) {
      node.warnings.push('Anidamiento MIME demasiado profundo; se detiene el análisis.');
      return node;
    }

    if (node.contentType.startsWith('multipart/')) {
      const boundary = ct.params.boundary;
      if (!boundary) {
        node.warnings.push('Parte multipart sin boundary.');
      } else {
        const { parts, preamble, closed } = splitMultipart(node.rawBody, boundary);
        if (!closed) node.warnings.push('Falta el delimitador de cierre del multipart (mensaje truncado o malformado).');
        if (/\S/.test(preamble) && preamble.length > 400) node.warnings.push('Preámbulo multipart inusualmente largo.');
        node.children = parts.map((p, i) => parseEntity(p, path.concat(i + 1), depth + 1, node.contentType));
      }
    } else if (node.contentType === 'message/rfc822' || node.contentType === 'message/global') {
      const inner = decodeTransfer(node.rawBody, cte);
      node.embeddedRaw = inner;
      node.children = [parseEntity(inner, path.concat(1), depth + 1, node.contentType)];
      node.isEmbeddedMessage = true;
    }
    return node;
  }

  // ---------- acceso a contenido ----------

  function getBinary(node) {
    if (node._bin === undefined) node._bin = decodeTransfer(node.rawBody, node.cte);
    return node._bin;
  }

  function getBytes(node) {
    if (node.isEmbeddedMessage) return binaryToBytes(node.embeddedRaw);
    if (!node._bytes) node._bytes = binaryToBytes(getBinary(node));
    return node._bytes;
  }

  function getText(node) {
    if (node._text === undefined) node._text = decodeBytes(getBytes(node), node.charset);
    return node._text;
  }

  function walk(node, fn, parent) {
    fn(node, parent);
    for (const c of node.children) walk(c, fn, node);
  }

  function isAttachmentNode(node, parent) {
    if (node.children.length && !node.isEmbeddedMessage) return false;
    if (node.isEmbeddedMessage) return true;
    if (node.disposition === 'attachment') return true;
    if (node.filename) return true;
    const t = node.contentType;
    if (t === 'text/plain' || t === 'text/html') return false;
    if (t.startsWith('text/') && node.disposition !== 'inline') return t !== 'text/enriched';
    return true;
  }

  // Recorre el árbol sin entrar en mensajes adjuntos y separa cuerpos de adjuntos.
  function collectContent(root) {
    const texts = [], htmls = [], attachments = [];
    const visit = (node, parent) => {
      if (isAttachmentNode(node, parent)) {
        attachments.push(node);
        return;
      }
      if (node.children.length) {
        node.children.forEach(c => visit(c, node));
        return;
      }
      if (node.contentType === 'text/html') htmls.push(node);
      else if (node.contentType === 'text/plain') texts.push(node);
    };
    visit(root, null);
    return { texts, htmls, attachments };
  }

  function parseEmail(bytes, fileName) {
    const bin = bytesToBinary(bytes);
    // Algunos exportadores añaden una línea "From " estilo mbox al principio.
    const start = /^From [^\r\n]*\r?\n/.test(bin) ? bin.indexOf('\n') + 1 : 0;
    const root = parseEntity(start ? bin.slice(start) : bin, [], 0, null);
    const { texts, htmls, attachments } = collectContent(root);
    const inlineByCid = {};
    walk(root, n => { if (n.contentId && !n.children.length) inlineByCid[n.contentId.toLowerCase()] = n; });

    const text = texts.map(getText).join('\n\n').replace(/\r\n?/g, '\n');
    const html = htmls.map(getText).join('\n<hr>\n');

    const warnings = [];
    walk(root, n => n.warnings.forEach(w => warnings.push({ path: n.path, text: w })));

    return {
      fileName: fileName || '',
      size: bytes.length,
      raw: bin,
      root,
      headers: root.headers,
      text,
      html,
      textParts: texts,
      htmlParts: htmls,
      attachments,
      inlineByCid,
      warnings,
    };
  }

  const MIME = {
    parseEmail,
    parseStructuredHeader,
    decodeEncodedWords,
    decodeBytes,
    getBytes,
    getText,
    walk,
    bytesToBinary,
    binaryToBytes,
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = MIME;
  global.MIME = MIME;
})(typeof globalThis !== 'undefined' ? globalThis : this);

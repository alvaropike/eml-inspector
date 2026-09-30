/*
 * Verificación criptográfica de firmas DKIM (RFC 6376, RFC 8301, RFC 8463)
 * con WebCrypto. La clave pública se obtiene por DNS mediante el resolvedor
 * que se le pase (en el navegador, DNS-over-HTTPS).
 */
(function (global) {
  'use strict';

  const MIME = global.MIME;
  const subtle = () => (global.crypto && global.crypto.subtle) || null;

  // ---------- utilidades ----------

  function b64ToBytes(s) {
    const bin = atob(String(s).replace(/[^A-Za-z0-9+/]/g, '').replace(/^(.*?)(=*)$/, (_, a) => a + '='.repeat((4 - a.length % 4) % 4)));
    return MIME.binaryToBytes(bin);
  }

  function bytesToB64(bytes) {
    return btoa(MIME.bytesToBinary(new Uint8Array(bytes)));
  }

  function parseTags(value) {
    const tags = {};
    for (const part of value.split(';')) {
      const i = part.indexOf('=');
      if (i < 0) continue;
      const k = part.slice(0, i).replace(/\s+/g, '').toLowerCase();
      if (k) tags[k] = part.slice(i + 1).replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
    }
    return tags;
  }

  // Separa la cabecera en campos conservando el plegado original.
  function splitRawMessage(bin) {
    const crlf = bin.replace(/\r?\n/g, '\r\n');
    let end = crlf.indexOf('\r\n\r\n');
    const head = end < 0 ? crlf : crlf.slice(0, end + 2);
    const body = end < 0 ? '' : crlf.slice(end + 4);
    const fields = [];
    const lines = head.split('\r\n');
    if (lines[lines.length - 1] === '') lines.pop();
    for (const line of lines) {
      if (/^[ \t]/.test(line) && fields.length) fields[fields.length - 1].raw += '\r\n' + line;
      else if (line.indexOf(':') > 0) fields.push({ raw: line });
    }
    fields.forEach(f => { f.key = f.raw.slice(0, f.raw.indexOf(':')).trim().toLowerCase(); });
    return { fields, body };
  }

  // ---------- canonicalización ----------

  function canonHeader(raw, mode) {
    if (mode !== 'relaxed') return raw;
    const i = raw.indexOf(':');
    const name = raw.slice(0, i).replace(/[ \t]+$/, '').toLowerCase();
    const value = raw.slice(i + 1).replace(/\r\n/g, '').replace(/[ \t]+/g, ' ').replace(/^ | $/g, '');
    return name + ':' + value;
  }

  function canonBody(body, mode) {
    if (mode === 'relaxed') {
      body = body.split('\r\n').map(l => l.replace(/[ \t]+/g, ' ').replace(/ $/, '')).join('\r\n');
    }
    // Elimina las líneas vacías del final sin usar regex (cuerpos grandes).
    let end = body.length;
    while (end >= 2 && body.charCodeAt(end - 2) === 13 && body.charCodeAt(end - 1) === 10) end -= 2;
    body = body.slice(0, end);
    if (body.length) return body + '\r\n';
    return mode === 'relaxed' ? '' : '\r\n';
  }

  // Quita el valor de b= (no bh=) conservando el resto del campo tal cual.
  function stripSignature(raw) {
    return raw.replace(/([:;][ \t\r\n]*b[ \t\r\n]*=)[^;]*/, '$1');
  }

  // ---------- claves ----------

  function derLen(n) {
    if (n < 128) return [n];
    const out = [];
    while (n) { out.unshift(n & 0xff); n >>= 8; }
    return [0x80 | out.length, ...out];
  }

  // Envuelve una clave RSAPublicKey (PKCS#1) en SubjectPublicKeyInfo.
  function pkcs1ToSpki(pkcs1) {
    const algId = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    const bitStr = [0x03, ...derLen(pkcs1.length + 1), 0x00, ...pkcs1];
    const inner = [...algId, ...bitStr];
    return new Uint8Array([0x30, ...derLen(inner.length), ...inner]);
  }

  async function importKey(keyTags, algo) {
    const raw = b64ToBytes(keyTags.p);
    if (algo.sig === 'ed25519') {
      const key = await subtle().importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
      return { key, bits: 256 };
    }
    const params = { name: 'RSASSA-PKCS1-v1_5', hash: algo.hash };
    let key;
    try { key = await subtle().importKey('spki', raw, params, true, ['verify']); }
    catch (_) { key = await subtle().importKey('spki', pkcs1ToSpki(raw), params, true, ['verify']); }
    let bits = 0;
    try {
      const jwk = await subtle().exportKey('jwk', key);
      bits = Math.round(jwk.n.replace(/=+$/, '').length * 6 / 8) * 8;
      bits = Math.round(bits / 256) * 256 || bits;
    } catch (_) { /* tamaño desconocido */ }
    return { key, bits };
  }

  const ALGOS = {
    'rsa-sha256': { sig: 'rsa', hash: 'SHA-256' },
    'rsa-sha1': { sig: 'rsa', hash: 'SHA-1' },
    'ed25519-sha256': { sig: 'ed25519', hash: 'SHA-256' },
  };

  // ---------- verificación ----------

  async function verifyOne(msg, sigField, resolveTxt) {
    const tags = parseTags(sigField.raw.slice(sigField.raw.indexOf(':') + 1));
    const r = {
      domain: (tags.d || '').toLowerCase(),
      selector: tags.s || '',
      algorithm: (tags.a || '').toLowerCase(),
      canon: tags.c || 'simple/simple',
      identity: tags.i || '',
      headers: (tags.h || '').split(':').map(h => h.trim()).filter(Boolean),
      signedAt: tags.t ? new Date(+tags.t * 1000) : null,
      expires: tags.x ? new Date(+tags.x * 1000) : null,
      length: tags.l !== undefined ? +tags.l : null,
      result: 'permerror',
      reason: '',
      bodyHashOk: null,
      keyBits: 0,
      testing: false,
      keyRecord: '',
    };
    const fail = (result, reason) => Object.assign(r, { result, reason });

    if (tags.v !== '1') return fail('permerror', 'Versión DKIM no soportada (v=' + (tags.v || '') + ')');
    for (const t of ['a', 'b', 'bh', 'd', 'h', 's']) if (!tags[t]) return fail('permerror', `Falta la etiqueta obligatoria ${t}=`);
    const algo = ALGOS[r.algorithm];
    if (!algo) return fail('permerror', 'Algoritmo no soportado: ' + r.algorithm);
    if (!r.headers.some(h => h.toLowerCase() === 'from')) return fail('permerror', 'La firma no cubre la cabecera From');
    if (r.identity && !('@' + r.identity.split('@').pop().toLowerCase()).match(new RegExp('[@.]' + r.domain.replace(/\./g, '\\.') + '$'))) {
      return fail('permerror', `La identidad i=${r.identity} no pertenece al dominio d=${r.domain}`);
    }
    if (r.expires && r.expires < new Date()) r.expired = true;

    // --- DNS
    const qname = `${r.selector}._domainkey.${r.domain}`;
    let txt;
    try { txt = await resolveTxt(qname); }
    catch (e) { return fail('temperror', 'Error DNS al buscar la clave: ' + (e.message || e)); }
    if (!txt || !txt.length) return fail('permerror', `No existe la clave pública en ${qname} (rotada, eliminada o dominio falso)`);
    const record = txt.find(t => /(^|;)\s*p\s*=/.test(t)) || txt[0];
    r.keyRecord = record;
    const key = parseTags(record);
    if (key.v && key.v !== 'DKIM1') return fail('permerror', 'Registro de clave con versión inválida');
    if (!key.p) return fail('permerror', 'La clave ha sido revocada (p= vacío)');
    const kType = (key.k || 'rsa').toLowerCase();
    if ((algo.sig === 'rsa' && kType !== 'rsa') || (algo.sig === 'ed25519' && kType !== 'ed25519')) {
      return fail('permerror', `Tipo de clave k=${kType} incompatible con ${r.algorithm}`);
    }
    if (key.h && !key.h.toLowerCase().split(':').map(s => s.trim()).includes(algo.hash.toLowerCase().replace('-', ''))) {
      return fail('permerror', 'El registro no admite el hash ' + algo.hash);
    }
    const flags = (key.t || '').split(':').map(s => s.trim());
    r.testing = flags.includes('y');
    if (flags.includes('s') && r.identity) {
      const idDomain = r.identity.split('@').pop().toLowerCase();
      if (idDomain !== r.domain) return fail('permerror', 'La clave exige i= exactamente igual a d= (t=s)');
    }

    // --- Cuerpo
    const [hCanon, bCanon] = r.canon.toLowerCase().split('/').map(s => s.trim());
    const headerMode = hCanon === 'relaxed' ? 'relaxed' : 'simple';
    const bodyMode = (bCanon || 'simple') === 'relaxed' ? 'relaxed' : 'simple';
    let body = canonBody(msg.body, bodyMode);
    if (r.length !== null) {
      if (r.length > body.length) return fail('permerror', 'l= mayor que el cuerpo');
      if (r.length < body.length) r.partialBody = body.length - r.length;
      body = body.slice(0, r.length);
    }
    const bh = bytesToB64(await subtle().digest(algo.hash, MIME.binaryToBytes(body)));
    r.bodyHashOk = bh === tags.bh.replace(/\s+/g, '');
    if (!r.bodyHashOk) return fail('fail', 'El hash del cuerpo no coincide: el contenido se modificó después de firmarse');

    // --- Cabeceras firmadas
    const used = {};
    const parts = [];
    for (const name of r.headers) {
      const k = name.toLowerCase();
      const instances = msg.fields.filter(f => f.key === k && f !== sigField);
      used[k] = (used[k] || 0) + 1;
      const f = instances[instances.length - used[k]];
      if (f) parts.push(canonHeader(f.raw, headerMode) + '\r\n');
    }
    parts.push(canonHeader(stripSignature(sigField.raw), headerMode));
    let data = MIME.binaryToBytes(parts.join(''));

    let imported;
    try { imported = await importKey(key, algo); }
    catch (e) { return fail('permerror', 'Clave pública inválida o no soportada por el navegador: ' + (e.message || e.name)); }
    r.keyBits = imported.bits;
    if (algo.sig === 'rsa' && imported.bits && imported.bits < 1024) return fail('permerror', `Clave RSA demasiado corta (${imported.bits} bits)`);

    const sig = b64ToBytes(tags.b);
    let ok;
    try {
      if (algo.sig === 'ed25519') {
        data = new Uint8Array(await subtle().digest('SHA-256', data));
        ok = await subtle().verify({ name: 'Ed25519' }, imported.key, sig, data);
      } else {
        ok = await subtle().verify({ name: 'RSASSA-PKCS1-v1_5' }, imported.key, sig, data);
      }
    } catch (e) { return fail('permerror', 'Error al verificar: ' + (e.message || e.name)); }
    if (!ok) return fail('fail', 'Firma inválida: las cabeceras firmadas se modificaron o la firma no corresponde a la clave');
    r.result = 'pass';
    r.reason = r.expired ? 'Firma válida, pero caducada (x=)' : 'Firma válida';
    if (r.algorithm === 'rsa-sha1') r.reason += ' (rsa-sha1 está obsoleto, RFC 8301)';
    return r;
  }

  // skip(firma) → motivo para no verificarla (no se consulta su clave), o '' para verificarla.
  async function verifyAll(rawBinary, resolveTxt, { skip } = {}) {
    if (!subtle()) throw new Error('WebCrypto no disponible (se necesita un contexto seguro: https o localhost)');
    const msg = splitRawMessage(rawBinary);
    const sigs = msg.fields.filter(f => f.key === 'dkim-signature');
    return Promise.all(sigs.map(s => {
      const t = parseTags(s.raw.slice(s.raw.indexOf(':') + 1));
      const sig = { domain: (t.d || '').toLowerCase(), selector: t.s || '', algorithm: (t.a || '').toLowerCase(), canon: t.c || 'simple/simple' };
      const why = skip && skip(sig);
      return why ? Object.assign(sig, { result: 'skipped', reason: why }) : verifyOne(msg, s, resolveTxt);
    }).map(p => Promise.resolve(p).catch(e => ({
      domain: '', selector: '', result: 'permerror', reason: 'Error inesperado: ' + (e.message || e),
    }))));
  }

  const DKIM = { verifyAll, canonBody, canonHeader, splitRawMessage, stripSignature, parseTags };
  if (typeof module !== 'undefined' && module.exports) module.exports = DKIM;
  global.DKIM = DKIM;
})(typeof globalThis !== 'undefined' ? globalThis : this);

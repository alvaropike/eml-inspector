/*
 * Busca códigos QR en las imágenes del correo (quishing). Usa BarcodeDetector
 * si el navegador lo ofrece y, si no, jsQR (js/vendor/jsQR.js) cargado bajo demanda.
 */
(function (global) {
  'use strict';

  const MAX_BYTES = 15 * 1024 * 1024;
  const MAX_SIDE = 1600;
  let jsqrLoading = null;

  function loadJsQR() {
    if (global.jsQR) return Promise.resolve(global.jsQR);
    if (!jsqrLoading) {
      jsqrLoading = new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'js/vendor/jsQR.js';
        s.onload = () => resolve(global.jsQR);
        s.onerror = () => { jsqrLoading = null; reject(new Error('No se pudo cargar jsQR')); };
        document.head.appendChild(s);
      });
    }
    return jsqrLoading;
  }

  let detector;
  async function nativeDetector() {
    if (detector !== undefined) return detector;
    detector = null;
    try {
      if ('BarcodeDetector' in global && (await BarcodeDetector.getSupportedFormats()).includes('qr_code')) {
        detector = new BarcodeDetector({ formats: ['qr_code'] });
      }
    } catch (_) { detector = null; }
    return detector;
  }

  async function decodeImage(bytes, type) {
    const bmp = await createImageBitmap(new Blob([bytes], { type: type || 'image/png' }));
    try {
      const det = await nativeDetector();
      if (det) {
        const found = await det.detect(bmp);
        if (found.length) return found.map(f => f.rawValue);
      }
      const jsQR = await loadJsQR();
      const scale = Math.min(1, MAX_SIDE / Math.max(bmp.width, bmp.height));
      const w = Math.max(1, Math.round(bmp.width * scale)), h = Math.max(1, Math.round(bmp.height * scale));
      const canvas = typeof OffscreenCanvas !== 'undefined' ? new OffscreenCanvas(w, h) : Object.assign(document.createElement('canvas'), { width: w, height: h });
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.fillStyle = '#fff';
      ctx.fillRect(0, 0, w, h);
      ctx.drawImage(bmp, 0, 0, w, h);
      const code = jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'attemptBoth' });
      return code && code.data ? [code.data] : [];
    } finally {
      bmp.close && bmp.close();
    }
  }

  // Devuelve [{attachment, text}] para cada QR encontrado en imágenes adjuntas o incrustadas.
  async function scan(attachments) {
    const out = [];
    for (const a of attachments) {
      const isImage = /^image\/(png|jpe?g|gif|webp|bmp)$/.test(a.contentType) || ['PNG', 'JPEG', 'GIF'].includes(a.magic);
      if (!isImage || a.size > MAX_BYTES || a.size < 60) continue;
      try {
        const texts = await decodeImage(global.MIME.getBytes(a.node), a.contentType.startsWith('image/') ? a.contentType : '');
        texts.forEach(text => out.push({ attachment: a, text }));
      } catch (_) { /* imagen no decodificable */ }
    }
    return out;
  }

  global.QR = { scan, decodeImage };
})(typeof globalThis !== 'undefined' ? globalThis : this);

/*
 * Buzón de análisis: quien escribe a eml@eml.alvaropiquerastrenado.com con un correo adjunto
 * (.eml, .msg o «reenviar como adjunto») recibe el informe como respuesta.
 *
 * El correo llega por Cloudflare Email Routing y se contesta con message.reply(), que sólo
 * responde al remitente real del sobre y exige que su correo pase DMARC: nadie puede usar el
 * buzón para que llegue un informe a un tercero. No se guarda nada.
 */
import { EmailMessage } from 'cloudflare:email';
import { AsyncLocalStorage } from 'node:async_hooks';
import { emailAttachments, analyzeEmail, Online } from './core.js';
import { buildReport, helpReport } from './report.js';
import { buildMime } from './mime-out.js';

const MAX_EMAILS = 3;          // correos adjuntos que se analizan por mensaje
// El plan gratuito de Workers admite 50 subpeticiones por ejecución; se reservan unas pocas.
const SUBREQUEST_BUDGET = 45;
const MAX_LINK_DOMAINS = 4;     // dominios de enlaces que se consultan (en la web, 15)

// En un Worker, 1.1.1.2 se consulta por nombre: una petición por dominio en lugar de dos.
Online.setSecurityURLs(['https://security.cloudflare-dns.com/dns-query']);

// Todas las consultas de online.js y safebrowsing.js pasan por aquí: se cuentan por correo
// recibido y se quitan las opciones de fetch propias del navegador.
const budget = new AsyncLocalStorage();
const nativeFetch = globalThis.fetch;
globalThis.fetch = function (input, init) {
  const b = budget.getStore();
  if (b) {
    if (b.used >= b.max) { b.skipped++; return Promise.reject(new Error('límite de consultas del buzón')); }
    b.used++;
  }
  if (init) {
    init = Object.assign({}, init);
    delete init.credentials;
    delete init.referrerPolicy;
    delete init.mode;
  }
  return nativeFetch(input, init);
};

// Respuestas automáticas, rebotes y listas de correo: no se contestan, para no crear bucles.
function isAutomated(message, self) {
  const h = message.headers;
  const from = (message.from || '').toLowerCase();
  if (!from || from === self) return true;
  if (/^(mailer-daemon|postmaster|no-?reply|do-?not-?reply|bounces?)([+-][^@]*)?@/.test(from)) return true;
  const auto = (h.get('auto-submitted') || '').trim().toLowerCase();
  if (auto && auto !== 'no') return true;
  if (/^(bulk|junk|list|auto_reply)$/i.test((h.get('precedence') || '').trim())) return true;
  return h.has('list-id') || h.has('list-unsubscribe') || h.has('x-autoreply') || h.has('x-autorespond');
}

export default {
  async email(message, env, ctx) {
    const self = String(message.to || '').toLowerCase();
    if (isAutomated(message, self)) {
      console.log(JSON.stringify({ event: 'ignored', reason: 'automated' }));
      return;
    }
    if (message.rawSize > 25 * 1024 * 1024) {
      message.setReject('Mensaje demasiado grande para analizarlo (máximo 25 MB)');
      return;
    }
    if (env.PER_SENDER) {
      const { success } = await env.PER_SENDER.limit({ key: message.from.toLowerCase() });
      if (!success) {
        message.setReject('Demasiados análisis seguidos: espera un minuto y vuelve a intentarlo');
        return;
      }
    }

    const started = Date.now();
    const raw = new Uint8Array(await new Response(message.raw).arrayBuffer());
    const site = env.SITE_URL;
    let report, stats = null, found = [];
    try {
      found = emailAttachments(raw);
    } catch (e) {
      console.log(JSON.stringify({ event: 'parse-error', error: e.message }));
    }
    if (!found.length) {
      report = helpReport({ site, address: self });
    } else {
      const items = [];
      stats = { used: 0, max: SUBREQUEST_BUDGET, skipped: 0 };
      await budget.run(stats, async () => {
        for (const f of found.slice(0, MAX_EMAILS)) {
          try {
            const entry = await analyzeEmail(f.bytes, f.name, { safeBrowsingProxy: env.SB_PROXY, maxLinkDomains: MAX_LINK_DOMAINS });
            items.push({ name: f.name, entry });
          } catch (e) {
            items.push({ name: f.name, error: e.message });
          }
        }
      });
      report = buildReport(items, { site, stats, extra: Math.max(0, found.length - MAX_EMAILS) });
    }

    // message.reply() no admite como remitente una dirección de un subdominio (fallo conocido de
    // Cloudflare: «mail from is not from the correct domain»), así que se contesta desde el dominio
    // principal y las respuestas al informe vuelven al buzón de análisis.
    const replyFrom = env.REPLY_FROM || self;
    const mime = buildMime({
      from: replyFrom,
      fromName: 'EML Inspector',
      replyTo: replyFrom !== self ? self : '',
      to: message.from,
      subject: report.subject,
      text: report.text,
      html: report.html,
      inReplyTo: message.headers.get('message-id'),
      references: message.headers.get('references'),
    });
    // Sólo métricas: nada del contenido ni de las direcciones.
    console.log(JSON.stringify({ event: 'report', emails: found.length, subrequests: stats && stats.used, skipped: stats && stats.skipped, ms: Date.now() - started }));
    try {
      await message.reply(new EmailMessage(replyFrom, message.from, mime));
    } catch (e) {
      // Suele ser que el correo recibido no pasa DMARC: no se puede contestar.
      console.log(JSON.stringify({ event: 'reply-error', error: e.message }));
    }
  },
};

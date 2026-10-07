const path = require('path');
const fs = require('fs');
const logger = require('./logger');

// baileys is an ESM-only package — this file stays CommonJS like the rest of
// the API, so the module is loaded with a dynamic import() instead of require().
const AUTH_FOLDER = path.join(__dirname, '..', 'baileys_auth');
const QR_FILE = path.join(__dirname, '..', 'whatsapp-qr.png');

let sock = null;
let isReady = false;
let starting = null;

// Baileys requires a pino-shaped logger (level + child() + trace/debug/info/
// warn/error). trace/debug/info are no-ops here — Baileys logs every socket
// frame at those levels, which would flood the app's real logs — only
// warnings/errors are forwarded to the existing winston logger.
const waLogger = {
  level: 'warn',
  child() { return waLogger; },
  trace() {}, debug() {}, info() {},
  warn:  (obj, msg) => logger.warn(`[WHATSAPP] ${msg || ''} ${JSON.stringify(obj)}`),
  error: (obj, msg) => logger.error(`[WHATSAPP] ${msg || ''} ${JSON.stringify(obj)}`),
};

// Same E.164 South African normalisation as lib/sms.js, so a phone number
// stored any way a user might have typed it (071..., 27071..., +27071...)
// resolves to the same WhatsApp JID.
function toJid(phone) {
  const cleaned = String(phone).replace(/\D/g, '');
  const e164digits = cleaned.startsWith('27') ? cleaned
    : cleaned.startsWith('0') ? `27${cleaned.slice(1)}`
    : cleaned;
  return `${e164digits}@s.whatsapp.net`;
}

async function initWhatsApp() {
  if (process.env.WHATSAPP_ENABLED !== 'true') {
    logger.info('[WHATSAPP] Disabled (set WHATSAPP_ENABLED=true to enable).');
    return;
  }
  if (starting) return starting;

  starting = (async () => {
    const {
      default: makeWASocket,
      useMultiFileAuthState,
      fetchLatestBaileysVersion,
      DisconnectReason,
    } = await import('baileys');
    const qrTerminal = require('qrcode-terminal');
    const qrImage = require('qrcode');

    const { state, saveCreds } = await useMultiFileAuthState(AUTH_FOLDER);
    const { version } = await fetchLatestBaileysVersion();

    sock = makeWASocket({ version, auth: state, logger: waLogger });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', (update) => {
      const { connection, lastDisconnect, qr } = update;

      if (qr) {
        qrTerminal.generate(qr, { small: true });
        qrImage.toFile(QR_FILE, qr, { width: 500 })
          .then(() => logger.info(`[WHATSAPP] QR code saved to ${QR_FILE} — open it and scan with the salon WhatsApp (Linked Devices → Link a Device). Expires in ~60s; a fresh one is written automatically if it does.`))
          .catch(err => logger.error(`[WHATSAPP] Failed to write QR image: ${err.message}`));
      }

      if (connection === 'open') {
        isReady = true;
        logger.info('[WHATSAPP] Connected.');
        fs.unlink(QR_FILE, () => {}); // best-effort cleanup, QR is no longer valid anyway
      }

      if (connection === 'close') {
        isReady = false;
        const statusCode = lastDisconnect?.error?.output?.statusCode;
        const loggedOut  = statusCode === DisconnectReason.loggedOut;
        logger.warn(`[WHATSAPP] Connection closed (code ${statusCode}). ${loggedOut ? 'Logged out — delete baileys_auth/ and restart to re-link.' : 'Reconnecting…'}`);
        if (!loggedOut) {
          starting = null;
          initWhatsApp();
        }
      }
    });
  })();

  return starting;
}

// Never throws — a WhatsApp outage must not break a booking/payment flow.
// Mirrors lib/sms.js's graceful-degradation shape: { sent, reason? }.
async function sendWhatsAppMessage(phone, message) {
  if (!phone) return { sent: false, reason: 'no_phone' };
  if (!sock || !isReady) {
    logger.warn('[WHATSAPP] Not connected — message not sent.');
    return { sent: false, reason: 'not_connected' };
  }
  try {
    const jid = toJid(phone);
    await sock.sendMessage(jid, { text: message });
    logger.info(`[WHATSAPP] Sent to ${jid}`);
    return { sent: true };
  } catch (err) {
    logger.error(`[WHATSAPP] Send failed: ${err.message}`);
    return { sent: false, reason: err.message };
  }
}

module.exports = { initWhatsApp, sendWhatsAppMessage };

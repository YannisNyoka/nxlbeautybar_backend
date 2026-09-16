const fetchFn = require('./fetchPolyfill');
const logger = require('./logger');

async function sendSMS(phone, message) {
  const cleaned = phone.replace(/\D/g, '');
  // Normalise to E.164 South African format
  const e164 = cleaned.startsWith('27') ? `+${cleaned}`
    : cleaned.startsWith('0') ? `+27${cleaned.slice(1)}`
    : `+${cleaned}`;

  if (process.env.AT_API_KEY && process.env.AT_USERNAME) {
    try {
      const params = new URLSearchParams({
        username: process.env.AT_USERNAME,
        to:       e164,
        message,
        from:     process.env.AT_SENDER_ID || 'NXLBeauty',
      });
      const resp = await fetchFn('https://api.africastalking.com/version1/messaging', {
        method:  'POST',
        headers: {
          'apiKey':       process.env.AT_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept':       'application/json',
        },
        body: params.toString(),
      });
      const data = await resp.json();
      const status = data?.SMSMessageData?.Recipients?.[0]?.status;
      logger.info(`[SMS] Sent to ${e164}: ${status}`);
      return { sent: true, status, provider: 'africastalking' };
    } catch (smsErr) {
      logger.error(`[SMS] Africa's Talking failed: ${smsErr.message}`);
    }
  }

  // Fallback — log WhatsApp link
  const waText = encodeURIComponent(message);
  const waUrl  = `https://wa.me/${e164.replace('+','')}?text=${waText}`;
  logger.info(`[SMS FALLBACK] No AT credentials — wa.me link: ${waUrl}`);
  return { sent: false, waUrl, provider: 'fallback' };
}

module.exports = sendSMS;

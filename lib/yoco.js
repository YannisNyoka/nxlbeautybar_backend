const fetchFn = require('./fetchPolyfill');
const logger = require('./logger');

async function verifyYocoCheckout(checkoutId) {
  if (!checkoutId) return { verified:false, status:'no_checkout_id' };
  try {
    const resp = await fetchFn(`https://payments.yoco.com/api/checkouts/${checkoutId}`, {
      headers: { 'Authorization': `Bearer ${process.env.YOCO_SECRET_KEY}` },
    });
    if (!resp.ok) { logger.error('Yoco checkout lookup failed', { checkoutId, status:resp.status }); return { verified:false, status:'lookup_failed' }; }
    const data = await resp.json();
    return { verified: data.status === 'completed', status: data.status };
  } catch (err) {
    logger.error('Yoco checkout verification error', { checkoutId, error:err.message });
    return { verified:false, status:'error' };
  }
}

module.exports = { verifyYocoCheckout };

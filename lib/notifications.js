const { ObjectId } = require('mongodb');
const logger = require('./logger');

const NOTIF_ICONS = {
  booking_confirmed:  '📅',
  booking_cancelled:  '❌',
  booking_reminder:   '⏰',
  order_confirmed:    '🛒',
  order_shipped:      '🚚',
  order_ready:        '🏪',
  order_delivered:    '✅',
  loyalty_earned:     '⭐',
  loyalty_redeemed:   '🎁',
  loyalty_tier_up:    '🏆',
  gift_card_received: '🎁',
  promotion:          '🎉',
  system:             '💡',
};

// Factory: db isn't available until MongoClient.connect() resolves, so this
// is bound once in server.js right after `db = client.db(dbName)`, and the
// returned notifyClient is reused everywhere (identical to how the inline
// closure worked before this was extracted).
function createNotifier(db) {
  // Helper: create a client notification
  async function notifyClient(userId, { type, title, body, link = null, meta = {} }) {
    try {
      await db.collection('CLIENT_NOTIFICATIONS').insertOne({
        userId: typeof userId === 'string' ? new ObjectId(userId) : userId,
        type, title, body,
        icon:  NOTIF_ICONS[type] || '🔔',
        link,  meta,
        read:  false, readAt: null,
        createdAt: new Date(),
      });
    } catch (err) {
      logger.error(`[CLIENT NOTIF] Failed to create notification: ${err.message}`);
    }
  }

  return { NOTIF_ICONS, notifyClient };
}

module.exports = createNotifier;

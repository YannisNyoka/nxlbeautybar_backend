const { ObjectId } = require('mongodb');
const logger = require('./logger');

const LOYALTY_CONFIG = {
  pointsPerRand:      1,      // 1 point per R1 spent on bookings only
  bookingBonus:       0,      // no extra bonus per booking
  signupBonus:        0,      // no welcome points on registration
  pointValue:         0.10,   // 1 point = R0.10 discount (100 pts = R10)
  minRedemption:      100,    // minimum points to redeem
  maxRedemptionPct:   50,     // max % of order value that can be paid with points
};

// Factory: db isn't available until MongoClient.connect() resolves, so this
// is bound once in server.js right after `db = client.db(dbName)`.
// notifyClient is injected (rather than required from ./notifications here)
// so there's a single bound instance shared with the rest of the app, and
// no require cycle between the loyalty/notifications modules.
function createLoyaltyHelpers(db, notifyClient) {
  // ── Helper: get or create loyalty account ─────────────────────────────
  async function getLoyaltyAccount(userId) {
    // Ensure userId is ObjectId
    if (typeof userId === 'string') userId = new ObjectId(userId);

    let account = await db.collection('LOYALTY').findOne({ userId });
    if (!account) {
      const now = new Date();
      const res = await db.collection('LOYALTY').insertOne({
        userId, points: 0, totalEarned: 0, totalRedeemed: 0,
        tier: 'bronze', createdAt: now, updatedAt: now,
      });
      account = { _id: res.insertedId, userId, points: 0, totalEarned: 0, totalRedeemed: 0, tier: 'bronze' };
    }
    return account;
  }

  // ── Helper: calculate tier ─────────────────────────────────────────────
  function calcTier(totalEarned) {
    if (totalEarned >= 5000) return 'platinum';
    if (totalEarned >= 2000) return 'gold';
    if (totalEarned >= 500)  return 'silver';
    return 'bronze';
  }

  // ── Helper: award points ───────────────────────────────────────────────
  async function awardPoints(userId, points, reason, referenceId = null) {
    if (points <= 0) return;

    // Ensure userId is ObjectId
    if (typeof userId === 'string') userId = new ObjectId(userId);

    const now = new Date();
    await db.collection('LOYALTY_TRANSACTIONS').insertOne({
      userId, points, type: 'earn', reason, referenceId, createdAt: now,
    });
    const account = await getLoyaltyAccount(userId);
    const newTotal = account.totalEarned + points;
    const oldTier  = account.tier;
    const newTier  = calcTier(newTotal);
    await db.collection('LOYALTY').updateOne(
      { userId },
      { $inc: { points, totalEarned: points }, $set: { tier: newTier, updatedAt: now } }
    );
    logger.info(`[LOYALTY] +${points} pts to user ${userId} — ${reason}`);

    // Tier-up notification
    if (newTier !== oldTier) {
      const tierEmojis = { silver:'🥈', gold:'🥇', platinum:'💎' };
      await notifyClient(userId, {
        type:  'loyalty_tier_up',
        title: `You've reached ${newTier.charAt(0).toUpperCase() + newTier.slice(1)} tier! ${tierEmojis[newTier]||'🏆'}`,
        body:  `Congratulations! You've unlocked ${newTier} member status. Keep earning points for exclusive perks.`,
        link:  '/profile',
        meta:  { tier: newTier },
      });
    }
  }

  // ── Helper: redeem points ──────────────────────────────────────────────
  async function redeemPoints(userId, points, reason, referenceId = null) {
    if (points <= 0) return;

    // Ensure userId is ObjectId
    if (typeof userId === 'string') userId = new ObjectId(userId);

    const now = new Date();
    await db.collection('LOYALTY_TRANSACTIONS').insertOne({
      userId, points: -points, type: 'redeem', reason, referenceId, createdAt: now,
    });
    await db.collection('LOYALTY').updateOne(
      { userId },
      { $inc: { points: -points, totalRedeemed: points }, $set: { updatedAt: now } }
    );
    logger.info(`[LOYALTY] -${points} pts from user ${userId} — ${reason}`);
  }

  return { LOYALTY_CONFIG, getLoyaltyAccount, calcTier, awardPoints, redeemPoints };
}

module.exports = createLoyaltyHelpers;

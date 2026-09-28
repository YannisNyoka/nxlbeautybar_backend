const DAY_KEYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

const DEFAULT_WEEKLY_HOURS = Object.fromEntries(
  DAY_KEYS.map(day => [day, { open: '07:00', close: '18:00', closed: false }])
);

// SALON_SETTINGS is a singleton — exactly one document. Created with sensible
// defaults (matching the app's previous hardcoded 07:00-18:00, every day
// open) the first time anything asks for it, so behavior is unchanged until
// an admin actually edits it.
async function getSalonSettings(db) {
  let doc = await db.collection('SALON_SETTINGS').findOne({});
  if (!doc) {
    const fresh = { weeklyHours: DEFAULT_WEEKLY_HOURS, updatedAt: new Date() };
    const result = await db.collection('SALON_SETTINGS').insertOne(fresh);
    doc = { _id: result.insertedId, ...fresh };
  }
  return doc;
}

function getDayKey(dateISO) {
  return DAY_KEYS[new Date(dateISO + 'T00:00:00').getDay()];
}

// Returns { open, close, closed } for the given date, using the default
// hours for that weekday if weeklyHours is missing/incomplete for some reason.
function getHoursForDate(weeklyHours, dateISO) {
  const key = getDayKey(dateISO);
  return (weeklyHours && weeklyHours[key]) || DEFAULT_WEEKLY_HOURS[key];
}

module.exports = { DAY_KEYS, DEFAULT_WEEKLY_HOURS, getSalonSettings, getDayKey, getHoursForDate };

const { ObjectId } = require('mongodb');
const { generateSlotRange } = require('./dateTime');

// Returns { 'YYYY-MM-DD': ['HH:MM', ...] } of every slot that's unavailable
// (admin-blocked or occupied by a booked/pending appointment) between
// startDate and endDate inclusive, for the given employee ('any' = all staff).
// Deliberately returns only bare time strings — no client names, phone
// numbers, or other appointment data — so it's safe to expose to anyone,
// including customers who aren't the owner of the appointment.
async function getOccupiedSlotsMap(db, startDate, endDate, employeeId) {
  const isAny = employeeId === 'any' || !employeeId;
  let empObjectId = null;
  if (!isAny) empObjectId = new ObjectId(employeeId);

  const dateRange = { $gte: startDate, $lte: endDate };
  const blockedQuery = isAny
    ? { date: dateRange }
    : { date: dateRange, $or: [{ employeeId: empObjectId }, { employeeId: 'ALL' }] };
  const blocked = await db.collection('AVAILABILITY').find(blockedQuery).project({ date:1, time:1 }).toArray();

  const apptQuery = { date: dateRange, status: { $in: ['booked', 'pending'] }, ...(isAny ? {} : { employeeId: empObjectId }) };
  const bookedAppts = await db.collection('APPOINTMENTS').find(apptQuery).project({ date:1, time:1, occupiedSlots:1, serviceIds:1 }).toArray();

  // Expand each appointment to every slot it occupies. Bookings made through
  // the staff/admin flow store `occupiedSlots`; guest bookings don't, so
  // fall back to deriving the range from service durations — otherwise a
  // multi-slot appointment (e.g. a 45-min service spanning two 30-min slots)
  // only shows its start time as taken.
  const needDurationIds = [...new Set(
    bookedAppts.filter(a => !(Array.isArray(a.occupiedSlots) && a.occupiedSlots.length))
               .flatMap(a => a.serviceIds || []).map(String)
  )];
  const svcMap = needDurationIds.length
    ? Object.fromEntries((await db.collection('SERVICES')
        .find({ _id: { $in: needDurationIds.map(id => new ObjectId(id)) } })
        .project({ durationMinutes:1 }).toArray())
        .map(s => [String(s._id), s.durationMinutes]))
    : {};

  const map = {};
  const addTime = (date, time) => { if (!map[date]) map[date] = new Set(); map[date].add(time); };
  blocked.forEach(b => addTime(b.date, b.time));
  bookedAppts.forEach(a => {
    const times = (Array.isArray(a.occupiedSlots) && a.occupiedSlots.length)
      ? a.occupiedSlots
      : generateSlotRange(a.time, (a.serviceIds || []).reduce((sum, id) => sum + (svcMap[String(id)] || 30), 0) || 30);
    times.forEach(t => addTime(a.date, t));
  });

  const result = {};
  for (const [date, set] of Object.entries(map)) result[date] = [...set];
  return result;
}

module.exports = getOccupiedSlotsMap;

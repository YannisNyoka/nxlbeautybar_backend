function pad2(n) { return String(n).padStart(2, '0'); }

function normalizeTimeTo24h(timeRaw) {
  if (typeof timeRaw !== 'string') return null;
  const t = timeRaw.trim();
  if (/^\d{2}:\d{2}$/.test(t)) return t;
  const m = t.match(/^(\d{1,2}):(\d{2})\s*(am|pm)$/i);
  if (!m) return null;
  let hh = parseInt(m[1], 10);
  const mm = parseInt(m[2], 10);
  const ampm = m[3].toLowerCase();
  if (hh < 1 || hh > 12 || mm < 0 || mm > 59) return null;
  if (ampm === 'am') { if (hh === 12) hh = 0; } else { if (hh !== 12) hh += 12; }
  return `${pad2(hh)}:${pad2(mm)}`;
}

function normalizeDateToISO(dateRaw) {
  if (typeof dateRaw !== 'string') return null;
  const d = dateRaw.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(d)) return d;
  {
    const m = d.replace(/,/g, ' ').replace(/\s+/g, ' ').match(/^([A-Za-z]+)\s+(\d{1,2}|\d{4})\s+(\d{1,2}|\d{4})$/);
    if (m) {
      const monthName = m[1].toLowerCase();
      const a = m[2]; const b = m[3];
      const months = { jan:0,january:0,feb:1,february:1,mar:2,march:2,apr:3,april:3,may:4,jun:5,june:5,jul:6,july:6,aug:7,august:7,sep:8,sept:8,september:8,oct:9,october:9,nov:10,november:10,dec:11,december:11 };
      const monthIdx = months[monthName];
      if (monthIdx !== undefined) {
        const aIsYear = /^\d{4}$/.test(a); const bIsYear = /^\d{4}$/.test(b);
        let year = null; let day = null;
        if (aIsYear && !bIsYear) { year = parseInt(a, 10); day = parseInt(b, 10); }
        else if (bIsYear && !aIsYear) { year = parseInt(b, 10); day = parseInt(a, 10); }
        if (year && day && day >= 1 && day <= 31) {
          const parsed = new Date(year, monthIdx, day);
          return `${parsed.getFullYear()}-${pad2(parsed.getMonth()+1)}-${pad2(parsed.getDate())}`;
        }
      }
    }
  }
  const parsed = new Date(d);
  if (Number.isNaN(parsed.getTime())) return null;
  return `${parsed.getFullYear()}-${pad2(parsed.getMonth()+1)}-${pad2(parsed.getDate())}`;
}

function normalizeAppointmentDateTime(dateRaw, timeRaw) {
  const date = normalizeDateToISO(dateRaw);
  const time = normalizeTimeTo24h(timeRaw);
  if (!date || !time) return null;
  return { date, time };
}

function generateSlotRange(startTime, totalMinutes) {
  const slots = [];
  let [h, m] = startTime.split(':').map(Number);
  const count = Math.ceil(totalMinutes / 30);
  for (let i = 0; i < count; i++) {
    slots.push(`${pad2(h)}:${pad2(m)}`);
    m += 30;
    if (m >= 60) { h += 1; m -= 60; }
  }
  return slots;
}

module.exports = { pad2, normalizeTimeTo24h, normalizeDateToISO, normalizeAppointmentDateTime, generateSlotRange };

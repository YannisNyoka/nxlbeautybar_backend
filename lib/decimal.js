function decimalToNumber(v) {
  if (v == null) return null;
  if (typeof v === 'number') return v;
  if (typeof v === 'object' && typeof v.toString === 'function') { const n = Number(v.toString()); return Number.isFinite(n) ? n : null; }
  const n = Number(String(v));
  return Number.isFinite(n) ? n : null;
}

module.exports = decimalToNumber;

function sanitiseText(val, maxLen = 1000) {
  if (typeof val !== 'string') return '';
  return val
    .replace(/<[^>]*>/g, '')        // strip HTML tags
    .replace(/javascript:/gi, '')   // strip JS protocol
    .replace(/on\w+\s*=/gi, '')     // strip inline event handlers
    .trim()
    .slice(0, maxLen);
}

module.exports = sanitiseText;

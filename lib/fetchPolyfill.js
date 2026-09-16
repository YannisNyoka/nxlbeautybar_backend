let fetchFn;
try {
  fetchFn = fetch;
} catch {
  fetchFn = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
}

module.exports = fetchFn;

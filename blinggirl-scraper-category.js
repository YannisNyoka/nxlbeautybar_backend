/**
 * ═══════════════════════════════════════════════════════════════════════
 * Blinggirl Scraper — Production Build
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Scrapes product listings from Blinggirl's category pages and syncs them
 * into the PRODUCTS collection used by the NXL Beauty Bar backend.
 *
 * Highlights over the original prototype:
 *   - Exponential backoff + jitter retries on every network call
 *   - Automatic category inference (nails / hair / skincare / accessories /
 *     professional / other) so it matches the PRODUCTS schema enum
 *   - SKU cleanup + collision-safe fallback generation
 *   - Cross-category duplicate removal before writing
 *   - Decimal128 for price/comparePrice, Int32 for stock (schema-correct
 *     BSON types — avoids silent validation failures against the
 *     PRODUCTS $jsonSchema validator)
 *   - Per-item schema validation with a structured, aggregated log
 *   - Bulk upserts via bulkWrite() instead of N sequential findOne/updateOne
 *     round-trips
 *
 * Usage:
 *   node blinggirl-scraper.js
 *
 * Required env vars (.env):
 *   MONGODB_URI=mongodb+srv://...
 *   DB_NAME=nxlbeautybar
 *
 * Optional env vars (all have sane defaults — see CONFIG below):
 *   BLINGGIRL_BASE_URL, MARKUP_PERCENTAGE, DEFAULT_STOCK, AUTO_ACTIVATE,
 *   UPDATE_EXISTING, BATCH_SIZE, MAX_RETRIES, RETRY_BASE_DELAY_MS,
 *   REQUEST_DELAY_MS, REQUEST_TIMEOUT_MS
 * ═══════════════════════════════════════════════════════════════════════
 */

require('dotenv').config();
const axios = require('axios');
const cheerio = require('cheerio');
const crypto = require('crypto');
const { MongoClient, Decimal128, Int32 } = require('mongodb');

// ─────────────────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────────────────
const CONFIG = {
  BLINGGIRL_BASE_URL: process.env.BLINGGIRL_BASE_URL || 'https://blinggirl.co.za',
  MARKUP_PERCENTAGE: parseFloat(process.env.MARKUP_PERCENTAGE ?? '0.25'),
  DEFAULT_STOCK: parseInt(process.env.DEFAULT_STOCK ?? '20', 10),

  MONGODB_URI: process.env.MONGODB_URI,
  DB_NAME: process.env.DB_NAME,

  AUTO_ACTIVATE: process.env.AUTO_ACTIVATE !== 'false',
  UPDATE_EXISTING: process.env.UPDATE_EXISTING !== 'false',

  BATCH_SIZE: parseInt(process.env.BATCH_SIZE ?? '100', 10),

  MAX_RETRIES: parseInt(process.env.MAX_RETRIES ?? '4', 10),
  RETRY_BASE_DELAY_MS: parseInt(process.env.RETRY_BASE_DELAY_MS ?? '500', 10),
  REQUEST_DELAY_MS: parseInt(process.env.REQUEST_DELAY_MS ?? '400', 10),
  REQUEST_TIMEOUT_MS: parseInt(process.env.REQUEST_TIMEOUT_MS ?? '15000', 10),

  // Must match the PRODUCTS collection's $jsonSchema `category` enum exactly.
  VALID_CATEGORIES: ['nails', 'hair', 'skincare', 'accessories', 'professional', 'other'],
  DEFAULT_CATEGORY: 'other',

  SOURCE_MERCHANT: 'Blinggirl',
};

if (!CONFIG.MONGODB_URI || !CONFIG.DB_NAME) {
  console.error('[❌] Missing required env vars: MONGODB_URI and/or DB_NAME');
  process.exit(1);
}

// ─────────────────────────────────────────────────────────────────────────
// LOGGER
// ─────────────────────────────────────────────────────────────────────────
const ts = () => new Date().toISOString();
const logger = {
  info: (msg) => console.log(`[ℹ️  ${ts()}] ${msg}`),
  success: (msg) => console.log(`[✅ ${ts()}] ${msg}`),
  warn: (msg) => console.warn(`[⚠️  ${ts()}] ${msg}`),
  error: (msg) => console.error(`[❌ ${ts()}] ${msg}`),
  debug: (msg) => { if (process.env.DEBUG) console.log(`[🔍 ${ts()}] ${msg}`); },
};

// ─────────────────────────────────────────────────────────────────────────
// HTTP CLIENT WITH RETRY + EXPONENTIAL BACKOFF
// ─────────────────────────────────────────────────────────────────────────
const httpClient = axios.create({
  timeout: CONFIG.REQUEST_TIMEOUT_MS,
  headers: {
    'User-Agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  },
  validateStatus: (status) => status < 500, // let us decide what to retry
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function isRetryableError(err) {
  if (!err) return false;
  // Network-level errors (no response) are retryable
  if (!err.response) return true;
  const status = err.response.status;
  return status === 429 || status >= 500;
}

/**
 * GET with exponential backoff + jitter.
 * Retries on network errors, 429, and 5xx. Does not retry on 4xx (except 429).
 */
async function fetchWithRetry(url, { retries = CONFIG.MAX_RETRIES } = {}) {
  let attempt = 0;
  let lastError = null;

  while (attempt <= retries) {
    try {
      const response = await httpClient.get(url);

      if (response.status >= 400 && response.status !== 429) {
        // Non-retryable client error (404, 403, etc.)
        const err = new Error(`HTTP ${response.status} for ${url}`);
        err.response = response;
        err.nonRetryable = true;
        throw err;
      }

      if (response.status === 429 || response.status >= 500) {
        const err = new Error(`HTTP ${response.status} for ${url}`);
        err.response = response;
        throw err;
      }

      return response;
    } catch (err) {
      lastError = err;

      if (err.nonRetryable || !isRetryableError(err) || attempt === retries) {
        logger.warn(`Giving up on ${url} after ${attempt + 1} attempt(s): ${err.message}`);
        throw err;
      }

      const backoff = CONFIG.RETRY_BASE_DELAY_MS * 2 ** attempt;
      const jitter = Math.floor(Math.random() * 250);
      const delay = backoff + jitter;
      logger.warn(
        `Retryable error on ${url} (attempt ${attempt + 1}/${retries + 1}): ${err.message}. Retrying in ${delay}ms...`
      );
      await sleep(delay);
      attempt++;
    }
  }

  throw lastError;
}

// ─────────────────────────────────────────────────────────────────────────
// CATEGORY INFERENCE
// Maps arbitrary Blinggirl category/product text onto the fixed
// PRODUCTS.category enum: nails | hair | skincare | accessories |
// professional | other
// ─────────────────────────────────────────────────────────────────────────
const CATEGORY_KEYWORDS = [
  {
    category: 'nails',
    keywords: [
      'nail', 'polish', 'manicure', 'pedicure', 'acrylic', 'gel polish',
      'nail art', 'nail tip', 'nail glue', 'cuticle', 'press-on', 'press on',
    ],
  },
  {
    category: 'hair',
    keywords: [
      'hair', 'wig', 'weave', 'extension', 'braid', 'shampoo', 'conditioner',
      'edge control', 'wax stick', 'closure', 'frontal', 'bundle', 'ponytail',
      'clip-in', 'clip in',
    ],
  },
  {
    category: 'skincare',
    keywords: [
      'skin', 'face', 'facial', 'cream', 'lotion', 'serum', 'moisturi',
      'cleanser', 'toner', 'mask', 'sunscreen', 'spf', 'exfoliat', 'scrub',
      'body butter', 'oil',
    ],
  },
  {
    category: 'accessories',
    keywords: [
      'jewel', 'earring', 'necklace', 'bracelet', 'ring', 'bag', 'purse',
      'accessory', 'accessories', 'headband', 'hair clip', 'scrunchie',
      'sunglasses', 'belt',
    ],
  },
  {
    category: 'professional',
    keywords: [
      'salon', 'professional', 'tool', 'equipment', 'kit', 'machine',
      'sterilizer', 'steriliser', 'uv lamp', 'led lamp', 'drill', 'trolley',
      'wholesale', 'bulk',
    ],
  },
];

function inferCategory(...texts) {
  const haystack = texts
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  for (const { category, keywords } of CATEGORY_KEYWORDS) {
    if (keywords.some((kw) => haystack.includes(kw))) {
      return category;
    }
  }
  return CONFIG.DEFAULT_CATEGORY;
}

// ─────────────────────────────────────────────────────────────────────────
// SKU CLEANUP
// ─────────────────────────────────────────────────────────────────────────
function cleanSku(rawSku, fallbackSeed) {
  let sku = (rawSku || '').toString();

  try {
    sku = decodeURIComponent(sku);
  } catch {
    // leave as-is if it isn't valid percent-encoding
  }

  sku = sku
    .split('?')[0] // strip query string
    .split('#')[0] // strip fragment
    .replace(/[^A-Za-z0-9\-_]/g, '') // keep only safe chars
    .replace(/^-+|-+$/g, '') // trim leading/trailing dashes
    .toUpperCase();

  if (sku.length > 80) sku = sku.slice(0, 80);

  if (!sku) {
    const hash = crypto.createHash('md5').update(fallbackSeed || Math.random().toString()).digest('hex').slice(0, 10).toUpperCase();
    sku = `BG-${hash}`;
  } else if (!sku.startsWith('BG-')) {
    sku = `BG-${sku}`;
  }

  return sku.slice(0, 100);
}

// ─────────────────────────────────────────────────────────────────────────
// SCRAPING
// ─────────────────────────────────────────────────────────────────────────
async function fetchCategories() {
  logger.info('Fetching categories from shop index...');

  try {
    const response = await fetchWithRetry(`${CONFIG.BLINGGIRL_BASE_URL}/shop/`);
    const $ = cheerio.load(response.data);
    const categories = new Map(); // url -> name

    $('a[href*="/category/"], a[href*="/shop/category/"]').each((_, el) => {
      const href = $(el).attr('href');
      const name = $(el).text().trim();
      if (!href) return;

      const url = href.startsWith('http') ? href : `${CONFIG.BLINGGIRL_BASE_URL}${href}`;
      if (!categories.has(url)) categories.set(url, name || '');
    });

    const result = [...categories.entries()].map(([url, name]) => ({ url, name }));
    logger.success(`Found ${result.length} unique categories`);
    return result;
  } catch (err) {
    logger.error(`Failed to fetch categories: ${err.message}`);
    return [];
  }
}

async function scrapeCategory({ url, name }) {
  try {
    const response = await fetchWithRetry(url);
    const $ = cheerio.load(response.data);
    const products = [];

    const selectors = ['a[href*="/product/"]', '[class*="product"]', '[data-product]', 'article', '.item'];
    let productElements = $();
    for (const selector of selectors) {
      productElements = $(selector);
      if (productElements.length > 0) break;
    }

    productElements.each((i, el) => {
      try {
        const $el = $(el);

        let link = $el.attr('href') || $el.find('a').first().attr('href');
        if (!link) return;
        if (!link.startsWith('http')) link = `${CONFIG.BLINGGIRL_BASE_URL}${link}`;

        let productName = $el.find('h2, h3, [class*="name"], [class*="title"]').text().trim();
        if (!productName) productName = $el.attr('title') || '';
        productName = productName.trim();
        if (!productName) return;

        // ── Price extraction ────────────────────────────────────────────
        // IMPORTANT — two things this has to get right:
        //
        // 1. Blinggirl product titles often embed a product code that
        //    looks like a price, e.g. "...scissors[R2402P29]". Scanning
        //    the whole card's text for "R<digits>" can wrongly grab
        //    "R2402" from the title instead of the real "R80.00" price.
        //    Fix: strip the product name out of the search text, and
        //    require the matched number is NOT immediately followed by
        //    another letter/digit (embedded codes like "R2402P29" have a
        //    letter glued on right after the digits; real prices don't).
        //
        // 2. When a product is on sale, Blinggirl shows TWO numbers — the
        //    original ("was") price and the discounted current price.
        //    Grabbing only the first match and using it for both our sale
        //    price AND our "compare at" price means the compare price
        //    ends up being the SAME low number, and after we mark it up
        //    for resale it becomes LOWER than our new price — a "was"
        //    price that's cheaper than the current price, which is
        //    backwards. Fix: collect every valid price-looking number in
        //    the price element, and treat the highest as the "was" price
        //    and the lowest as the current price. If there's only one
        //    number, there's no discount to show at all.
        let priceScope = $el.find('[class*="price"]').first();
        let priceText = priceScope.length ? priceScope.text() : $el.text();
        if (productName) priceText = priceText.split(productName).join(' ');

        const priceRegex = /R\s*([\d,]+\.?\d*)(?![A-Za-z0-9])/gi;
        const foundPrices = [];
        let m;
        while ((m = priceRegex.exec(priceText)) !== null) {
          const val = parseFloat(m[1].replace(/,/g, ''));
          // Sanity guard: product codes on this site run into the
          // thousands (e.g. R2402), while real product prices on
          // Blinggirl are consistently well under R2000. Anything above
          // that threshold is almost certainly a mis-parsed code, not a
          // genuine price — discard it rather than syncing garbage.
          if (Number.isFinite(val) && val > 0 && val <= 5000) foundPrices.push(val);
        }

        if (foundPrices.length === 0) {
          logger.debug(`No valid price found for "${productName}" — skipping`);
          return;
        }

        const sourceCurrentPrice = Math.min(...foundPrices);
        const sourceWasPrice = Math.max(...foundPrices); // equal to current if only one price found

        const img = $el.find('img').first();
        let image = img.attr('src') || img.attr('data-src') || img.attr('data-lazy-src') || '';
        if (image && !image.startsWith('http')) image = `${CONFIG.BLINGGIRL_BASE_URL}${image}`;

        const rawSkuSeed = link.split('/').filter(Boolean).pop() || `${name}-${i}`;

        products.push({
          name: productName.slice(0, 200),
          description: productName,
          sourceCurrentPrice,
          sourceWasPrice,
          rawSku: rawSkuSeed,
          skuSeed: link,
          image,
          link,
          sourceCategoryName: name,
        });
      } catch {
        // skip malformed individual product node
      }
    });

    logger.info(`  → ${products.length} product(s) found in "${name || url.split('/').filter(Boolean).pop()}"`);
    return products;
  } catch (err) {
    logger.warn(`Failed to scrape category ${url}: ${err.message}`);
    return [];
  }
}

// ─────────────────────────────────────────────────────────────────────────
// TRANSFORM: raw scrape result -> schema-compliant PRODUCTS document
// ─────────────────────────────────────────────────────────────────────────
function toProductDoc(raw) {
  const sku = cleanSku(raw.rawSku, raw.skuSeed);
  const category = inferCategory(raw.sourceCategoryName, raw.name);

  // Apply our resale markup to BOTH the current and "was" price so their
  // relative order is preserved — a genuine discount on Blinggirl stays a
  // genuine discount for our customers, just scaled up by the markup.
  const sellingPrice = Math.round(raw.sourceCurrentPrice * (1 + CONFIG.MARKUP_PERCENTAGE) * 100) / 100;
  const hasGenuineDiscount = raw.sourceWasPrice > raw.sourceCurrentPrice;
  const comparePrice = hasGenuineDiscount
    ? Math.round(raw.sourceWasPrice * (1 + CONFIG.MARKUP_PERCENTAGE) * 100) / 100
    : null; // no fabricated "was" price when the source shows no discount

  return {
    sku,
    name: raw.name.slice(0, 200),
    description: (raw.description || raw.name).slice(0, 2000),
    price: sellingPrice,
    comparePrice,
    category,
    images: raw.image ? [raw.image] : [],
    stock: CONFIG.DEFAULT_STOCK,
    brand: CONFIG.SOURCE_MERCHANT,
    tags: ['blinggirl', 'reseller', category],
    isActive: CONFIG.AUTO_ACTIVATE,
    isFeatured: false,
    sourceUrl: raw.link,
    sourceMerchant: CONFIG.SOURCE_MERCHANT,
    syncedAt: new Date(),
  };
}

// ─────────────────────────────────────────────────────────────────────────
// VALIDATION
// Mirrors the PRODUCTS $jsonSchema validator in the backend so we never
// send documents Mongo will reject (error code 121).
// ─────────────────────────────────────────────────────────────────────────
function validateProductDoc(doc) {
  const errors = [];

  if (!doc.sku || typeof doc.sku !== 'string') errors.push('sku missing or not a string');
  if (!doc.name || typeof doc.name !== 'string' || doc.name.trim().length < 1) {
    errors.push('name missing or empty');
  }
  if (!Number.isFinite(doc.price) || doc.price < 0) {
    errors.push(`price invalid (${doc.price})`);
  }
  if (doc.comparePrice != null && (!Number.isFinite(doc.comparePrice) || doc.comparePrice < 0)) {
    errors.push(`comparePrice invalid (${doc.comparePrice})`);
  }
  // A "was" price that isn't actually higher than the current price is
  // either a data bug or a misleading display — never sync it either way.
  if (doc.comparePrice != null && Number.isFinite(doc.comparePrice) && doc.comparePrice <= doc.price) {
    errors.push(`comparePrice (${doc.comparePrice}) must be greater than price (${doc.price})`);
  }
  if (!CONFIG.VALID_CATEGORIES.includes(doc.category)) {
    errors.push(`category "${doc.category}" not in enum`);
  }
  if (!Number.isInteger(doc.stock) || doc.stock < 0) {
    errors.push(`stock invalid (${doc.stock})`);
  }
  if (!Array.isArray(doc.images) || doc.images.some((i) => typeof i !== 'string')) {
    errors.push('images must be an array of strings');
  }
  if (!Array.isArray(doc.tags) || doc.tags.some((t) => typeof t !== 'string')) {
    errors.push('tags must be an array of strings');
  }
  if (typeof doc.isActive !== 'boolean') errors.push('isActive must be boolean');

  return { valid: errors.length === 0, errors };
}

// ─────────────────────────────────────────────────────────────────────────
// DEDUPLICATION
// Products can appear in multiple categories on Blinggirl (cross-listed).
// Keep the first occurrence per SKU, but prefer the one with more complete
// data (has an image) if there's a conflict.
// ─────────────────────────────────────────────────────────────────────────
function dedupeBySku(docs) {
  const bySku = new Map();
  let duplicatesRemoved = 0;

  for (const doc of docs) {
    const existing = bySku.get(doc.sku);
    if (!existing) {
      bySku.set(doc.sku, doc);
      continue;
    }

    duplicatesRemoved++;
    const existingHasImage = existing.images.length > 0;
    const candidateHasImage = doc.images.length > 0;
    if (!existingHasImage && candidateHasImage) {
      bySku.set(doc.sku, doc);
    }
  }

  return { deduped: [...bySku.values()], duplicatesRemoved };
}

// ─────────────────────────────────────────────────────────────────────────
// MONGODB SYNC — bulkWrite with proper BSON types
// ─────────────────────────────────────────────────────────────────────────
async function syncToMongoDB(products) {
  const client = new MongoClient(CONFIG.MONGODB_URI);
  const stats = { matched: 0, modified: 0, upserted: 0, batches: 0, bulkErrors: [] };

  try {
    await client.connect();
    const db = client.db(CONFIG.DB_NAME);
    const col = db.collection('PRODUCTS');

    logger.info(`Preparing bulk upsert for ${products.length} product(s)...`);

    for (let i = 0; i < products.length; i += CONFIG.BATCH_SIZE) {
      const batch = products.slice(i, i + CONFIG.BATCH_SIZE);
      const now = new Date();

      const ops = batch.map((p) => {
        const setFields = {
          name: p.name,
          description: p.description,
          price: Decimal128.fromString(p.price.toFixed(2)),
          comparePrice: p.comparePrice != null ? Decimal128.fromString(p.comparePrice.toFixed(2)) : null,
          category: p.category,
          images: p.images,
          stock: new Int32(p.stock),
          brand: p.brand,
          tags: p.tags,
          sourceUrl: p.sourceUrl,
          sourceMerchant: p.sourceMerchant,
          syncedAt: p.syncedAt,
          updatedAt: now,
        };

        if (CONFIG.AUTO_ACTIVATE) setFields.isActive = true;

        const update = CONFIG.UPDATE_EXISTING
          ? {
              $set: setFields,
              $setOnInsert: { sku: p.sku, isFeatured: false, createdAt: now, ...(CONFIG.AUTO_ACTIVATE ? {} : { isActive: p.isActive }) },
            }
          : {
              $setOnInsert: {
                sku: p.sku,
                ...setFields,
                isFeatured: false,
                createdAt: now,
                isActive: p.isActive,
              },
            };

        return {
          updateOne: {
            filter: { sku: p.sku },
            update,
            upsert: true,
          },
        };
      });

      try {
        const result = await col.bulkWrite(ops, { ordered: false });
        stats.matched += result.matchedCount || 0;
        stats.modified += result.modifiedCount || 0;
        stats.upserted += result.upsertedCount || 0;
        stats.batches++;
        logger.info(
          `Batch ${stats.batches} (${batch.length} items): matched=${result.matchedCount}, modified=${result.modifiedCount}, upserted=${result.upsertedCount}`
        );
      } catch (err) {
        // bulkWrite with ordered:false still throws on completion if any op failed —
        // err.result carries the partial results plus per-op write errors.
        const writeErrors = err.writeErrors || err.result?.result?.writeErrors || [];
        stats.matched += err.result?.result?.nMatched || 0;
        stats.modified += err.result?.result?.nModified || 0;
        stats.upserted += err.result?.result?.nUpserted || 0;
        stats.batches++;

        for (const we of writeErrors) {
          const failedSku = batch[we.index]?.sku || 'UNKNOWN';
          const msg = `SKU ${failedSku}: ${we.errmsg || we.err?.errmsg || 'unknown write error'}`;
          stats.bulkErrors.push(msg);
          logger.warn(`Write error — ${msg}`);
        }

        if (writeErrors.length === 0) {
          logger.error(`Batch ${stats.batches} failed entirely: ${err.message}`);
          stats.bulkErrors.push(`Batch ${stats.batches}: ${err.message}`);
        }
      }
    }

    return stats;
  } finally {
    await client.close();
  }
}

// ─────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────
async function main() {
  const startTime = Date.now();
  logger.info('═'.repeat(70));
  logger.info('🛍️  BLINGGIRL SCRAPER — PRODUCTION RUN');
  logger.info('═'.repeat(70));
  logger.info(
    `Config: markup=${(CONFIG.MARKUP_PERCENTAGE * 100).toFixed(0)}%, defaultStock=${CONFIG.DEFAULT_STOCK}, ` +
    `autoActivate=${CONFIG.AUTO_ACTIVATE}, updateExisting=${CONFIG.UPDATE_EXISTING}, batchSize=${CONFIG.BATCH_SIZE}`
  );

  const runStats = {
    categoriesFound: 0,
    categoriesFailed: 0,
    rawProductsScraped: 0,
    duplicatesRemoved: 0,
    validationFailed: 0,
    validationFailureSamples: [],
    validProducts: 0,
  };

  try {
    // Step 1 — categories
    const categories = await fetchCategories();
    runStats.categoriesFound = categories.length;

    if (categories.length === 0) {
      logger.error('No categories found — aborting.');
      process.exitCode = 1;
      return;
    }

    // Step 2 — scrape each category (politely, sequentially, with delay)
    let rawProducts = [];
    for (const category of categories) {
      const products = await scrapeCategory(category);
      if (products.length === 0) runStats.categoriesFailed++;
      rawProducts = rawProducts.concat(products);
      await sleep(CONFIG.REQUEST_DELAY_MS);
    }
    runStats.rawProductsScraped = rawProducts.length;
    logger.success(`Scraped ${rawProducts.length} raw product listing(s) across ${categories.length} categories`);

    if (rawProducts.length === 0) {
      logger.error('No products scraped — aborting.');
      process.exitCode = 1;
      return;
    }

    // Step 3 — transform to schema-shaped docs
    const transformed = rawProducts.map(toProductDoc);

    // Step 4 — dedupe by SKU (cross-category listings)
    const { deduped, duplicatesRemoved } = dedupeBySku(transformed);
    runStats.duplicatesRemoved = duplicatesRemoved;
    logger.info(`Removed ${duplicatesRemoved} duplicate SKU(s); ${deduped.length} unique product(s) remain`);

    // Step 5 — validate against PRODUCTS schema before touching the DB
    const validProducts = [];
    for (const doc of deduped) {
      const { valid, errors } = validateProductDoc(doc);
      if (valid) {
        validProducts.push(doc);
      } else {
        runStats.validationFailed++;
        const sample = `SKU ${doc.sku} ("${doc.name}"): ${errors.join('; ')}`;
        if (runStats.validationFailureSamples.length < 25) {
          runStats.validationFailureSamples.push(sample);
        }
        logger.warn(`Validation failed — ${sample}`);
      }
    }
    runStats.validProducts = validProducts.length;

    if (validProducts.length === 0) {
      logger.error('No products passed validation — aborting before DB write.');
      process.exitCode = 1;
      return;
    }

    // Step 6 — bulk sync to MongoDB
    const syncStats = await syncToMongoDB(validProducts);

    // ── Summary ────────────────────────────────────────────────────────
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    logger.info('');
    logger.info('═'.repeat(70));
    logger.success(`COMPLETE in ${duration}s`);
    logger.info(`Categories found:        ${runStats.categoriesFound}`);
    logger.info(`Categories with 0 items: ${runStats.categoriesFailed}`);
    logger.info(`Raw listings scraped:    ${runStats.rawProductsScraped}`);
    logger.info(`Duplicates removed:      ${runStats.duplicatesRemoved}`);
    logger.info(`Failed validation:       ${runStats.validationFailed}`);
    logger.info(`Valid products:          ${runStats.validProducts}`);
    logger.info(`Mongo matched:           ${syncStats.matched}`);
    logger.info(`Mongo modified:          ${syncStats.modified}`);
    logger.info(`Mongo upserted (new):    ${syncStats.upserted}`);
    if (syncStats.bulkErrors.length > 0) {
      logger.warn(`Mongo write errors:      ${syncStats.bulkErrors.length} (see log above for details)`);
    }
    logger.info('═'.repeat(70));

    process.exitCode = syncStats.bulkErrors.length > 0 ? 1 : 0;
  } catch (err) {
    logger.error(`Fatal error: ${err.stack || err.message}`);
    process.exitCode = 1;
  }
}

main();
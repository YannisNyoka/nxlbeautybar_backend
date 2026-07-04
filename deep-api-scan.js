/**
 * Deep API Scanner for Blinggirl
 * Checks page source, cookies, and network patterns
 */

const axios = require('axios');
const cheerio = require('cheerio');

const client = axios.create({
  timeout: 15000,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  },
});

async function deepScan() {
  console.log('🔍 Deep scanning Blinggirl...\n');

  try {
    const response = await client.get('https://blinggirl.co.za/shop/');
    const html = response.data;
    const $ = cheerio.load(html);

    console.log('═══════════════════════════════════════════════════════════');
    console.log('1. CHECKING PAGE SOURCE FOR API HINTS');
    console.log('═══════════════════════════════════════════════════════════\n');

    // Look for API keys, URLs in page source
    const apiPatterns = [
      /apiKey["\']?\s*[:=]\s*["\']([^"']+)["\']?/gi,
      /api[_-]?url["\']?\s*[:=]\s*["\']([^"']+)["\']?/gi,
      /endpoint["\']?\s*[:=]\s*["\']([^"']+)["\']?/gi,
      /\/api\/[a-zA-Z0-9\-_/]+/g,
      /https?:\/\/[a-zA-Z0-9.-]+\/api[a-zA-Z0-9\-_/]*/g,
      /shopifycdn|shopify/gi,
      /woocommerce/gi,
      /"products"\s*:\s*\[/gi,
    ];

    let foundPatterns = false;
    apiPatterns.forEach((pattern) => {
      const matches = html.match(pattern);
      if (matches) {
        console.log(`✅ Found pattern: ${pattern}`);
        console.log(`   Matches: ${matches.slice(0, 3).join(', ')}\n`);
        foundPatterns = true;
      }
    });

    if (!foundPatterns) {
      console.log('⚠️  No obvious API patterns found in HTML\n');
    }

    // Check for specific frameworks
    console.log('═══════════════════════════════════════════════════════════');
    console.log('2. DETECTING PLATFORM');
    console.log('═══════════════════════════════════════════════════════════\n');

    const platforms = {
      Shopify: html.includes('Shopify') || html.includes('shopifycdn'),
      WooCommerce: html.includes('wp-json') || html.includes('woocommerce'),
      Magento: html.includes('Magento') || html.includes('/media/'),
      BigCommerce: html.includes('bigcommerce'),
      'Custom Node/Express': html.includes('__NEXT_DATA__') || html.includes('__nuxt'),
      React: html.includes('react') || html.includes('reactRoot'),
      Vue: html.includes('vue') || html.includes('v-app'),
      Angular: html.includes('angular') || html.includes('ng-app'),
    };

    Object.entries(platforms).forEach(([platform, detected]) => {
      if (detected) {
        console.log(`✅ Detected: ${platform}`);
      }
    });

    // Check for JSON-LD structured data
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('3. CHECKING STRUCTURED DATA (JSON-LD)');
    console.log('═══════════════════════════════════════════════════════════\n');

    const jsonLdScripts = $('script[type="application/ld+json"]');
    if (jsonLdScripts.length > 0) {
      console.log(`✅ Found ${jsonLdScripts.length} JSON-LD scripts`);
      jsonLdScripts.each((i, el) => {
        try {
          const data = JSON.parse($(el).html());
          console.log(`   Script ${i + 1}: ${data['@type'] || 'Unknown'}`);
          if (data.itemListElement) {
            console.log(`   Contains ${data.itemListElement.length} items`);
          }
        } catch (e) {
          console.log(`   Script ${i + 1}: (Invalid JSON)`);
        }
      });
    } else {
      console.log('⚠️  No JSON-LD structured data found');
    }

    // Check for inline data
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('4. CHECKING FOR INLINE PRODUCT DATA');
    console.log('═══════════════════════════════════════════════════════════\n');

    const dataScripts = $('script:not([type])').filter((i, el) => {
      return $(el).html().includes('product') || $(el).html().includes('Product');
    });

    if (dataScripts.length > 0) {
      console.log(`✅ Found ${dataScripts.length} scripts with product data`);
      dataScripts.each((i, el) => {
        const content = $(el).html();
        if (content.length < 500) {
          console.log(`   Script ${i + 1}: ${content.substring(0, 100)}...`);
        }
      });
    } else {
      console.log('⚠️  No inline product data found');
    }

    // Check meta tags and headers
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('5. CHECKING META TAGS & HEADERS');
    console.log('═══════════════════════════════════════════════════════════\n');

    const metaTags = {
      'X-Powered-By': response.headers['x-powered-by'],
      'Server': response.headers['server'],
      'Content-Type': response.headers['content-type'],
    };

    Object.entries(metaTags).forEach(([key, value]) => {
      if (value) {
        console.log(`✅ ${key}: ${value}`);
      }
    });

    // Look for API endpoints in HTML attributes
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('6. SCANNING HTML ATTRIBUTES FOR ENDPOINTS');
    console.log('═══════════════════════════════════════════════════════════\n');

    let foundEndpoints = false;
    $('[data-*]').each((i, el) => {
      const attrs = el.attribs;
      Object.entries(attrs).forEach(([key, value]) => {
        if ((key.includes('api') || key.includes('url') || key.includes('endpoint')) && 
            (value.includes('/') || value.includes('http'))) {
          console.log(`✅ Found: ${key}="${value}"`);
          foundEndpoints = true;
        }
      });
    });

    if (!foundEndpoints) {
      console.log('⚠️  No endpoint attributes found');
    }

    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('NEXT STEPS');
    console.log('═══════════════════════════════════════════════════════════\n');
    console.log('Option 1: Check Network tab in DevTools');
    console.log('  1. Open https://blinggirl.co.za/shop/');
    console.log('  2. F12 → Network tab');
    console.log('  3. Look for XHR/Fetch requests');
    console.log('  4. Share the URL of any request with product data\n');

    console.log('Option 2: Check if using Render or similar service');
    console.log('  - Look for /api/* routes');
    console.log('  - Check for GraphQL endpoint at /graphql\n');

    console.log('Option 3: Try category-specific scraping');
    console.log('  - Different categories might load products differently\n');

  } catch (error) {
    console.error('❌ Scan failed:', error.message);
  }
}

deepScan();
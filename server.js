require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { MongoClient, ObjectId, Decimal128 } = require('mongodb');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const { body, param, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const swaggerUi = require('swagger-ui-express');
const winston = require('winston');
const { Resend } = require('resend');
const crypto = require('crypto');

let fetchFn;
try {
  fetchFn = fetch;
} catch {
  fetchFn = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
}

function pad2(n) { return String(n).padStart(2, '0'); }

// ── Sanitise free-text to prevent XSS / injection ─────────────────────────
// Strips HTML tags and trims whitespace. Applied to all user-supplied text
// that is stored in DB and potentially rendered back to clients.
function sanitiseText(val, maxLen = 1000) {
  if (typeof val !== 'string') return '';
  return val
    .replace(/<[^>]*>/g, '')        // strip HTML tags
    .replace(/javascript:/gi, '')   // strip JS protocol
    .replace(/on\w+\s*=/gi, '')     // strip inline event handlers
    .trim()
    .slice(0, maxLen);
}
// ─────────────────────────────────────────────────────────────────────────

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

const app = express();
const port = process.env.PORT;

app.set('trust proxy', 1);

const allowedOrigins = process.env.NODE_ENV === 'production'
  ? [process.env.CORS_ORIGIN, 'https://nxlbeautybar.co.za', 'https://www.nxlbeautybar.co.za']
  : [/^http:\/\/localhost:\d+$/];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.some(o => (o instanceof RegExp ? o.test(origin) : o === origin))) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 200
};

const refreshTokens = new Set();

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

function sendValidationError(res, errors) {
  const list = Array.isArray(errors) ? errors : [];
  const msg = list.length ? list.map(e => `${e?.path || e?.param || 'field'}: ${e?.msg || 'Invalid value'}`).join(', ') : 'Validation failed';
  return res.status(400).json({ success: false, error: msg, errors: list });
}

function decimalToNumber(v) {
  if (v == null) return null;
  if (typeof v === 'number') return v;
  if (typeof v === 'object' && typeof v.toString === 'function') { const n = Number(v.toString()); return Number.isFinite(n) ? n : null; }
  const n = Number(String(v));
  return Number.isFinite(n) ? n : null;
}

const requiredEnv = ['PORT', 'MONGODB_URI', 'DB_NAME', 'JWT_SECRET', 'CORS_ORIGIN'];
const missingEnv = requiredEnv.filter(key => !process.env[key]);
if (missingEnv.length > 0) { console.error(`Missing required environment variables: ${missingEnv.join(', ')}`); process.exit(1); }

app.set('trust proxy', 1);
app.use(helmet());
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

app.use((req, _res, next) => {
  if (req.url.startsWith('/api/')) req.url = req.url.slice(4);
  else if (req.url === '/api') req.url = '/';
  next();
});

app.use((req, res, next) => {
  if (req.path === '/payments/webhook') {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      req.rawBody = Buffer.concat(chunks);
      try { req.body = JSON.parse(req.rawBody.toString('utf8')); } catch { req.body = {}; }
      next();
    });
    req.on('error', next);
  } else {
    bodyParser.json()(req, res, next);
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many requests, please try again later.' }
});

// Stricter limiter for payment creation (prevent payment flooding)
const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 5,
  message: { success: false, error: 'Too many payment requests. Please wait a moment.' }
});

// Order creation limiter
const orderLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many order requests. Please wait a moment.' }
});

// Discount code validation limiter (prevent brute-force guessing)
const discountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, error: 'Too many discount code attempts. Please try again later.' }
});

const uri = process.env.MONGODB_URI;
const dbName = process.env.DB_NAME;
const jwtSecret = process.env.JWT_SECRET;

const client = new MongoClient(uri);
let db;

function shutdown() { client.close().then(() => process.exit(0)); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') return res.redirect('https://' + req.headers.host + req.url);
    next();
  });
}

const initCollections = async (db) => {
  await db.createCollection('USERS', { validator: { $jsonSchema: { bsonType:'object', required:['email','password','firstName','lastName','role','isActive','createdAt','updatedAt'], properties: { email:{bsonType:'string',pattern:'^\\S+@\\S+\\.\\S+$'}, password:{bsonType:'string',minLength:60}, firstName:{bsonType:'string',minLength:1}, lastName:{bsonType:'string',minLength:1}, role:{bsonType:'string',enum:['user','admin']}, isActive:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('USERS').dropIndex('email_1'); } catch(e) {}
  await db.collection('USERS').createIndex({ email:1 }, { unique:true, name:'email_unique_idx' });
  await db.collection('USERS').createIndex({ referralCode:1 }, { sparse:true, unique:true });

  await db.createCollection('SERVICES', { validator: { $jsonSchema: { bsonType:'object', required:['name','durationMinutes','price','isActive','createdAt','updatedAt'], properties: { name:{bsonType:'string',minLength:1}, durationMinutes:{bsonType:'int',minimum:15}, price:{bsonType:'decimal',minimum:0}, isActive:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('SERVICES').dropIndex('name_1'); } catch(e) {}
  await db.collection('SERVICES').createIndex({ name:1 }, { unique:true, name:'service_name_unique_idx' });

  await db.createCollection('EMPLOYEES', { validator: { $jsonSchema: { bsonType:'object', required:['name','servicesOffered','isActive','createdAt','updatedAt'], properties: { name:{bsonType:'string',minLength:1}, email:{bsonType:['string','null']}, phone:{bsonType:['string','null']}, bio:{bsonType:['string','null']}, role:{bsonType:['string','null']}, color:{bsonType:['string','null']}, workingHours:{bsonType:['object','null']}, servicesOffered:{bsonType:'array',minItems:1,items:{bsonType:'objectId'}}, isActive:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
  try { await db.collection('EMPLOYEES').dropIndex('email_1'); } catch(e) {}
  await db.collection('EMPLOYEES').createIndex({ email:1 }, { unique:true, sparse:true, name:'employee_email_unique_idx' });

  await db.createCollection('AVAILABILITY', { validator: { $jsonSchema: { bsonType:'object', required:['date','time','employeeId','reason','createdAt'], properties: { date:{bsonType:'string',pattern:'^\\d{4}-\\d{2}-\\d{2}$'}, time:{bsonType:'string',pattern:'^\\d{2}:\\d{2}$'}, employeeId:{anyOf:[{bsonType:'objectId'},{bsonType:'string',enum:['ALL']}]}, reason:{bsonType:'string'}, createdAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('AVAILABILITY').dropIndex('date_1_time_1_employeeId_1'); } catch(e) {}
  await db.collection('AVAILABILITY').createIndex({ date:1,time:1,employeeId:1 }, { unique:true, name:'availability_unique_idx' });

  await db.createCollection('APPOINTMENTS', { validator: { $jsonSchema: { bsonType:'object', required:['date','time','userId','employeeId','serviceIds','totalPrice','status','createdAt','updatedAt'], properties: { date:{bsonType:'string',pattern:'^\\d{4}-\\d{2}-\\d{2}$'}, time:{bsonType:'string',pattern:'^\\d{2}:\\d{2}$'}, userId:{bsonType:'objectId'}, employeeId:{bsonType:'objectId'}, serviceIds:{bsonType:'array',minItems:1,items:{bsonType:'objectId'}}, totalPrice:{bsonType:'decimal',minimum:0}, status:{bsonType:'string',enum:['pending','booked','cancelled','completed','no-show']}, paymentStatus:{bsonType:'string',enum:['unpaid','deposit_paid','paid']}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('APPOINTMENTS').dropIndex('date_1_time_1_employeeId_1'); } catch(e) {}
  try { await db.collection('APPOINTMENTS').dropIndex('appointment_unique_idx'); } catch(e) {}
  await db.collection('APPOINTMENTS').createIndex({ date:1,time:1,employeeId:1 }, { unique:true, name:'appointment_unique_idx', partialFilterExpression:{ status:{$in:['booked','completed','no-show']}, paymentStatus:{$in:['deposit_paid','paid']} } });

  await db.createCollection('PAYMENTS', { validator: { $jsonSchema: { bsonType:'object', required:['appointmentId','type','amount','method','status','createdAt'], properties: { appointmentId:{bsonType:'objectId'}, type:{bsonType:'string',enum:['deposit','full']}, amount:{bsonType:'decimal',minimum:0}, currency:{bsonType:'string'}, method:{bsonType:'string',enum:['cash','card','online']}, status:{bsonType:'string',enum:['pending','paid','refunded']}, createdAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('PAYMENTS').dropIndex('payment_appointment_unique_idx'); } catch(e) {}
  try { await db.collection('PAYMENTS').dropIndex('appointmentId_1'); } catch(e) {}
  await db.collection('PAYMENTS').createIndex({ appointmentId:1,type:1 }, { unique:true, name:'payment_appointment_type_unique_idx' });

  await db.createCollection('NOTIFICATIONS', { validator: { $jsonSchema: { bsonType:'object', required:['message','target','createdBy','createdAt','read'], properties: { message:{bsonType:'string'}, target:{bsonType:'string',enum:['client','staff','all']}, recipientId:{bsonType:['objectId','null']}, createdBy:{bsonType:'objectId'}, createdAt:{bsonType:'date'}, read:{bsonType:'bool'}, readAt:{bsonType:['date','null']} } } }, validationLevel:'strict' }).catch(()=>{});
  await db.collection('NOTIFICATIONS').createIndex({ createdAt:-1 });

  await db.createCollection('AUDIT_LOG', { validator: { $jsonSchema: { bsonType:'object', required:['collection','documentId','action','performedBy','timestamp'], properties: { collection:{bsonType:'string'}, documentId:{bsonType:'objectId'}, action:{bsonType:'string'}, performedBy:{bsonType:'objectId'}, timestamp:{bsonType:'date'}, data:{bsonType:'object'} } } }, validationLevel:'strict' }).catch(()=>{});

  await db.createCollection('GALLERY').catch(()=>{});
  await db.collection('GALLERY').createIndex({ createdAt:-1 });

  // CLIENT GALLERY — before/after photos submitted by clients after appointments
  await db.createCollection('CLIENT_GALLERY', {}).catch(() => {});
  await db.collection('CLIENT_GALLERY').createIndex({ userId: 1 });
  await db.collection('CLIENT_GALLERY').createIndex({ appointmentId: 1 });
  await db.collection('CLIENT_GALLERY').createIndex({ status: 1, createdAt: -1 });

  // CLIENT_NOTIFICATIONS — in-app notifications for customers
  await db.createCollection('CLIENT_NOTIFICATIONS', {}).catch(() => {});
  await db.collection('CLIENT_NOTIFICATIONS').createIndex({ userId: 1, createdAt: -1 });
  await db.collection('CLIENT_NOTIFICATIONS').createIndex({ userId: 1, read: 1 });

  // REFERRALS — referral program
  await db.createCollection('REFERRALS', {}).catch(() => {});
  await db.collection('REFERRALS').createIndex({ referrerId: 1 });
  await db.collection('REFERRALS').createIndex({ referralCode: 1 }, { unique: true });
  await db.collection('REFERRALS').createIndex({ refereeId: 1 });

  // SUBSCRIPTION_PLANS — admin-defined monthly plans
  await db.createCollection('SUBSCRIPTION_PLANS', {}).catch(() => {});
  await db.collection('SUBSCRIPTION_PLANS').createIndex({ isActive: 1 });

  // FEEDBACK — post-visit NPS surveys
  await db.createCollection('FEEDBACK', {}).catch(() => {});
  await db.collection('FEEDBACK').createIndex({ userId: 1 });
  await db.collection('FEEDBACK').createIndex({ appointmentId: 1 }, { unique: true, sparse: true });
  await db.collection('FEEDBACK').createIndex({ createdAt: -1 });
  await db.collection('FEEDBACK').createIndex({ npsScore: 1 });

  // SUBSCRIPTIONS — client subscriptions
  await db.createCollection('SUBSCRIPTIONS', {}).catch(() => {});
  await db.collection('SUBSCRIPTIONS').createIndex({ userId: 1 });
  await db.collection('SUBSCRIPTIONS').createIndex({ planId: 1 });
  await db.collection('SUBSCRIPTIONS').createIndex({ status: 1, renewalDate: 1 });





  // DISCOUNT_CODES
  await db.createCollection('DISCOUNT_CODES', {
    validator: { $jsonSchema: { bsonType:'object', required:['code','type','value','isActive','createdAt'], properties: {
      code:           { bsonType:'string' },
      type:           { bsonType:'string', enum:['percentage','flat'] },
      value:          { bsonType:'number', minimum:0 },
      minOrderAmount: { bsonType:['number','null'] },
      usageLimit:     { bsonType:['int','null'] },
      usedCount:      { bsonType:'int', minimum:0 },
      expiresAt:      { bsonType:['date','null'] },
      isActive:       { bsonType:'bool' },
      description:    { bsonType:'string' },
      createdAt:      { bsonType:'date' },
    }}},
    validationLevel: 'moderate'
  }).catch(()=>{});
  await db.collection('DISCOUNT_CODES').createIndex({ code:1 }, { unique:true });

  // LOYALTY
  await db.createCollection('LOYALTY', {}).catch(() => {});
  await db.collection('LOYALTY').createIndex({ userId: 1 }, { unique: true });

  // LOYALTY_TRANSACTIONS
  await db.createCollection('LOYALTY_TRANSACTIONS', {}).catch(() => {});
  await db.collection('LOYALTY_TRANSACTIONS').createIndex({ userId: 1 });
  await db.collection('LOYALTY_TRANSACTIONS').createIndex({ createdAt: -1 });

  // GIFT_CARDS
  await db.createCollection('GIFT_CARDS', {}).catch(() => {});
  await db.collection('GIFT_CARDS').createIndex({ code: 1 }, { unique: true });
  await db.collection('GIFT_CARDS').createIndex({ recipientEmail: 1 });

  // INVENTORY (purchase orders + stock history)
  await db.createCollection('INVENTORY_ORDERS', {}).catch(() => {});
  await db.collection('INVENTORY_ORDERS').createIndex({ productId: 1 });
  await db.collection('INVENTORY_ORDERS').createIndex({ createdAt: -1 });

  // SUPPLIERS
  await db.createCollection('SUPPLIERS', {}).catch(() => {});
  await db.collection('SUPPLIERS').createIndex({ name: 1 });



  await db.createCollection('PRODUCTS', { validator: { $jsonSchema: { bsonType:'object', required:['name','price','category','stock','isActive','createdAt','updatedAt'], properties: { name:{bsonType:'string',minLength:1}, description:{bsonType:'string'}, price:{bsonType:'decimal',minimum:0}, comparePrice:{bsonType:['decimal','null']}, category:{bsonType:'string',enum:['nails','hair','skincare','accessories','professional','other']}, images:{bsonType:'array',items:{bsonType:'string'}}, stock:{bsonType:'int',minimum:0}, sku:{bsonType:'string'}, brand:{bsonType:'string'}, tags:{bsonType:'array',items:{bsonType:'string'}}, isActive:{bsonType:'bool'}, isFeatured:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
  await db.collection('PRODUCTS').createIndex({ name:'text',description:'text',brand:'text',tags:'text' });
  await db.collection('PRODUCTS').createIndex({ category:1 });
  await db.collection('PRODUCTS').createIndex({ isActive:1,isFeatured:-1,createdAt:-1 });

  await db.createCollection('ORDERS', { validator: { $jsonSchema: { bsonType:'object', required:['userId','items','totalAmount','status','paymentStatus','shippingAddress','createdAt','updatedAt'], properties: { userId:{bsonType:'objectId'}, items:{bsonType:'array',minItems:1}, subtotal:{bsonType:'decimal',minimum:0}, shippingFee:{bsonType:'decimal',minimum:0}, totalAmount:{bsonType:'decimal',minimum:0}, status:{bsonType:'string',enum:['pending','confirmed','processing','ready','shipped','delivered','cancelled','refunded']}, paymentStatus:{bsonType:'string',enum:['unpaid','paid','refunded']}, paymentMethod:{bsonType:'string',enum:['yoco','cash','eft']}, yocoCheckoutId:{bsonType:'string'}, shippingAddress:{bsonType:'object'}, trackingNumber:{bsonType:'string'}, notes:{bsonType:'string'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
  await db.collection('ORDERS').createIndex({ userId:1,createdAt:-1 });
  await db.collection('ORDERS').createIndex({ status:1 });

  await db.createCollection('REVIEWS', { validator: { $jsonSchema: { bsonType:'object', required:['productId','userId','rating','createdAt'], properties: { productId:{bsonType:'objectId'}, userId:{bsonType:'objectId'}, rating:{bsonType:'int',minimum:1,maximum:5}, comment:{bsonType:'string'}, createdAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
  await db.collection('REVIEWS').createIndex({ productId:1,createdAt:-1 });
  await db.collection('REVIEWS').createIndex({ productId:1,userId:1 }, { unique:true });
};

async function startServer() {
  try {
    await client.connect();
    db = client.db(dbName);
    await initCollections(db);
    console.log('Connected to MongoDB Atlas');

    function authenticateToken(req, res, next) {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      if (!token) return res.status(401).json({ success: false, error: 'Missing token' });
      jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ success: false, error: 'Invalid token' });
        req.user = user;
        next();
      });
    }

    function authorizeRole(role) {
      return (req, res, next) => {
        if (!req.user || req.user.role !== role) return res.status(403).json({ success: false, error: 'Forbidden' });
        next();
      };
    }

    const idValidator = param('id').isMongoId().withMessage('Invalid ID format');

    // =====================
    // AUTH ROUTES
    // =====================
    app.post('/auth/register', authLimiter,
      body('email').isEmail().normalizeEmail(),
      body('password').isString().isLength({ min:8 }).matches(/[A-Z]/).matches(/[a-z]/).matches(/[0-9]/).matches(/[^A-Za-z0-9]/),
      body('confirmPassword').custom((value, { req }) => value === req.body.password).withMessage('Passwords do not match'),
      body('firstName').isString().notEmpty(),
      body('lastName').isString().notEmpty(),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const { email, password, firstName, lastName } = req.body;
          const exists = await db.collection('USERS').findOne({ email });
          if (exists) return res.status(409).json({ success: false, error: 'Email already registered' });
          const hashedPassword = await bcrypt.hash(password, 10);
          const now = new Date();
          const user = { email, password: hashedPassword, firstName, lastName, role:'user', isActive:true, createdAt:now, updatedAt:now };
          const result = await db.collection('USERS').insertOne(user);
          const token = jwt.sign({ userId: result.insertedId, email: user.email, role: user.role }, jwtSecret, { expiresIn:'1h' });

          // ── Welcome email ────────────────────────────────────────────────
          if (process.env.RESEND_API_KEY) {
            try {
              const resend = new Resend(process.env.RESEND_API_KEY);
              const frontendUrl = (process.env.CORS_ORIGIN || 'https://nxlbeautybar.co.za').replace(/\/$/, '');
              await resend.emails.send({
                from:    'NXL Beauty Bar <onboarding@resend.dev>',
                to:      user.email,
                subject: `Welcome to NXL Beauty Bar, ${user.firstName}! 💅`,
                html: `
                  <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;">
                    <h2 style="font-family:Georgia,serif;color:#3d1f15;margin-bottom:0.25rem;">NXL Beauty Bar</h2>
                    <h3 style="color:#6b3528;margin-top:0;">Welcome, ${user.firstName}! 🎉</h3>
                    <p style="color:#555;line-height:1.7;">You've joined the NXL Beauty Bar family. We're so excited to have you!</p>
                    <div style="background:#fff;border:1px solid #e0ccc4;border-radius:10px;padding:1.25rem 1.5rem;margin:1.5rem 0;">
                      <p style="margin:0 0 0.75rem;font-weight:700;color:#3d1f15;font-size:0.88rem;">What you can do now:</p>
                      <table style="width:100%;border-collapse:collapse;">
                        <tr><td style="padding:0.4rem 0;font-size:0.85rem;color:#555;">💅 <a href="${frontendUrl}/dashboard" style="color:#a0502e;text-decoration:none;">Book an appointment</a> — Manicure, Pedicure, Lashes &amp; more</td></tr>
                        <tr><td style="padding:0.4rem 0;font-size:0.85rem;color:#555;">🛍️ <a href="${frontendUrl}/shop" style="color:#a0502e;text-decoration:none;">Shop our products</a> — Professional beauty products delivered to you</td></tr>
                        <tr><td style="padding:0.4rem 0;font-size:0.85rem;color:#555;">📦 Free delivery on orders over <strong>R500</strong></td></tr>
                      </table>
                    </div>
                    <div style="text-align:center;margin:1.75rem 0;">
                      <a href="${frontendUrl}/dashboard" style="background:#3d1f15;color:#ffe8d6;text-decoration:none;padding:0.875rem 2rem;border-radius:50px;font-weight:700;font-size:0.92rem;display:inline-block;">Book Your First Appointment →</a>
                    </div>
                    <div style="background:#fff8f3;border:1px solid #e0ccc4;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.25rem;">
                      <p style="margin:0;font-size:0.82rem;font-weight:700;color:#6b3528;">📍 Find us</p>
                      <p style="margin:0.3rem 0 0;font-size:0.8rem;color:#9e7060;">1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                      <p style="margin:0.2rem 0 0;font-size:0.8rem;color:#9e7060;">📞 068 511 3394 &nbsp;|&nbsp; Mon–Sat 9AM–5PM</p>
                    </div>
                    <hr style="border:none;border-top:1px solid #e0ccc4;margin:1.5rem 0;"/>
                    <p style="color:#b08070;font-size:0.7rem;text-align:center;margin:0;">NXL Beauty Bar &middot; 1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                  </div>
                `,
              });
              logger.info(`[WELCOME EMAIL] Sent to ${user.email}`);
            } catch (emailErr) {
              logger.error(`[WELCOME EMAIL] Failed: ${emailErr.message}`);
            }
          }
          // ─────────────────────────────────────────────────────────────────

          // ── Referral program — handle referral code on signup ─────────────
          const { referralCode: refCode } = req.body;
          if (refCode) {
            try {
              const referrer = await db.collection('USERS').findOne(
                { referralCode: refCode.trim().toUpperCase() },
                { projection: { _id:1, firstName:1 } }
              );
              if (referrer && String(referrer._id) !== String(result.insertedId)) {
                // Record the referral
                await db.collection('REFERRALS').insertOne({
                  referrerId:    referrer._id,
                  refereeId:     result.insertedId,
                  referralCode:  refCode.trim().toUpperCase(),
                  status:        'signed_up',
                  pointsAwarded: 0,
                  discountGiven: REFERRAL_CONFIG.refereeDiscount,
                  createdAt:     new Date(),
                  updatedAt:     new Date(),
                });

                // Tag user as referred
                await db.collection('USERS').updateOne(
                  { _id: result.insertedId },
                  { $set: { referredBy: referrer._id, referredByCode: refCode.trim().toUpperCase() } }
                );

                // Notify referrer — friend signed up (points come when they book)
                await notifyClient(referrer._id, {
                  type:  'promotion',
                  title: `${firstName} joined using your referral! 🎉`,
                  body:  `You'll earn +${REFERRAL_CONFIG.referrerPoints} points when they complete their first booking.`,
                  link:  '/profile',
                });

                // Create a one-time discount code for the referee (R50 off first order)
                const discountCode = `REF${refCode.slice(-4)}${result.insertedId.toString().slice(-4).toUpperCase()}`;
                await db.collection('DISCOUNT_CODES').insertOne({
                  code:           discountCode,
                  type:           'fixed',
                  value:          REFERRAL_CONFIG.refereeDiscount,
                  description:    `Welcome gift from ${referrer.firstName} — R${REFERRAL_CONFIG.refereeDiscount} off your first order`,
                  minOrderAmount: 0,
                  usageLimit:     1,
                  usedCount:      0,
                  isActive:       true,
                  expiresAt:      new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
                  forUserId:      result.insertedId,
                  createdAt:      new Date(),
                });

                // Notify new user of their discount
                await notifyClient(result.insertedId, {
                  type:  'promotion',
                  title: `Welcome gift from ${referrer.firstName}! 🎁`,
                  body:  `You have a R${REFERRAL_CONFIG.refereeDiscount} discount waiting. Use code ${discountCode} at checkout. Valid for 90 days.`,
                  link:  '/shop',
                  meta:  { code: discountCode },
                });

                logger.info(`[REFERRAL] ${firstName} signed up via referral from ${referrer.firstName}`);
              }
            } catch (refErr) { logger.error(`[REFERRAL] Signup handling failed: ${refErr.message}`); }
          }
          // ─────────────────────────────────────────────────────────────────

          res.status(201).json({ success:true, message:'User registered successfully', data:{ _id:result.insertedId, email:user.email, firstName:user.firstName, lastName:user.lastName, role:user.role }, token });
        } catch (err) { next(err); }
      }
    );

    app.post('/auth/login', authLimiter,
      body('email').isEmail().normalizeEmail(),
      body('password').isString().notEmpty(),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const { email, password } = req.body;
          const user = await db.collection('USERS').findOne({ email });
          if (!user) return res.status(400).json({ success:false, error:'Invalid credentials' });
          const match = await bcrypt.compare(password, user.password);
          if (!match) return res.status(400).json({ success:false, error:'Invalid credentials' });
          const normalizedRole = ['admin','user'].includes(user.role) ? user.role : 'user';
          if (normalizedRole !== user.role) await db.collection('USERS').updateOne({ _id:user._id }, { $set:{ role:normalizedRole, updatedAt:new Date() } });
          const token = jwt.sign({ userId:user._id, email:user.email, role:normalizedRole }, jwtSecret, { expiresIn:'1h' });
          const refreshToken = jwt.sign({ userId:user._id, email:user.email, role:normalizedRole }, jwtSecret, { expiresIn:'7d' });
          refreshTokens.add(refreshToken);
          res.status(200).json({ success:true, message:'Login successful', data:{ _id:user._id, email:user.email, firstName:user.firstName, lastName:user.lastName, role:normalizedRole }, token, refreshToken });
        } catch (err) { next(err); }
      }
    );

    // ── Self-service profile update (any authenticated user) ──────────────
    app.put('/auth/profile', authenticateToken,
      body('firstName').optional().isString().notEmpty().withMessage('First name cannot be empty'),
      body('lastName').optional().isString().notEmpty().withMessage('Last name cannot be empty'),
      body('email').optional().isEmail().normalizeEmail().withMessage('Invalid email address'),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());

          const userId = new ObjectId(req.user.userId);
          const update = { updatedAt: new Date() };

          if (req.body.firstName) update.firstName = sanitiseText(req.body.firstName, 50);
          if (req.body.lastName)  update.lastName  = sanitiseText(req.body.lastName, 50);

          // If email is changing, check it's not already taken
          if (req.body.email) {
            const existing = await db.collection('USERS').findOne({
              email: req.body.email,
              _id: { $ne: userId },
            });
            if (existing) return res.status(409).json({ success: false, error: 'Email already in use by another account.' });
            update.email = req.body.email;
          }

          const updated = await db.collection('USERS').findOneAndUpdate(
            { _id: userId },
            { $set: update },
            { returnDocument: 'after', projection: { password: 0 } }
          );

          if (!updated) return res.status(404).json({ success: false, error: 'User not found.' });

          res.json({ success: true, message: 'Profile updated.', data: updated });
        } catch (err) { next(err); }
      }
    );
    // ──────────────────────────────────────────────────────────────────────
    app.post('/auth/change-password', authenticateToken,
      body('oldPassword').isString().notEmpty(),
      body('newPassword').isString().isLength({ min:8 }).matches(/[A-Z]/).matches(/[a-z]/).matches(/[0-9]/).matches(/[^A-Za-z0-9]/),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const user = await db.collection('USERS').findOne({ _id: new ObjectId(req.user.userId) });
          if (!user) return res.status(404).json({ success:false, error:'User not found' });
          const match = await bcrypt.compare(req.body.oldPassword, user.password);
          if (!match) return res.status(400).json({ success:false, error:'Old password incorrect' });
          const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
          await db.collection('USERS').updateOne({ _id:user._id }, { $set:{ password:hashedPassword, updatedAt:new Date() } });
          res.status(200).json({ success:true, message:'Password changed successfully' });
        } catch (err) { next(err); }
      }
    );

    app.post('/auth/request-password-reset', authLimiter,
      body('email').isEmail().normalizeEmail(),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const user = await db.collection('USERS').findOne({ email: req.body.email });
          if (!user) return res.status(200).json({ success:true, message:'If the email exists, a reset link has been sent' });
          const resetToken = jwt.sign({ userId:user._id, email:user.email, type:'password-reset' }, jwtSecret, { expiresIn:'1h' });
          await db.collection('USERS').updateOne({ _id:user._id }, { $set:{ passwordResetToken:resetToken, passwordResetExpiry:new Date(Date.now()+3600000) } });
          const frontendOrigin = (process.env.CORS_ORIGIN || 'http://localhost:5173').replace(/\/$/, '');
          const resetUrl = `${frontendOrigin}/reset-password?token=${resetToken}`;
          logger.info(`[PASSWORD RESET] Reset URL for ${user.email}: ${resetUrl}`);
          if (process.env.RESEND_API_KEY) {
            try {
              const resend = new Resend(process.env.RESEND_API_KEY);
              const { error } = await resend.emails.send({
                from: 'NXL Beauty Bar <onboarding@resend.dev>',
                to: user.email,
                subject: 'Reset Your NXL Beauty Bar Password',
                html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;"><h2 style="font-family:Georgia,serif;color:#3d1f15;">NXL Beauty Bar</h2><h3 style="color:#6b3528;">Password Reset Request</h3><p style="color:#555;line-height:1.65;">Hi ${user.firstName},<br/><br/>We received a request to reset your password. Click the button below to choose a new password. This link expires in <strong>1 hour</strong>.</p><div style="text-align:center;margin:2rem 0;"><a href="${resetUrl}" style="background:#3d1f15;color:#ffe8d6;text-decoration:none;padding:0.85rem 2rem;border-radius:50px;font-weight:700;font-size:0.95rem;display:inline-block;">Reset My Password</a></div><p style="color:#9e7060;font-size:0.82rem;">If the button doesn't work, copy this link:<br/><a href="${resetUrl}" style="color:#a0502e;word-break:break-all;">${resetUrl}</a></p><p style="color:#b08070;font-size:0.78rem;">If you didn't request this, you can safely ignore this email.</p><hr style="border:none;border-top:1px solid #e0ccc4;margin:1.5rem 0;"/><p style="color:#b08070;font-size:0.7rem;text-align:center;">NXL Beauty Bar &middot; 1948 Mahalefele Rd, Dube, Soweto, 1800</p></div>`,
              });
              if (error) logger.error(`[PASSWORD RESET] Resend error for ${user.email}:`, error);
              else logger.info(`[PASSWORD RESET] Email sent successfully to ${user.email}`);
            } catch (emailErr) { logger.error(`[PASSWORD RESET] Resend exception for ${user.email}: ${emailErr.message}`); }
          } else { logger.warn('[PASSWORD RESET] RESEND_API_KEY not set — email not sent.'); }
          return res.status(200).json({ success:true, message:'If the email exists, a reset link has been sent' });
        } catch (err) { next(err); }
      }
    );

    app.post('/auth/reset-password', authLimiter,
      body('token').isString().notEmpty(),
      body('newPassword').isString().isLength({ min:8 }).matches(/[A-Z]/).matches(/[a-z]/).matches(/[0-9]/).matches(/[^A-Za-z0-9]/),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          let decoded;
          try {
            decoded = jwt.verify(req.body.token, jwtSecret);
            if (decoded.type !== 'password-reset') return res.status(400).json({ success:false, error:'Invalid reset token' });
          } catch (err) { return res.status(400).json({ success:false, error:'Invalid or expired reset token' }); }
          const user = await db.collection('USERS').findOne({ _id: new ObjectId(decoded.userId) });
          if (!user) return res.status(404).json({ success:false, error:'User not found' });
          if (user.passwordResetToken !== req.body.token || new Date() > new Date(user.passwordResetExpiry)) {
            return res.status(400).json({ success:false, error:'Invalid or expired reset token' });
          }
          const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
          await db.collection('USERS').updateOne({ _id:user._id }, { $set:{ password:hashedPassword, updatedAt:new Date() }, $unset:{ passwordResetToken:'', passwordResetExpiry:'' } });
          res.status(200).json({ success:true, message:'Password reset successfully' });
        } catch (err) { next(err); }
      }
    );

    app.post('/auth/refresh-token',
      body('refreshToken').isString().notEmpty(),
      async (req, res, next) => {
        try {
          const { refreshToken } = req.body;
          if (!refreshTokens.has(refreshToken)) return res.status(403).json({ success:false, error:'Invalid refresh token' });
          jwt.verify(refreshToken, jwtSecret, (err, user) => {
            if (err) return res.status(403).json({ success:false, error:'Invalid refresh token' });
            const token = jwt.sign({ userId:user.userId, email:user.email, role:user.role }, jwtSecret, { expiresIn:'1h' });
            res.status(200).json({ success:true, token });
          });
        } catch (err) { next(err); }
      }
    );

    // =====================
    // CRUD GENERATOR
    // =====================
    function crudRoutes(collectionName, route) {
      console.log(`Registering routes for /${route}`);

      let validators = [];
      if (collectionName === 'SERVICES') {
        validators = [body('name').isString().notEmpty(), body('durationMinutes').isInt({ min:15 }).custom(v => v % 15 === 0), body('price').isDecimal({ decimal_digits:'0,2' }).custom(v => parseFloat(v) > 0), body('isActive').isBoolean().optional()];
      } else if (collectionName === 'EMPLOYEES') {
        validators = [body('name').isString().notEmpty(), body('email').optional({ nullable:true }).isEmail().normalizeEmail(), body('servicesOffered').isArray({ min:1 }), body('servicesOffered.*').isMongoId(), body('isActive').isBoolean().optional()];
      } else if (collectionName === 'AVAILABILITY') {
        validators = [body('date').matches(/^\d{4}-\d{2}-\d{2}$/), body('time').matches(/^\d{2}:\d{2}$/), body('employeeId').custom(v => v === 'ALL' || /^[a-f\d]{24}$/i.test(v)), body('reason').isString().notEmpty()];
      } else if (collectionName === 'APPOINTMENTS') {
        validators = [
          body('date').custom((v, { req }) => { const n = normalizeAppointmentDateTime(v, req.body?.time); if (!n) return false; req.body.date = n.date; req.body.time = n.time; return true; }),
          body('time').custom((v, { req }) => { const n = normalizeAppointmentDateTime(req.body?.date, v); if (!n) return false; req.body.date = n.date; req.body.time = n.time; return true; }),
          body('employeeId').isMongoId(), body('serviceIds').isArray({ min:1 }), body('serviceIds.*').isMongoId()
        ];
      } else if (collectionName === 'PAYMENTS') {
        validators = [body('appointmentId').isMongoId(), body('type').optional().isIn(['deposit','full']), body('amount').isDecimal({ decimal_digits:'0,2' }).custom(v => parseFloat(v) > 0), body('method').isIn(['cash','card','online']), body('status').isIn(['pending','paid','refunded'])];
      }

      const putValidators =
        collectionName === 'SERVICES' ? [body('name').optional().isString().notEmpty(), body('durationMinutes').optional().isInt({ min:15 }).custom(v => v % 15 === 0), body('price').optional().isDecimal({ decimal_digits:'0,2' }).custom(v => parseFloat(v) > 0), body('isActive').optional().isBoolean()]
        : collectionName === 'EMPLOYEES' ? [body('name').optional().isString().notEmpty(), body('email').optional({ nullable:true }).isEmail().normalizeEmail(), body('servicesOffered').optional().isArray({ min:1 }), body('servicesOffered.*').optional().isMongoId(), body('isActive').optional().isBoolean()]
        : collectionName === 'AVAILABILITY' ? [body('date').optional().matches(/^\d{4}-\d{2}-\d{2}$/), body('time').optional().matches(/^\d{2}:\d{2}$/), body('employeeId').optional().custom(v => v === 'ALL' || /^[a-f\d]{24}$/i.test(v)), body('reason').optional().isString().notEmpty()]
        : collectionName === 'APPOINTMENTS' ? [
            body('date').optional().custom((v, { req }) => { const n = normalizeAppointmentDateTime(v, req.body?.time); if (!n) return false; req.body.date = n.date; req.body.time = n.time; return true; }),
            body('time').optional().custom((v, { req }) => { const n = normalizeAppointmentDateTime(req.body?.date, v); if (!n) return false; req.body.date = n.date; req.body.time = n.time; return true; }),
            body('employeeId').optional().isMongoId(), body('serviceIds').optional().isArray({ min:1 }), body('serviceIds.*').optional().isMongoId()
          ]
        : collectionName === 'PAYMENTS' ? [body('appointmentId').optional().isMongoId(), body('type').optional().isIn(['deposit','full']), body('amount').optional().isDecimal({ decimal_digits:'0,2' }).custom(v => parseFloat(v) > 0), body('method').optional().isIn(['cash','card','online']), body('status').optional().isIn(['pending','paid','refunded'])]
        : [];

      app.post(`/${route}`, authenticateToken, ...validators, async (req, res, next) => {
        if (!db) return res.status(500).json({ success:false, error:'Database not connected' });
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationError(res, errors.array());
        if (req.body._id) return res.status(400).json({ success:false, error:'Manual _id injection is not allowed' });
        delete req.body.createdAt; delete req.body.updatedAt;
        if (collectionName === 'USERS') delete req.body.role;
        req.body.createdAt = new Date(); req.body.updatedAt = new Date();
        if (req.body.employeeId && typeof req.body.employeeId === 'string' && req.body.employeeId !== 'ALL') req.body.employeeId = new ObjectId(req.body.employeeId);
        if (Array.isArray(req.body.serviceIds)) req.body.serviceIds = req.body.serviceIds.map(id => new ObjectId(id));
        if (Array.isArray(req.body.servicesOffered)) req.body.servicesOffered = req.body.servicesOffered.map(id => new ObjectId(id));
        if (req.body.appointmentId && typeof req.body.appointmentId === 'string') req.body.appointmentId = new ObjectId(req.body.appointmentId);
        if (collectionName === 'SERVICES' && req.body.price) req.body.price = Decimal128.fromString(String(req.body.price));
        if (collectionName === 'PAYMENTS' && req.body.amount) req.body.amount = Decimal128.fromString(String(req.body.amount));

        if (collectionName === 'EMPLOYEES') {
          const serviceIds = req.body.servicesOffered || [];
          const count = await db.collection('SERVICES').countDocuments({ _id:{ $in:serviceIds }, isActive:true });
          if (count !== serviceIds.length) return res.status(400).json({ success:false, error:'All referenced services must exist and be active' });
        }

        if (collectionName === 'APPOINTMENTS') {
          const emp = await db.collection('EMPLOYEES').findOne({ _id:req.body.employeeId, isActive:true });
          if (!emp) return res.status(400).json({ success:false, error:'Employee not found or inactive' });
          const serviceIds = req.body.serviceIds || [];
          const count = await db.collection('SERVICES').countDocuments({ _id:{ $in:serviceIds }, isActive:true });
          if (count !== serviceIds.length) return res.status(400).json({ success:false, error:'All services must exist and be active' });
          const services = await db.collection('SERVICES').find({ _id:{ $in:req.body.serviceIds } }).toArray();
          const totalDuration = services.reduce((sum, s) => sum + s.durationMinutes, 0);
          const requestedSlots = generateSlotRange(req.body.time, totalDuration);

          // ── 6 PM CUTOFF VALIDATION ───────────────────────────────────────
          // Appointments can reach 6 PM (18:00) but cannot extend beyond it
          if (requestedSlots.length > 0) {
            const lastSlot = requestedSlots[requestedSlots.length - 1];
            const [lastHour, lastMin] = lastSlot.split(':').map(Number);
            // Block if last slot is after 18:00 (extends past 6 PM)
            if (lastHour > 18 || (lastHour === 18 && lastMin > 0)) {
              return res.status(400).json({
                success: false,
                error: `This appointment would end at ${lastSlot}, which is past our 6 PM closing time. Please contact NXL Beauty Bar at 068 511 3394 or WhatsApp us for special arrangements.`,
              });
            }
          }
          // ──────────────────────────────────────────────────────────────────

          // ── Overlap check ────────────────────────────────────────────────
          // Only confirmed (paid) appointments block slots.
          // Pending/unpaid appointments intentionally do NOT hold slots —
          // abandoned checkouts should never block the calendar.
          // Fix: check full slot range (not just start time) to catch overlaps
          // from multi-service bookings that span 30+ min slots.
          const allActiveAppointments = await db.collection('APPOINTMENTS').find({
            date:          req.body.date,
            employeeId:    req.body.employeeId,
            status:        { $nin: ['cancelled', 'pending'] },
            paymentStatus: { $nin: ['unpaid'] },
          }).toArray();

          for (const existing of allActiveAppointments) {
            const existingServices = await db.collection('SERVICES').find({
              _id: { $in: existing.serviceIds || [] }
            }).toArray();
            const existingDuration = existingServices.reduce((sum, s) => sum + (s.durationMinutes || 30), 0);
            const existingSlots    = generateSlotRange(existing.time, existingDuration);

            const hasOverlap = requestedSlots.some(s => existingSlots.includes(s));
            if (hasOverlap) {
              return res.status(400).json({
                success: false,
                error: 'This appointment overlaps with an existing booking.',
              });
            }
          }
          // ────────────────────────────────────────────────────────────────
          const blocked = await db.collection('AVAILABILITY').findOne({ date:req.body.date, time:{ $in:requestedSlots }, $or:[{ employeeId:req.body.employeeId },{ employeeId:'ALL' }] });
          if (blocked) return res.status(400).json({ success:false, error:'One or more time slots are unavailable' });
          const totalPrice = services.reduce((sum, s) => sum + parseFloat(s.price), 0);
          req.body.totalPrice   = Decimal128.fromString(totalPrice.toFixed(2));
          req.body.occupiedSlots = requestedSlots; // stored for fast conflict queries
          req.body.status = (req.body.paymentStatus === 'paid' || req.body.paymentStatus === 'deposit_paid') ? 'booked' : 'pending';
          if (req.body.userId) req.body.userId = new ObjectId(req.body.userId);
          else if (req.user?.userId) req.body.userId = new ObjectId(req.user.userId);
          if (req.body.userId) {
            const clientUser = await db.collection('USERS').findOne({ _id:req.body.userId }, { projection:{ firstName:1, lastName:1 } });
            if (clientUser && clientUser.firstName && clientUser.lastName) {
              req.body.userName = `${clientUser.firstName} ${clientUser.lastName}`.trim();
            } else if (clientUser) {
              req.body.userName = clientUser.firstName || clientUser.lastName || 'Client';
            } else {
              req.body.userName = 'Client'; // fallback if user not found
            }
          }
          // Ensure userName is NEVER undefined, null, or "undefined undefined"
          if (!req.body.userName || 
              req.body.userName === 'undefined' || 
              req.body.userName === 'undefined undefined' ||
              req.body.userName === 'null' ||
              req.body.userName === 'null null' ||
              req.body.userName.trim() === '') {
            req.body.userName = 'Client';
          }
          if (req.body.paymentStatus && !['unpaid','deposit_paid','paid'].includes(req.body.paymentStatus)) return res.status(400).json({ success:false, error:'Invalid paymentStatus' });
          req.body.paymentStatus = req.body.paymentStatus || 'unpaid';
          delete req.body.totalDuration; delete req.body.contactNumber; delete req.body.stylist; delete req.body.manicureType; delete req.body.pedicureType;
          if (req.body.notes) req.body.notes = sanitiseText(req.body.notes, 500);
        }

        if (collectionName === 'PAYMENTS') {
          const appt = await db.collection('APPOINTMENTS').findOne({ _id:req.body.appointmentId });
          if (!appt) return res.status(400).json({ success:false, error:'Appointment does not exist' });
          const paymentType = req.body.type || 'full';
          const depositAmount = decimalToNumber(process.env.DEPOSIT_AMOUNT ?? 100);
          const paidAmount = decimalToNumber(req.body.amount);
          const total = decimalToNumber(appt.totalPrice);
          if (paidAmount == null || total == null) return res.status(400).json({ success:false, error:'Invalid payment amount' });
          if (paymentType === 'deposit') {
            if (depositAmount == null || paidAmount !== depositAmount) return res.status(400).json({ success:false, error:`Deposit must be ${depositAmount?.toFixed?.(2) ?? depositAmount}` });
            if (paidAmount > total) return res.status(400).json({ success:false, error:'Deposit cannot exceed appointment totalPrice' });
            req.body.type = 'deposit';
          } else {
            if (paidAmount !== total) return res.status(400).json({ success:false, error:'Payment amount must match appointment totalPrice' });
            req.body.type = 'full';
          }
          const exists = await db.collection('PAYMENTS').findOne({ appointmentId:req.body.appointmentId, type:req.body.type });
          if (exists) return res.status(400).json({ success:false, error:'Payment already exists for this appointment' });
          if (!['pending','paid'].includes(req.body.status)) return res.status(400).json({ success:false, error:'Invalid payment status' });
        }

        try {
          const result = await db.collection(collectionName).insertOne(req.body);
          if (!result.insertedId) return res.status(500).json({ success:false, error:'Failed to create document' });
          if (collectionName === 'APPOINTMENTS' && req.body.paymentStatus === 'paid' && req.body.paymentMethod) {
            const apptServices = await db.collection('SERVICES').find({ _id:{ $in:req.body.serviceIds } }).toArray();
            const totalPrice = apptServices.reduce((sum, s) => sum + parseFloat(s.price.toString()), 0);
            await db.collection('PAYMENTS').insertOne({ appointmentId:result.insertedId, type:'full', amount:Decimal128.fromString(totalPrice.toFixed(2)), method:req.body.paymentMethod, status:'paid', currency:'ZAR', createdAt:new Date() });
          }
          if (collectionName === 'APPOINTMENTS') {
            try {
              const bookedServices = await db.collection('SERVICES').find({ _id:{ $in:req.body.serviceIds } }).project({ name:1 }).toArray();
              const svcNames = bookedServices.map(s => s.name).join(', ');
              await db.collection('NOTIFICATIONS').insertOne({ message:`📅 New booking: ${req.body.userName || 'A client'} — ${svcNames} on ${req.body.date} at ${req.body.time}`, target:'staff', recipientId:null, createdBy:new ObjectId(req.user.userId), createdAt:new Date(), read:false, readAt:null });
              logger.info('Booking notification created', { appointmentId:result.insertedId, userName:req.body.userName, date:req.body.date, time:req.body.time });

              // ── Booking confirmation email ────────────────────────────────
              if (process.env.RESEND_API_KEY) {
                try {
                  const clientUser = await db.collection('USERS').findOne({ _id: req.body.userId }, { projection: { email:1, firstName:1, lastName:1 } });
                  if (clientUser?.email) {
                    const resend = new Resend(process.env.RESEND_API_KEY);
                    const formattedDate = new Date(req.body.date + 'T00:00:00').toLocaleDateString('en-ZA', { weekday:'long', day:'numeric', month:'long', year:'numeric' });
                    await resend.emails.send({
                      from:    'NXL Beauty Bar <onboarding@resend.dev>',
                      to:      clientUser.email,
                      subject: `Booking Confirmed — ${svcNames} on ${formattedDate}`,
                      html: `
                        <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;">
                          <h2 style="font-family:Georgia,serif;color:#3d1f15;margin-bottom:0.25rem;">NXL Beauty Bar</h2>
                          <h3 style="color:#6b3528;margin-top:0;">Booking Confirmed! 💅</h3>
                          <p style="color:#555;line-height:1.65;">Hi ${clientUser.firstName},</p>
                          <p style="color:#555;line-height:1.65;">Your appointment has been booked. Here are your details:</p>
                          <table style="width:100%;border-collapse:collapse;margin:1.25rem 0;background:#fff;border-radius:10px;overflow:hidden;">
                            <tr style="border-bottom:1px solid #e0ccc4;">
                              <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;width:40%;">Service</td>
                              <td style="padding:0.75rem 1rem;color:#555;">${svcNames}</td>
                            </tr>
                            <tr style="border-bottom:1px solid #e0ccc4;">
                              <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;">Date</td>
                              <td style="padding:0.75rem 1rem;color:#555;">${formattedDate}</td>
                            </tr>
                            <tr style="border-bottom:1px solid #e0ccc4;">
                              <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;">Time</td>
                              <td style="padding:0.75rem 1rem;color:#555;">${req.body.time}</td>
                            </tr>
                            <tr>
                              <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;">Deposit Paid</td>
                              <td style="padding:0.75rem 1rem;color:#276749;font-weight:700;">✓ R${Number(process.env.DEPOSIT_AMOUNT||100).toFixed(2)}</td>
                            </tr>
                          </table>
                          <div style="background:#fff8f3;border:1px solid #e0ccc4;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.25rem;">
                            <p style="margin:0;font-size:0.85rem;color:#6b3528;font-weight:700;">📍 Where to find us</p>
                            <p style="margin:0.35rem 0 0;font-size:0.82rem;color:#9e7060;">1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                            <p style="margin:0.25rem 0 0;font-size:0.82rem;color:#9e7060;">📞 068 511 3394 &nbsp;|&nbsp; 🕐 Mon–Sat 9AM–5PM</p>
                          </div>
                          <div style="background:#fff3f3;border:1px solid #fca5a5;border-radius:10px;padding:0.875rem 1.25rem;margin-bottom:1.25rem;">
                            <p style="margin:0;font-size:0.82rem;color:#c53030;font-weight:600;">⚠️ Please note</p>
                            <ul style="margin:0.4rem 0 0;padding-left:1.25rem;font-size:0.8rem;color:#9e7060;line-height:1.75;">
                              <li>R50 late fee applies per 15 minutes after your scheduled time</li>
                              <li>Arriving 30+ minutes late will result in appointment cancellation</li>
                              <li>48 hours notice required for cancellations</li>
                              <li>Your R${Number(process.env.DEPOSIT_AMOUNT||100).toFixed(2)} deposit is non-refundable</li>
                            </ul>
                          </div>
                          <p style="color:#9e7060;font-size:0.8rem;line-height:1.65;">Need to reschedule or have questions? WhatsApp us at <a href="https://wa.me/27685113394" style="color:#a0502e;">068 511 3394</a>.</p>
                          <hr style="border:none;border-top:1px solid #e0ccc4;margin:1.5rem 0;"/>
                          <p style="color:#b08070;font-size:0.7rem;text-align:center;margin:0;">NXL Beauty Bar &middot; 1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                        </div>
                      `,
                    });
                    logger.info(`[BOOKING EMAIL] Confirmation sent to ${clientUser.email}`, { appointmentId: result.insertedId });
                  }
                } catch (emailErr) {
                  logger.error(`[BOOKING EMAIL] Failed to send confirmation: ${emailErr.message}`);
                }
              }
              // ─────────────────────────────────────────────────────────────

            } catch (notifErr) { logger.warn('Failed to create booking notification:', { error:notifErr.message }); }
          }
          if (collectionName === 'PAYMENTS') {
            const nextStatus = req.body.type === 'deposit' ? 'deposit_paid' : 'paid';
            await db.collection('APPOINTMENTS').updateOne({ _id:req.body.appointmentId }, { $set:{ paymentStatus:nextStatus, updatedAt:new Date() } });

            // ── SMS confirmation after booking payment ────────────────────
          try {
            const apptForSMS = await db.collection('APPOINTMENTS').findOne({ _id: req.body.appointmentId });
            const clientForSMS = await db.collection('USERS').findOne({ _id: apptForSMS?.userId });
            if (clientForSMS?.phone) {
              const svcs = await db.collection('SERVICES').find({ _id:{ $in: apptForSMS.serviceIds||[] } }).project({ name:1 }).toArray();
              const svcNames = svcs.map(s => s.name).join(', ');
              await sendSMS(clientForSMS.phone,
                `NXL Beauty Bar: Payment confirmed! Your appointment for ${svcNames} on ${apptForSMS.date} at ${apptForSMS.time} is booked. See you soon! 💅`
              );
            }
            // In-app notification
            if (apptForSMS?.userId) {
              const svcs2    = apptForSMS._svcs || await db.collection('SERVICES').find({ _id:{ $in: apptForSMS.serviceIds||[] } }).project({ name:1 }).toArray();
              const svcNames = svcs2.map(s => s.name).join(', ');
              await notifyClient(apptForSMS.userId, {
                type:  'booking_confirmed',
                title: 'Booking Confirmed ✅',
                body:  `Your appointment for ${svcNames} on ${apptForSMS.date} at ${apptForSMS.time} is confirmed.`,
                link:  '/dashboard',
              });
            }
          } catch (smsErr) { logger.error(`[SMS] Booking confirm failed: ${smsErr.message}`); }
          // ──────────────────────────────────────────────────────────────

          // ── Award loyalty points for booking payment ──────────────────
            try {
              const apptForPoints = await db.collection('APPOINTMENTS').findOne({ _id: req.body.appointmentId });
              if (apptForPoints?.userId) {
                const amountPaid  = parseFloat(req.body.amount || 0);
                const earnedPts   = Math.floor(amountPaid * LOYALTY_CONFIG.pointsPerRand) + LOYALTY_CONFIG.bookingBonus;
                await awardPoints(apptForPoints.userId, earnedPts, `Booking payment — ${amountPaid.toFixed(2)} ZAR`, req.body.appointmentId);

                // ── Referral reward — first completed booking ─────────────
                try {
                  const booker = await db.collection('USERS').findOne({ _id: apptForPoints.userId }, { projection: { referredBy:1, firstName:1, referralRewardGiven:1 } });
                  if (booker?.referredBy && !booker.referralRewardGiven) {
                    await awardPoints(booker.referredBy, REFERRAL_CONFIG.referrerPoints, `Referral reward — ${booker.firstName} completed first booking`);
                    await db.collection('REFERRALS').updateOne(
                      { referrerId: booker.referredBy, refereeId: apptForPoints.userId },
                      { $set: { status: 'rewarded', pointsAwarded: REFERRAL_CONFIG.referrerPoints, rewardedAt: new Date(), updatedAt: new Date() } }
                    );
                    await db.collection('USERS').updateOne({ _id: apptForPoints.userId }, { $set: { referralRewardGiven: true } });
                    await notifyClient(booker.referredBy, {
                      type:  'loyalty_earned',
                      title: `Referral reward — +${REFERRAL_CONFIG.referrerPoints} points! 🏆`,
                      body:  `${booker.firstName} completed their first booking. You earned ${REFERRAL_CONFIG.referrerPoints} loyalty points!`,
                      link:  '/profile',
                      meta:  { points: REFERRAL_CONFIG.referrerPoints },
                    });
                    logger.info(`[REFERRAL] Rewarded referrer for ${booker.firstName}'s first booking`);
                  }
                } catch (refErr) { logger.error(`[REFERRAL] First booking reward failed: ${refErr.message}`); }
                // ─────────────────────────────────────────────────────────
              }
            } catch (loyaltyErr) { logger.error(`[LOYALTY] Booking award failed: ${loyaltyErr.message}`); }
            // ─────────────────────────────────────────────────────────────
          }
          res.status(201).json({ success:true, message:'Created', data:{ _id:result.insertedId, ...req.body } });
        } catch (err) {
          if (err.code === 121) return res.status(400).json({ success:false, error:'Schema validation failed', details:err.errInfo });
          if (err.code === 11000) return res.status(409).json({ success:false, error:'Duplicate key error' });
          next(err);
        }
      });

      app.put(`/${route}/:id`, authenticateToken, idValidator, ...putValidators, async (req, res, next) => {
        if (!db) return res.status(500).json({ success:false, error:'Database not connected' });
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationError(res, errors.array());
        if (req.body._id) return res.status(400).json({ success:false, error:'Manual _id injection is not allowed' });
        delete req.body.createdAt; delete req.body.updatedAt;
        if (collectionName === 'USERS') delete req.body.role;
        req.body.updatedAt = new Date();
        if (req.body.employeeId && typeof req.body.employeeId === 'string' && req.body.employeeId !== 'ALL') req.body.employeeId = new ObjectId(req.body.employeeId);
        if (Array.isArray(req.body.serviceIds)) req.body.serviceIds = req.body.serviceIds.map(id => new ObjectId(id));
        if (Array.isArray(req.body.servicesOffered)) req.body.servicesOffered = req.body.servicesOffered.map(id => new ObjectId(id));
        if (req.body.appointmentId && typeof req.body.appointmentId === 'string') req.body.appointmentId = new ObjectId(req.body.appointmentId);
        if (collectionName === 'SERVICES' && req.body.price) req.body.price = Decimal128.fromString(String(req.body.price));
        if (collectionName === 'PAYMENTS' && req.body.amount) req.body.amount = Decimal128.fromString(String(req.body.amount));
        if (collectionName === 'EMPLOYEES' && req.body.servicesOffered) {
          const count = await db.collection('SERVICES').countDocuments({ _id:{ $in:req.body.servicesOffered }, isActive:true });
          if (count !== req.body.servicesOffered.length) return res.status(400).json({ success:false, error:'All referenced services must exist and be active' });
        }
        if (collectionName === 'APPOINTMENTS') {
          const appt = await db.collection('APPOINTMENTS').findOne({ _id:new ObjectId(req.params.id) });
          if (!appt) return res.status(404).json({ success:false, error:'Appointment not found' });
          const validTransitions = { pending:['pending','booked','cancelled'], booked:['booked','cancelled','completed','no-show'], cancelled:['cancelled'], completed:['completed'], 'no-show':['no-show'] };
          if (req.body.status && !validTransitions[appt.status]?.includes(req.body.status)) return res.status(400).json({ success:false, error:'Invalid status transition' });

          // ── Overlap check on edit (if date/time/employee is changing) ──
          const newDate      = req.body.date       || appt.date;
          const newTime      = req.body.time       || appt.time;
          const newEmployee  = req.body.employeeId || appt.employeeId;
          const newServiceIds = req.body.serviceIds
            ? req.body.serviceIds
            : appt.serviceIds;

          const isTimeChange = req.body.date || req.body.time || req.body.employeeId || req.body.serviceIds;
          if (isTimeChange) {
            const editServices = await db.collection('SERVICES').find({ _id: { $in: newServiceIds } }).toArray();
            const editDuration = editServices.reduce((sum, s) => sum + (s.durationMinutes || 30), 0);
            const editSlots    = generateSlotRange(newTime, editDuration);

            // ── 6 PM CUTOFF VALIDATION (on edit) ───────────────────────────
            if (editSlots.length > 0) {
              const lastSlot = editSlots[editSlots.length - 1];
              const [lastHour, lastMin] = lastSlot.split(':').map(Number);
              if (lastHour > 18 || (lastHour === 18 && lastMin > 0)) {
                return res.status(400).json({
                  success: false,
                  error: `This appointment would end at ${lastSlot}, which is past our 6 PM closing time. Please contact NXL Beauty Bar at 068 511 3394 or WhatsApp us for special arrangements.`,
                });
              }
            }
            // ────────────────────────────────────────────────────────────────

            const conflicts = await db.collection('APPOINTMENTS').find({
              date:       newDate,
              employeeId: typeof newEmployee === 'string' ? new ObjectId(newEmployee) : newEmployee,
              status:     { $nin: ['cancelled'] },
              _id:        { $ne: new ObjectId(req.params.id) }, // exclude self
            }).toArray();

            for (const conflict of conflicts) {
              const cServices = await db.collection('SERVICES').find({ _id: { $in: conflict.serviceIds || [] } }).toArray();
              const cDuration = cServices.reduce((sum, s) => sum + (s.durationMinutes || 30), 0);
              const cSlots    = generateSlotRange(conflict.time, cDuration);
              if (editSlots.some(s => cSlots.includes(s))) {
                return res.status(400).json({ success:false, error:'The new time overlaps with an existing appointment.' });
              }
            }
          }
          // ─────────────────────────────────────────────────────────────
          if (req.body.paymentStatus) {
            if (!['unpaid','deposit_paid','paid'].includes(req.body.paymentStatus)) return res.status(400).json({ success:false, error:'Invalid paymentStatus' });
            if (req.body.paymentStatus === 'paid' && req.body.paymentMethod) {
              const existingPayment = await db.collection('PAYMENTS').findOne({ appointmentId:new ObjectId(req.params.id), type:'full' });
              if (!existingPayment) {
                const apptForPay = await db.collection('APPOINTMENTS').findOne({ _id:new ObjectId(req.params.id) });
                await db.collection('PAYMENTS').insertOne({ appointmentId:new ObjectId(req.params.id), type:'full', amount:apptForPay.totalPrice, method:req.body.paymentMethod || 'cash', status:'paid', createdAt:new Date(), updatedAt:new Date() });
              }
            }
          }
          if (req.body.serviceIds) {
            const count = await db.collection('SERVICES').countDocuments({ _id:{ $in:req.body.serviceIds }, isActive:true });
            if (count !== req.body.serviceIds.length) return res.status(400).json({ success:false, error:'All services must exist and be active' });
            const services = await db.collection('SERVICES').find({ _id:{ $in:req.body.serviceIds } }).toArray();
            req.body.totalPrice = Decimal128.fromString(services.reduce((sum, s) => sum + parseFloat(s.price), 0).toFixed(2));
          }
        }
        if (collectionName === 'PAYMENTS') {
          const payment = await db.collection('PAYMENTS').findOne({ _id:new ObjectId(req.params.id) });
          if (!payment) return res.status(404).json({ success:false, error:'Payment not found' });
          const validTransitions = { pending:['paid','refunded'], paid:['refunded'], refunded:[] };
          if (req.body.status && !validTransitions[payment.status].includes(req.body.status)) return res.status(400).json({ success:false, error:'Invalid payment status transition' });
        }
        try {
          const updatedDoc = await db.collection(collectionName).findOneAndUpdate({ _id:new ObjectId(req.params.id) }, { $set:req.body }, { returnDocument:'after' });
          if (!updatedDoc) return res.status(404).json({ success:false, error:'Document not found' });

          // ── Cancellation email ────────────────────────────────────────────
          if (
            collectionName === 'APPOINTMENTS' &&
            req.body.status === 'cancelled' &&
            process.env.RESEND_API_KEY
          ) {
            try {
              const apptDoc  = updatedDoc;
              const clientUser = await db.collection('USERS').findOne(
                { _id: apptDoc.userId },
                { projection: { email:1, firstName:1 } }
              );
              if (clientUser?.email) {
                const resend = new Resend(process.env.RESEND_API_KEY);
                const svcNames = (apptDoc.serviceIds || []).length > 0
                  ? (await db.collection('SERVICES').find({ _id: { $in: apptDoc.serviceIds } }).project({ name:1 }).toArray()).map(s => s.name).join(', ')
                  : 'Appointment';
                const formattedDate = new Date(apptDoc.date + 'T00:00:00').toLocaleDateString('en-ZA', { weekday:'long', day:'numeric', month:'long', year:'numeric' });
                const depositAmount = Number(process.env.DEPOSIT_AMOUNT || 100);
                const wasPaid = apptDoc.paymentStatus !== 'unpaid';
                await resend.emails.send({
                  from:    'NXL Beauty Bar <onboarding@resend.dev>',
                  to:      clientUser.email,
                  subject: `Appointment Cancelled — ${svcNames} on ${formattedDate}`,
                  html: `
                    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;">
                      <h2 style="font-family:Georgia,serif;color:#3d1f15;margin-bottom:0.25rem;">NXL Beauty Bar</h2>
                      <h3 style="color:#6b3528;margin-top:0;">Appointment Cancelled</h3>
                      <p style="color:#555;line-height:1.65;">Hi ${clientUser.firstName},</p>
                      <p style="color:#555;line-height:1.65;">Your appointment has been cancelled. Here are the details:</p>
                      <table style="width:100%;border-collapse:collapse;margin:1.25rem 0;background:#fff;border-radius:10px;overflow:hidden;">
                        <tr style="border-bottom:1px solid #e0ccc4;">
                          <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;width:40%;">Service</td>
                          <td style="padding:0.75rem 1rem;color:#555;">${svcNames}</td>
                        </tr>
                        <tr style="border-bottom:1px solid #e0ccc4;">
                          <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;">Date</td>
                          <td style="padding:0.75rem 1rem;color:#555;">${formattedDate}</td>
                        </tr>
                        <tr>
                          <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;">Time</td>
                          <td style="padding:0.75rem 1rem;color:#555;">${apptDoc.time}</td>
                        </tr>
                      </table>
                      ${wasPaid ? `
                      <div style="background:#fff3f3;border:1px solid #fca5a5;border-radius:10px;padding:0.875rem 1.25rem;margin-bottom:1.25rem;">
                        <p style="margin:0;font-size:0.82rem;color:#c53030;font-weight:600;">💳 Deposit Note</p>
                        <p style="margin:0.35rem 0 0;font-size:0.8rem;color:#9e7060;">Your R${depositAmount.toFixed(2)} booking deposit is non-refundable per our cancellation policy.</p>
                      </div>
                      ` : ''}
                      <p style="color:#9e7060;font-size:0.82rem;line-height:1.65;">We'd love to see you again! To book a new appointment, visit <a href="${(process.env.CORS_ORIGIN || 'https://nxlbeautybar.co.za').replace(/\/$/, '')}/dashboard" style="color:#a0502e;">nxlbeautybar.co.za</a> or WhatsApp us at <a href="https://wa.me/27685113394" style="color:#a0502e;">068 511 3394</a>.</p>
                      <hr style="border:none;border-top:1px solid #e0ccc4;margin:1.5rem 0;"/>
                      <p style="color:#b08070;font-size:0.7rem;text-align:center;margin:0;">NXL Beauty Bar &middot; 1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                    </div>
                  `,
                });
                logger.info(`[CANCEL EMAIL] Sent to ${clientUser.email}`, { appointmentId: req.params.id });
              }
            } catch (emailErr) {
              logger.error(`[CANCEL EMAIL] Failed: ${emailErr.message}`);
            }
          }
          // ─────────────────────────────────────────────────────────────────

          res.status(200).json({ success:true, message:'Updated', data:updatedDoc });
        } catch (err) {
          if (err.code === 121) return res.status(400).json({ success:false, error:'Schema validation failed', details:err.errInfo });
          if (err.code === 11000) return res.status(409).json({ success:false, error:'Duplicate key error' });
          next(err);
        }
      });

      app.get(`/${route}`, authenticateToken, async (req, res, next) => {
        if (!db) return res.status(500).json({ success:false, error:'Database not connected' });
        try {
          // ── Pagination support ──────────────────────────────────────────
          const page  = Math.max(1, parseInt(req.query.page  || '1',  10));
          const limit = Math.min(500, Math.max(1, parseInt(req.query.limit || '500', 10)));
          const skip  = (page - 1) * limit;

          const total = await db.collection(collectionName).countDocuments({});
          let docs = await db.collection(collectionName).find({}).sort({ createdAt:-1 }).skip(skip).limit(limit).toArray();
          // ────────────────────────────────────────────────────────────────

          if (collectionName === 'APPOINTMENTS') {
            const userIds = [...new Set(docs.map(d => d.userId))];
            const employeeIds = [...new Set(docs.map(d => d.employeeId))];
            const serviceIds = [...new Set(docs.flatMap(d => d.serviceIds))];
            const users = await db.collection('USERS').find({ _id:{ $in:userIds } }).project({ password:0 }).toArray();
            const employees = await db.collection('EMPLOYEES').find({ _id:{ $in:employeeIds } }).toArray();
            const services = await db.collection('SERVICES').find({ _id:{ $in:serviceIds } }).toArray();
            const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
            const empMap = Object.fromEntries(employees.map(e => [e._id.toString(), e]));
            const svcMap = Object.fromEntries(services.map(s => [s._id.toString(), s]));
            docs = docs.map(doc => {
              const user = userMap[doc.userId.toString()];
              // Use database userName if it's valid, otherwise try to construct from user object
              let displayName = doc.userName;
              if (!displayName || displayName === 'undefined' || displayName === 'undefined undefined' || displayName === 'null' || displayName === 'null null' || displayName.trim() === '') {
                if (user?.firstName && user?.lastName) {
                  displayName = `${user.firstName} ${user.lastName}`;
                } else if (user?.firstName) {
                  displayName = user.firstName;
                } else if (user?.lastName) {
                  displayName = user.lastName;
                } else {
                  displayName = 'Client';
                }
              }
              return { 
                ...doc, 
                userName: displayName, 
                user, 
                employee: empMap[doc.employeeId.toString()], 
                services: doc.serviceIds.map(id => svcMap[id.toString()]).filter(Boolean), 
                totalDuration: doc.totalDuration || doc.serviceIds.reduce((sum, id) => { const svc = svcMap[id.toString()]; return sum + (svc?.durationMinutes || 0); }, 0) 
              };
            });
          }
          res.status(200).json({ success:true, data:docs, total, page, pages: Math.ceil(total/limit), limit });
        } catch (err) { next(err); }
      });

      app.get(`/${route}/:id`, authenticateToken, idValidator, async (req, res, next) => {
        if (!db) return res.status(500).json({ success:false, error:'Database not connected' });
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationError(res, errors.array());
        try {
          let doc = await db.collection(collectionName).findOne({ _id:new ObjectId(req.params.id) });
          if (!doc) return res.status(404).json({ success:false, error:'Document not found' });
          if (collectionName === 'APPOINTMENTS') {
            const user = await db.collection('USERS').findOne({ _id:doc.userId }, { projection:{ password:0 } });
            const employee = await db.collection('EMPLOYEES').findOne({ _id:doc.employeeId });
            const services = await db.collection('SERVICES').find({ _id:{ $in:doc.serviceIds } }).toArray();
            doc = { ...doc, user, employee, services };
          }
          res.status(200).json({ success:true, data:doc });
        } catch (err) { next(err); }
      });

      app.delete(`/${route}/:id`, authenticateToken, authorizeRole('admin'), idValidator, async (req, res, next) => {
        if (!db) return res.status(500).json({ success:false, error:'Database not connected' });
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationError(res, errors.array());
        if (collectionName === 'EMPLOYEES') {
          const future = await db.collection('APPOINTMENTS').findOne({ employeeId:new ObjectId(req.params.id), date:{ $gte:new Date().toISOString().slice(0,10) } });
          if (future) return res.status(400).json({ success:false, error:'Cannot delete employee with future appointments' });
          const result = await db.collection(collectionName).updateOne({ _id:new ObjectId(req.params.id) }, { $set:{ isActive:false, updatedAt:new Date() } });
          if (result.matchedCount === 0) return res.status(404).json({ success:false, error:'Document not found' });
          return res.status(200).json({ success:true, message:'Soft deleted successfully' });
        }
        if (collectionName === 'SERVICES') {
          const future = await db.collection('APPOINTMENTS').findOne({ serviceIds:new ObjectId(req.params.id), date:{ $gte:new Date().toISOString().slice(0,10) } });
          if (future) return res.status(400).json({ success:false, error:'Cannot delete service linked to future appointments' });
          const result = await db.collection(collectionName).updateOne({ _id:new ObjectId(req.params.id) }, { $set:{ isActive:false, updatedAt:new Date() } });
          if (result.matchedCount === 0) return res.status(404).json({ success:false, error:'Document not found' });
          return res.status(200).json({ success:true, message:'Soft deleted successfully' });
        }
        try {
          const result = await db.collection(collectionName).deleteOne({ _id:new ObjectId(req.params.id) });
          if (result.deletedCount === 0) return res.status(404).json({ success:false, error:'Document not found' });
          res.status(200).json({ success:true, message:'Deleted successfully' });
        } catch (err) { next(err); }
      });
    }

    // =====================
    // YOCO — APPOINTMENT PAYMENTS
    // =====================
    app.post('/payments', authenticateToken, paymentLimiter, async (req, res, next) => {
      try {
        const { appointmentId, loyaltyPointsToRedeem, discountCode } = req.body;
        if (!appointmentId) return res.status(400).json({ success:false, error:'appointmentId is required' });
        let apptId;
        try { apptId = new ObjectId(appointmentId); } catch { return res.status(400).json({ success:false, error:'Invalid appointmentId' }); }
        const appt = await db.collection('APPOINTMENTS').findOne({ _id:apptId });
        if (!appt) return res.status(404).json({ success:false, error:'Appointment not found' });
        const existing = await db.collection('PAYMENTS').findOne({ appointmentId:apptId });
        if (existing && existing.status === 'paid') return res.status(409).json({ success:false, error:'Appointment already paid' });
        const frontendUrl = process.env.FRONTEND_URL || 'https://nxlbeautybar.co.za';
        const depositAmount = Number(process.env.DEPOSIT_AMOUNT || 100);
        const amountInCents = Math.round(depositAmount * 100);
        logger.info('Yoco: creating checkout session', { appointmentId, amountInCents, loyaltyPointsToRedeem, discountCode });
        
        // Build metadata with loyalty and discount info
        const apptSnapshot = { 
          appointmentId, 
          date:appt.date, 
          time:appt.time, 
          userId:String(appt.userId), 
          employeeId:String(appt.employeeId), 
          serviceIds:(appt.serviceIds||[]).map(String), 
          totalPrice:String(appt.totalPrice), 
          userName:appt.userName||'',
          loyaltyPointsToRedeem: loyaltyPointsToRedeem ? parseInt(loyaltyPointsToRedeem) : null,
          discountCode: discountCode || null,
        };
        
        const yocoResponse = await fetchFn('https://payments.yoco.com/api/checkouts', {
          method:'POST',
          headers:{ 'Content-Type':'application/json', 'Authorization':`Bearer ${process.env.YOCO_SECRET_KEY}` },
          body:JSON.stringify({ amount:amountInCents, currency:'ZAR', successUrl:`${frontendUrl}/payment-success?appointmentId=${appointmentId}`, cancelUrl:`${frontendUrl}/payment-cancel?appointmentId=${appointmentId}`, failureUrl:`${frontendUrl}/payment-cancel?appointmentId=${appointmentId}`, metadata:apptSnapshot }),
        });
        if (!yocoResponse.ok) {
          const errBody = await yocoResponse.json().catch(() => ({}));
          logger.error('Yoco checkout creation failed', { status:yocoResponse.status, body:errBody });
          return res.status(500).json({ success:false, error:'Could not create Yoco payment session. Please try again.' });
        }
        const yocoData = await yocoResponse.json();
        logger.info('Yoco: checkout session created', { appointmentId, checkoutId:yocoData.id });
        try {
          await db.collection('PAYMENTS').updateOne(
            { appointmentId:apptId, type:'deposit' },
            { $set:{ appointmentId:apptId, type:'deposit', amount:Decimal128.fromString(depositAmount.toFixed(2)), method:'online', status:'pending', yocoCheckoutId:yocoData.id, updatedAt:new Date(), apptSnapshot:{ date:appt.date, time:appt.time, userId:appt.userId, employeeId:appt.employeeId, serviceIds:appt.serviceIds, totalPrice:appt.totalPrice, userName:appt.userName||'', loyaltyPointsToRedeem:loyaltyPointsToRedeem?parseInt(loyaltyPointsToRedeem):null, discountCode:discountCode||null } }, $setOnInsert:{ createdAt:new Date() } },
            { upsert:true }
          );
        } catch (payErr) { logger.error('Yoco: FAILED to save pending payment record', { appointmentId, error:payErr.message }); }
        return res.json({ success:true, checkoutUrl:yocoData.redirectUrl, checkoutId:yocoData.id });
      } catch (err) { logger.error('Yoco payment init error:', err); next(err); }
    });

    // ── GET /loyalty/booking-preview/:appointmentId — how many pts can be used ──
    app.get('/loyalty/booking-preview/:id', authenticateToken, async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const userId  = new ObjectId(req.user.userId);
        const appt    = await db.collection('APPOINTMENTS').findOne({ _id: new ObjectId(req.params.id), userId });
        if (!appt) return res.status(404).json({ success:false, error:'Appointment not found' });

        const account       = await getLoyaltyAccount(userId);
        const depositAmount = parseFloat(process.env.DEPOSIT_AMOUNT || 100);
        const totalPrice    = parseFloat(appt.totalPrice?.toString() || 0);

        // Balance = amount still owed at salon after deposit
        const balance = Math.max(0, totalPrice - depositAmount);

        // Max points usable = up to 50% of the balance (not the deposit)
        const maxDiscount  = balance * (LOYALTY_CONFIG.maxRedemptionPct / 100);
        const maxPtsUsable = Math.floor(maxDiscount / LOYALTY_CONFIG.pointValue);
        const availablePts = Math.min(account.points, maxPtsUsable);
        const discount     = parseFloat((availablePts * LOYALTY_CONFIG.pointValue).toFixed(2));
        const newBalance   = Math.max(0, balance - discount);

        res.json({
          success: true,
          data: {
            currentPoints:   account.points,
            maxPointsUsable: availablePts,
            discountAmount:  discount,
            depositAmount,          // always R100, never changes
            totalPrice,
            balance,                // what they owe at salon
            newBalance,             // balance after points applied
            pointValue:      LOYALTY_CONFIG.pointValue,
            minRedemption:   LOYALTY_CONFIG.minRedemption,
            canRedeem:       account.points >= LOYALTY_CONFIG.minRedemption && balance > 0,
          },
        });
      } catch (err) { next(err); }
    });
    // ──────────────────────────────────────────────────────────────────────
    app.post('/payments/verify', authenticateToken, async (req, res, next) => {
      try {
        const { appointmentId, loyaltyPointsToRedeem, discountCode } = req.body;
        if (!appointmentId) return res.status(400).json({ success:false, error:'appointmentId is required' });
        let apptId;
        try { apptId = new ObjectId(appointmentId); } catch { return res.status(400).json({ success:false, error:'Invalid appointmentId' }); }
        const appt = await db.collection('APPOINTMENTS').findOne({ _id:apptId });
        if (!appt) return res.status(404).json({ success:false, error:'Appointment not found' });
        if (appt.status === 'booked' && appt.paymentStatus === 'deposit_paid') { return res.json({ success:true, alreadyConfirmed:true }); }
        await db.collection('APPOINTMENTS').updateOne({ _id:apptId }, { $set:{ status:'booked', paymentStatus:'deposit_paid', updatedAt:new Date() } });
        await db.collection('PAYMENTS').updateOne({ appointmentId:apptId, status:{ $ne:'paid' } }, { $set:{ status:'paid', paidAt:new Date(), updatedAt:new Date() } });

        // ── Redeem loyalty points against balance (not deposit) ───────────
        if (loyaltyPointsToRedeem && parseInt(loyaltyPointsToRedeem) >= LOYALTY_CONFIG.minRedemption) {
          try {
            const userId   = appt.userId;
            console.log(`[LOYALTY REDEEM] Starting - userId: ${userId}, loyaltyPointsToRedeem: ${loyaltyPointsToRedeem}`);
            
            const account  = await getLoyaltyAccount(userId);
            console.log(`[LOYALTY REDEEM] Account fetched - currentPoints: ${account.points}`);
            
            const pts      = Math.min(parseInt(loyaltyPointsToRedeem), account.points);
            console.log(`[LOYALTY REDEEM] Calculated pts to redeem: ${pts}, minRedemption: ${LOYALTY_CONFIG.minRedemption}`);
            
            if (pts >= LOYALTY_CONFIG.minRedemption) {
              const discount = parseFloat((pts * LOYALTY_CONFIG.pointValue).toFixed(2));
              console.log(`[LOYALTY REDEEM] About to call redeemPoints with pts=${pts}, discount=${discount}`);
              
              await redeemPoints(userId, pts, `Redeemed against balance — ${pts} pts = R${discount} off at salon`, apptId);
              console.log(`[LOYALTY REDEEM] redeemPoints completed successfully`);
              
              // Store on appointment so admin can see and deduct from balance due
              await db.collection('APPOINTMENTS').updateOne(
                { _id: apptId },
                { $set: { loyaltyPointsRedeemed: pts, loyaltyBalanceDiscount: discount, updatedAt: new Date() } }
              );
              console.log(`[LOYALTY REDEEM] Appointment updated with redemption info`);
              
              await notifyClient(userId, {
                type:  'loyalty_redeemed',
                title: `${pts} Points Redeemed 🎁`,
                body:  `R${discount} will be deducted from your balance due at the salon.`,
                link:  '/dashboard',
              });
              console.log(`[LOYALTY REDEEM] Client notified`);
            } else {
              console.log(`[LOYALTY REDEEM] pts=${pts} is less than minRedemption=${LOYALTY_CONFIG.minRedemption}, skipping redemption`);
            }
          } catch (lErr) { 
            console.error(`[LOYALTY REDEEM] ERROR: ${lErr.message}`);
            console.error(`[LOYALTY REDEEM] Stack: ${lErr.stack}`);
            logger.error(`[LOYALTY] Booking redemption failed: ${lErr.message}`); 
          }
        } else {
          console.log(`[LOYALTY REDEEM] Condition not met - loyaltyPointsToRedeem: ${loyaltyPointsToRedeem}, minRedemption: ${LOYALTY_CONFIG.minRedemption}`);
        }
        // ──────────────────────────────────────────────────────────────────

        // ── Apply discount code to booking balance ────────────────────────
        if (discountCode) {
          try {
            const found = await db.collection('DISCOUNT_CODES').findOne({
              code: discountCode.toUpperCase().trim(), isActive: true,
              $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
            });
            if (found && !(found.usageLimit && found.usedCount >= found.usageLimit)) {
              if (!found.forUserId || String(found.forUserId) === String(appt.userId)) {
                const depositAmount = parseFloat(process.env.DEPOSIT_AMOUNT || 100);
                const totalPrice    = parseFloat(appt.totalPrice?.toString() || 0);
                const balance       = Math.max(0, totalPrice - depositAmount);
                const discountAmt   = found.type === 'percentage'
                  ? parseFloat((balance * found.value / 100).toFixed(2))
                  : Math.min(found.value, balance);

                await db.collection('APPOINTMENTS').updateOne(
                  { _id: apptId },
                  { $set: { discountCode: found.code, discountAmount: discountAmt, updatedAt: new Date() } }
                );
                await db.collection('DISCOUNT_CODES').updateOne(
                  { _id: found._id },
                  { $inc: { usedCount: 1 }, $set: { updatedAt: new Date() } }
                );
                logger.info(`[DISCOUNT] Code ${found.code} applied to booking ${apptId} — R${discountAmt} off`);
              }
            }
          } catch (dcErr) { logger.error(`[DISCOUNT] Booking code apply failed: ${dcErr.message}`); }
        }
        // ──────────────────────────────────────────────────────────────────

        return res.json({ success:true });
      } catch (err) { next(err); }
    });

    app.post('/payments/webhook', (req, res) => {
      res.status(200).send('OK');
      setImmediate(async () => {
        try {
          const event = req.body;
          console.log('[WEBHOOK DEBUG] Full event received:', JSON.stringify(event, null, 2));
          logger.info('Yoco webhook received', { type:event.type, payloadId:event.payload?.id });
          if (!event?.type) { logger.error('Yoco webhook: empty or malformed body'); return; }
          const webhookSecret = process.env.YOCO_WEBHOOK_SECRET;
          const wSig = req.headers['webhook-signature'] || req.headers['svix-signature'];
          const wTimestamp = req.headers['webhook-timestamp'] || req.headers['svix-timestamp'];
          const wId = req.headers['webhook-id'] || req.headers['svix-id'];
          const yocoSig = req.headers['x-yoco-signature'];
          if (webhookSecret) {
            if (wSig && wTimestamp && wId) {
              if (req.rawBody) {
                const toSign = `${wId}.${wTimestamp}.${req.rawBody.toString('utf8')}`;
                const secretBytes = Buffer.from(webhookSecret.startsWith('whsec_') ? webhookSecret.slice(6) : webhookSecret, 'base64');
                const expected = crypto.createHmac('sha256', secretBytes).update(toSign).digest('base64');
                const matched = wSig.split(' ').some(part => { const [, sigB64] = part.split(','); return sigB64 === expected; });
                if (!matched) logger.error('Yoco webhook: signature mismatch — processing anyway', { wId });
              }
            } else if (yocoSig && req.rawBody) {
              const expected = crypto.createHmac('sha256', webhookSecret).update(req.rawBody).digest('hex');
              if (yocoSig !== expected) logger.error('Yoco webhook: x-yoco-signature mismatch — processing anyway');
            }
          }
          if (event.type === 'payment.succeeded') {
            const appointmentId = event.metadata?.appointmentId || event.payload?.metadata?.appointmentId;
            const checkoutId = event.payloadId || event.payload?.id;
            let loyaltyPointsToRedeem = event.metadata?.loyaltyPointsToRedeem || event.payload?.metadata?.loyaltyPointsToRedeem;
            let discountCode = event.metadata?.discountCode || event.payload?.metadata?.discountCode;
            
            console.log('[WEBHOOK DEBUG] Extracted from event:', { appointmentId, checkoutId, loyaltyPointsToRedeem, discountCode });
            console.log('[WEBHOOK DEBUG] event.metadata:', event.metadata);
            console.log('[WEBHOOK DEBUG] event.payload?.metadata:', event.payload?.metadata);
            
            // FIX: If metadata not in webhook, fetch from PAYMENTS collection
            if (!loyaltyPointsToRedeem || !discountCode) {
              try {
                let apptIdObj;
                try { apptIdObj = new ObjectId(appointmentId); } catch { apptIdObj = null; }
                if (apptIdObj) {
                  const paymentRecord = await db.collection('PAYMENTS').findOne({ appointmentId: apptIdObj });
                  console.log('[WEBHOOK DEBUG] Fetched PAYMENTS record apptSnapshot:', paymentRecord?.apptSnapshot);
                  if (paymentRecord?.apptSnapshot) {
                    loyaltyPointsToRedeem = loyaltyPointsToRedeem || paymentRecord.apptSnapshot.loyaltyPointsToRedeem;
                    discountCode = discountCode || paymentRecord.apptSnapshot.discountCode;
                    console.log('[WEBHOOK DEBUG] Updated from PAYMENTS:', { loyaltyPointsToRedeem, discountCode });
                  }
                }
              } catch (fetchErr) {
                console.error('[WEBHOOK DEBUG] Error fetching PAYMENTS record:', fetchErr.message);
              }
            }
            
            if (event.payload?.metadata?.type === 'shop_order') {
              const shopOrderId = event.payload?.metadata?.orderId;
              if (shopOrderId) {
                await db.collection('ORDERS').updateOne({ _id:new ObjectId(shopOrderId) }, { $set:{ status:'confirmed', paymentStatus:'paid', yocoPaymentId:checkoutId, updatedAt:new Date() } });
                const order = await db.collection('ORDERS').findOne({ _id:new ObjectId(shopOrderId) });
                if (order?.items) { for (const item of order.items) { await db.collection('PRODUCTS').updateOne({ _id:item.productId }, { $inc:{ stock:-item.quantity } }); } }
                logger.info('Shop order confirmed via webhook', { shopOrderId });
              }
              return;
            }
            if (!appointmentId) { logger.error('Yoco webhook: no appointmentId in metadata'); return; }
            let apptId;
            try { apptId = new ObjectId(appointmentId); } catch { return; }
            const alreadyPaid = await db.collection('PAYMENTS').findOne({ appointmentId:apptId, status:'paid' });
            if (alreadyPaid) { logger.info('Yoco webhook: already processed', { appointmentId }); return; }
            const depositAmount = Number(process.env.DEPOSIT_AMOUNT || 100);
            await db.collection('PAYMENTS').updateOne(
              { appointmentId:apptId },
              { $set:{ status:'paid', yocoPaymentId:checkoutId, paidAt:new Date(), updatedAt:new Date() }, $setOnInsert:{ appointmentId:apptId, type:'deposit', amount:Decimal128.fromString(depositAmount.toFixed(2)), method:'online', createdAt:new Date() } },
              { upsert:true }
            );
            const apptResult = await db.collection('APPOINTMENTS').updateOne({ _id:apptId }, { $set:{ paymentStatus:'deposit_paid', status:'booked', updatedAt:new Date() } });
            if (apptResult.matchedCount === 0) {
              const payRecord = await db.collection('PAYMENTS').findOne({ appointmentId:apptId });
              const snap = payRecord?.apptSnapshot || event.metadata || event.payload?.metadata;
              if (snap && snap.date && snap.time && snap.userId && snap.employeeId && snap.serviceIds) {
                try {
                  await db.collection('APPOINTMENTS').updateOne({ _id:apptId }, { $set:{ _id:apptId, date:snap.date, time:snap.time, userId:typeof snap.userId==='string'?new ObjectId(snap.userId):snap.userId, employeeId:typeof snap.employeeId==='string'?new ObjectId(snap.employeeId):snap.employeeId, serviceIds:(snap.serviceIds||[]).map(id => typeof id==='string'?new ObjectId(id):id), totalPrice:typeof snap.totalPrice==='string'?Decimal128.fromString(snap.totalPrice):snap.totalPrice, userName:snap.userName||'', status:'booked', paymentStatus:'deposit_paid', createdAt:new Date(), updatedAt:new Date() } }, { upsert:true });
                } catch (recreateErr) { logger.error('Yoco webhook: failed to recreate appointment', { error:recreateErr.message }); }
              }
            }

            // ── REDEEM LOYALTY POINTS ─────────────────────────────────────
            if (loyaltyPointsToRedeem && parseInt(loyaltyPointsToRedeem) >= LOYALTY_CONFIG.minRedemption) {
              try {
                const appt = await db.collection('APPOINTMENTS').findOne({ _id: apptId });
                if (appt) {
                  const userId = appt.userId;
                  console.log(`[WEBHOOK LOYALTY] Starting - userId: ${userId}, loyaltyPointsToRedeem: ${loyaltyPointsToRedeem}`);
                  
                  const account = await getLoyaltyAccount(userId);
                  console.log(`[WEBHOOK LOYALTY] Account fetched - currentPoints: ${account.points}`);
                  
                  const pts = Math.min(parseInt(loyaltyPointsToRedeem), account.points);
                  console.log(`[WEBHOOK LOYALTY] Calculated pts to redeem: ${pts}, minRedemption: ${LOYALTY_CONFIG.minRedemption}`);
                  
                  if (pts >= LOYALTY_CONFIG.minRedemption) {
                    const discount = parseFloat((pts * LOYALTY_CONFIG.pointValue).toFixed(2));
                    console.log(`[WEBHOOK LOYALTY] About to call redeemPoints with pts=${pts}, discount=${discount}`);
                    
                    await redeemPoints(userId, pts, `Redeemed against balance — ${pts} pts = R${discount} off at salon`, apptId);
                    console.log(`[WEBHOOK LOYALTY] redeemPoints completed successfully`);
                    
                    // Store result on appointment
                    await db.collection('APPOINTMENTS').updateOne(
                      { _id: apptId },
                      { $set: { loyaltyPointsRedeemed: pts, loyaltyBalanceDiscount: discount, updatedAt: new Date() } }
                    );
                    console.log(`[WEBHOOK LOYALTY] Appointment updated with redemption info`);
                    
                    await notifyClient(userId, {
                      type:  'loyalty_redeemed',
                      title: `${pts} Points Redeemed 🎁`,
                      body:  `R${discount} will be deducted from your balance due at the salon.`,
                      link:  '/dashboard',
                    });
                    console.log(`[WEBHOOK LOYALTY] Client notified`);
                  } else {
                    console.log(`[WEBHOOK LOYALTY] pts=${pts} is less than minRedemption=${LOYALTY_CONFIG.minRedemption}, skipping redemption`);
                  }
                }
              } catch (loyaltyErr) {
                console.error(`[WEBHOOK LOYALTY] ERROR: ${loyaltyErr.message}`);
                console.error(`[WEBHOOK LOYALTY] Stack: ${loyaltyErr.stack}`);
                logger.error(`[WEBHOOK LOYALTY] Webhook redemption failed: ${loyaltyErr.message}`);
              }
            } else {
              console.log(`[WEBHOOK LOYALTY] Condition not met - loyaltyPointsToRedeem: ${loyaltyPointsToRedeem}, minRedemption: ${LOYALTY_CONFIG.minRedemption}`);
            }
            // ─────────────────────────────────────────────────────────────
          }
        } catch (err) {
          if (err.code === 11000) { logger.info('Yoco webhook: duplicate — already processed'); return; }
          logger.error('Yoco webhook error', { error:err.message });
        }
      });
    });

    app.post('/appointments/check-availability', authenticateToken, async (req, res) => {
      try {
        const { date, time, employeeId, appointmentId } = req.body;
        if (!date || !time) return res.status(400).json({ success:false, error:'date and time are required' });
        const query = { date, status:{ $nin:['cancelled','pending'] }, paymentStatus:{ $in:['deposit_paid','paid'] } };
        if (employeeId) { try { query.employeeId = new ObjectId(employeeId); } catch {} }
        if (appointmentId) { try { query._id = { $ne: new ObjectId(appointmentId) }; } catch {} }
        query.time = normalizeTimeTo24h(time) || time;
        const existing = await db.collection('APPOINTMENTS').findOne(query);
        return res.json({ success:true, available:!existing, message:existing ? 'This time slot has been taken by another client.' : 'Available' });
      } catch (err) { res.status(500).json({ success:false, error:'Server error' }); }
    });

    crudRoutes('APPOINTMENTS', 'appointments');
    crudRoutes('AVAILABILITY', 'availability');
    crudRoutes('EMPLOYEES', 'employees');
    crudRoutes('PAYMENTS', 'payments');
    crudRoutes('SERVICES', 'services');

    // =====================
    // USER ADMIN ENDPOINTS
    // =====================
    app.get('/users', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const { page=1, limit=500, email } = req.query;
        const query = {};
        if (email) query.email = email;
        const skip = (parseInt(page)-1) * parseInt(limit);
        const users = await db.collection('USERS').find(query).project({ password:0 }).skip(skip).limit(parseInt(limit)).toArray();
        res.status(200).json({ success:true, data:users });
      } catch (err) { next(err); }
    });

    app.get('/users/:id', authenticateToken, authorizeRole('admin'), idValidator, async (req, res, next) => {
      try {
        const user = await db.collection('USERS').findOne({ _id:new ObjectId(req.params.id) }, { projection:{ password:0 } });
        if (!user) return res.status(404).json({ success:false, error:'User not found' });
        res.status(200).json({ success:true, data:user });
      } catch (err) { next(err); }
    });

    app.put('/users/:id', authenticateToken, authorizeRole('admin'), idValidator,
      body('email').optional().isEmail().normalizeEmail(),
      body('firstName').optional().isString().notEmpty(),
      body('lastName').optional().isString().notEmpty(),
      body('role').optional().isIn(['user','admin']),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          delete req.body.password;
          req.body.updatedAt = new Date();
          const updatedUser = await db.collection('USERS').findOneAndUpdate({ _id:new ObjectId(req.params.id) }, { $set:req.body }, { returnDocument:'after', projection:{ password:0 } });
          if (!updatedUser) return res.status(404).json({ success:false, error:'User not found' });
          res.status(200).json({ success:true, message:'User updated', data:updatedUser });
        } catch (err) { next(err); }
      }
    );

    app.delete('/users/:id', authenticateToken, authorizeRole('admin'), idValidator, async (req, res, next) => {
      try {
        const result = await db.collection('USERS').deleteOne({ _id:new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ success:false, error:'User not found' });
        res.status(200).json({ success:true, message:'User deleted' });
      } catch (err) { next(err); }
    });

    // =====================
    // NOTIFICATIONS
    // =====================
    app.post('/notifications', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const { message, target='staff' } = req.body;
        if (!message) return res.status(400).json({ success:false, error:'Message is required' });
        const notification = { message, target, recipientId:null, createdBy:new ObjectId(req.user.userId), createdAt:new Date(), read:false, readAt:null };
        const result = await db.collection('NOTIFICATIONS').insertOne(notification);
        res.status(201).json({ success:true, data:{ _id:result.insertedId, ...notification } });
      } catch (err) { next(err); }
    });

    app.get('/notifications', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const notifications = await db.collection('NOTIFICATIONS').find({}).sort({ createdAt:-1 }).limit(200).toArray();
        res.status(200).json({ success:true, data:notifications });
      } catch (err) { next(err); }
    });

    app.delete('/notifications', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        await db.collection('NOTIFICATIONS').deleteMany({});
        res.status(200).json({ success:true, message:'All notifications cleared' });
      } catch (err) { next(err); }
    });

    app.post('/notifications/mark-read', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        await db.collection('NOTIFICATIONS').updateMany({ read:false }, { $set:{ read:true, readAt:new Date() } });
        res.status(200).json({ success:true, message:'All notifications marked as read' });
      } catch (err) { next(err); }
    });

    // =====================
    // GALLERY
    // =====================
    app.post('/gallery', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const { imageUrl, clientName, caption } = req.body;
        if (!imageUrl) return res.status(400).json({ success:false, error:'imageUrl is required' });
        const item = { imageUrl, clientName:sanitiseText(clientName||'', 100), caption:sanitiseText(caption||'', 300), createdBy:new ObjectId(req.user.userId), createdAt:new Date() };
        const result = await db.collection('GALLERY').insertOne(item);
        res.status(201).json({ success:true, data:{ _id:result.insertedId, ...item } });
      } catch (err) { next(err); }
    });

    app.get('/gallery', async (req, res, next) => {
      try {
        const items = await db.collection('GALLERY').find({}).sort({ createdAt:-1 }).limit(20).toArray();
        res.status(200).json({ success:true, data:items });
      } catch (err) { next(err); }
    });

    app.delete('/gallery/:id', authenticateToken, authorizeRole('admin'), idValidator, async (req, res, next) => {
      try {
        const result = await db.collection('GALLERY').deleteOne({ _id:new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ success:false, error:'Item not found' });
        res.status(200).json({ success:true, message:'Deleted successfully' });
      } catch (err) { next(err); }
    });

    // =========================================================================
    // SHOP — PRODUCT ROUTES
    // *** IMPORTANT: specific routes BEFORE parameterized /:id routes ***
    // =========================================================================

    // GET /shop/products — public
    app.get('/shop/products', async (req, res, next) => {
      try {
        const { category, search, featured, minPrice, maxPrice, sort='newest', page=1, limit=24 } = req.query;
        const query = { isActive:true };
        if (category && category !== 'all') query.category = category;
        if (featured === 'true') query.isFeatured = true;
        if (minPrice || maxPrice) {
          query.price = {};
          if (minPrice) query.price.$gte = Decimal128.fromString(String(parseFloat(minPrice)));
          if (maxPrice) query.price.$lte = Decimal128.fromString(String(parseFloat(maxPrice)));
        }
        if (search) query.$text = { $search:search };
        const sortMap = { newest:{ createdAt:-1 }, oldest:{ createdAt:1 }, 'price-asc':{ price:1 }, 'price-desc':{ price:-1 }, featured:{ isFeatured:-1, createdAt:-1 } };
        const sortOpt = sortMap[sort] || sortMap.newest;
        const skip = (parseInt(page)-1) * parseInt(limit);
        const [products, total] = await Promise.all([
          db.collection('PRODUCTS').find(query).sort(sortOpt).skip(skip).limit(parseInt(limit)).toArray(),
          db.collection('PRODUCTS').countDocuments(query),
        ]);
        const productIds = products.map(p => p._id);
        const ratings = await db.collection('REVIEWS').aggregate([
          { $match:{ productId:{ $in:productIds } } },
          { $group:{ _id:'$productId', avg:{ $avg:'$rating' }, count:{ $sum:1 } } },
        ]).toArray();
        const ratingMap = Object.fromEntries(ratings.map(r => [r._id.toString(), r]));
        res.json({ success:true, data:products.map(p => ({ ...p, price:parseFloat(p.price?.toString()||0), comparePrice:p.comparePrice?parseFloat(p.comparePrice.toString()):null, rating:ratingMap[p._id.toString()]?.avg||0, reviewCount:ratingMap[p._id.toString()]?.count||0 })), total, page:parseInt(page), pages:Math.ceil(total/parseInt(limit)) });
      } catch (err) { next(err); }
    });

    // GET /shop/products/featured — public  ← BEFORE /:id
    app.get('/shop/products/featured', async (req, res, next) => {
      try {
        const products = await db.collection('PRODUCTS').find({ isActive:true, isFeatured:true }).sort({ createdAt:-1 }).limit(8).toArray();
        res.json({ success:true, data:products.map(p => ({ ...p, price:parseFloat(p.price?.toString()||0), comparePrice:p.comparePrice?parseFloat(p.comparePrice.toString()):null })) });
      } catch (err) { next(err); }
    });

    // GET /shop/admin/products — admin  ← BEFORE /:id
    app.get('/shop/admin/products', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const { category, search, page=1, limit=50 } = req.query;
        const query = {};
        if (category && category !== 'all') query.category = category;
        if (search) query.$text = { $search:search };
        const skip = (parseInt(page)-1) * parseInt(limit);
        const [products, total] = await Promise.all([
          db.collection('PRODUCTS').find(query).sort({ createdAt:-1 }).skip(skip).limit(parseInt(limit)).toArray(),
          db.collection('PRODUCTS').countDocuments(query),
        ]);
        res.json({ success:true, data:products.map(p => ({ ...p, price:parseFloat(p.price?.toString()||0), comparePrice:p.comparePrice?parseFloat(p.comparePrice.toString()):null })), total });
      } catch (err) { next(err); }
    });

    // ══════════════════════════════════════════════════════════════════════
    // GIFT CARDS
    // ══════════════════════════════════════════════════════════════════════
    function generateGiftCode() {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      let code = 'NXL-';
      for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 4; j++) code += chars[Math.floor(Math.random() * chars.length)];
        if (i < 3) code += '-';
      }
      return code;
    }

    // POST /gift-cards/purchase — buy a gift card (creates pending Yoco checkout)
    app.post('/gift-cards/purchase', authenticateToken, async (req, res, next) => {
      try {
        const { amount, recipientEmail, recipientName, message } = req.body;
        const validAmounts = [100, 200, 300, 500, 1000];
        if (!validAmounts.includes(Number(amount)))
          return res.status(400).json({ success: false, error: `Amount must be one of: R${validAmounts.join(', R')}` });
        if (!recipientEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipientEmail))
          return res.status(400).json({ success: false, error: 'Valid recipient email is required.' });

        let code; let attempts = 0;
        do { code = generateGiftCode(); attempts++; } while (attempts < 10 && await db.collection('GIFT_CARDS').findOne({ code }));

        const now = new Date();
        const expiresAt = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year

        const card = {
          code, amount: Number(amount),
          balance: Number(amount),
          purchasedBy: new ObjectId(req.user.userId),
          recipientEmail: recipientEmail.toLowerCase().trim(),
          recipientName: sanitiseText(recipientName || '', 60),
          message: sanitiseText(message || '', 200),
          status: 'pending_payment',
          redeemedAmount: 0,
          redemptions: [],
          expiresAt, createdAt: now, updatedAt: now,
        };

        const result = await db.collection('GIFT_CARDS').insertOne(card);
        const cardId  = result.insertedId.toString();
        const frontendUrl = process.env.FRONTEND_URL || 'https://nxlbeautybar.co.za';

        const yocoResp = await fetchFn('https://payments.yoco.com/api/checkouts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.YOCO_SECRET_KEY}` },
          body: JSON.stringify({
            amount: Number(amount) * 100,
            currency: 'ZAR',
            successUrl: `${frontendUrl}/gift-cards/success?cardId=${cardId}`,
            cancelUrl:  `${frontendUrl}/shop?giftCancelled=true`,
            metadata: { cardId, type: 'gift_card', userId: req.user.userId },
          }),
        });
        const yocoData = await yocoResp.json();
        if (!yocoData.redirectUrl) return res.status(500).json({ success: false, error: 'Payment init failed.' });

        await db.collection('GIFT_CARDS').updateOne({ _id: result.insertedId }, { $set: { yocoCheckoutId: yocoData.id, updatedAt: new Date() } });
        res.json({ success: true, data: { cardId, checkoutUrl: yocoData.redirectUrl, code } });
      } catch (err) { next(err); }
    });

    // POST /gift-cards/confirm — Yoco webhook or success page confirms payment
    app.post('/gift-cards/confirm', authenticateToken, async (req, res, next) => {
      try {
        const { cardId } = req.body;
        if (!cardId?.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success: false, error: 'Invalid card ID' });
        const card = await db.collection('GIFT_CARDS').findOne({ _id: new ObjectId(cardId) });
        if (!card) return res.status(404).json({ success: false, error: 'Gift card not found' });
        if (card.status === 'active') return res.json({ success: true, data: card });

        await db.collection('GIFT_CARDS').updateOne({ _id: new ObjectId(cardId) }, { $set: { status: 'active', updatedAt: new Date() } });

        // Send gift card email
        if (process.env.RESEND_API_KEY) {
          try {
            const resend  = new Resend(process.env.RESEND_API_KEY);
            const buyer   = await db.collection('USERS').findOne({ _id: card.purchasedBy }, { projection: { firstName:1 } });
            await resend.emails.send({
              from:    'NXL Beauty Bar <onboarding@resend.dev>',
              to:      card.recipientEmail,
              subject: `🎁 You've received an NXL Beauty Bar Gift Card — R${card.amount}`,
              html: `
                <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:0;background:#fdf6f0;border-radius:16px;overflow:hidden;">
                  <div style="background:linear-gradient(135deg,#3d1f15,#6b3528);padding:2.5rem 2rem;text-align:center;">
                    <p style="color:rgba(255,232,214,0.7);font-size:0.82rem;text-transform:uppercase;letter-spacing:0.12em;margin:0 0 0.5rem;">NXL Beauty Bar</p>
                    <h1 style="color:#ffe8d6;font-family:Georgia,serif;font-size:2rem;margin:0 0 0.5rem;">Gift Card</h1>
                    <div style="background:rgba(255,255,255,0.1);border-radius:12px;padding:1.5rem;margin-top:1.5rem;">
                      <p style="color:rgba(255,232,214,0.6);font-size:0.75rem;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 0.4rem;">Value</p>
                      <p style="color:#ffe8d6;font-size:3rem;font-weight:800;margin:0;line-height:1;">R${card.amount}</p>
                    </div>
                    <div style="background:rgba(255,255,255,0.06);border:1px solid rgba(255,232,214,0.2);border-radius:8px;padding:0.875rem 1.25rem;margin-top:1rem;">
                      <p style="color:rgba(255,232,214,0.55);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.12em;margin:0 0 0.25rem;">Your Gift Code</p>
                      <p style="color:#ffe8d6;font-family:monospace;font-size:1.3rem;font-weight:800;letter-spacing:0.15em;margin:0;">${card.code}</p>
                    </div>
                  </div>
                  <div style="padding:2rem;">
                    ${card.recipientName ? `<p style="color:#3d1f15;font-weight:700;font-size:1rem;margin:0 0 0.5rem;">Hi ${card.recipientName}!</p>` : ''}
                    <p style="color:#6b3528;line-height:1.65;margin:0 0 0.75rem;">${buyer?.firstName ? `<strong>${buyer.firstName}</strong> has sent you` : 'You have received'} a gift card for NXL Beauty Bar!</p>
                    ${card.message ? `<div style="background:#fff8f3;border:1px solid #e0ccc4;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1rem;font-style:italic;color:#6b3528;">"${card.message}"</div>` : ''}
                    <p style="color:#9e7060;font-size:0.82rem;line-height:1.65;margin:0 0 1rem;">Use your gift code at checkout on our shop to redeem your gift. Valid until ${card.expiresAt.toLocaleDateString('en-ZA', { day:'numeric', month:'long', year:'numeric' })}.</p>
                    <div style="text-align:center;margin:1.5rem 0;">
                      <a href="${process.env.CORS_ORIGIN || 'https://nxlbeautybar.co.za'}/shop" style="background:#3d1f15;color:#ffe8d6;text-decoration:none;padding:0.875rem 2rem;border-radius:50px;font-weight:700;font-size:0.9rem;display:inline-block;">Shop Now →</a>
                    </div>
                  </div>
                </div>
              `,
            });
          } catch (emailErr) { logger.error(`[GIFT CARD EMAIL] ${emailErr.message}`); }
        }

        const updated = await db.collection('GIFT_CARDS').findOne({ _id: new ObjectId(cardId) });
        res.json({ success: true, data: updated });
      } catch (err) { next(err); }
    });

    // POST /gift-cards/redeem — apply gift card at checkout
    app.post('/gift-cards/redeem', authenticateToken, async (req, res, next) => {
      try {
        const { code, orderSubtotal } = req.body;
        if (!code) return res.status(400).json({ success: false, error: 'Gift card code is required.' });

        const card = await db.collection('GIFT_CARDS').findOne({ code: code.trim().toUpperCase() });
        if (!card) return res.status(404).json({ success: false, error: 'Invalid gift card code.' });
        if (card.status !== 'active') return res.status(400).json({ success: false, error: 'This gift card is not active.' });
        if (card.balance <= 0) return res.status(400).json({ success: false, error: 'This gift card has no remaining balance.' });
        if (new Date() > card.expiresAt) return res.status(400).json({ success: false, error: 'This gift card has expired.' });

        const discount = Math.min(card.balance, orderSubtotal || card.balance);
        res.json({
          success: true,
          data: {
            code:           card.code,
            balance:        card.balance,
            discountAmount: parseFloat(discount.toFixed(2)),
            remainingAfter: parseFloat((card.balance - discount).toFixed(2)),
          },
        });
      } catch (err) { next(err); }
    });

    // GET /gift-cards/my — user's purchased gift cards
    app.get('/gift-cards/my', authenticateToken, async (req, res, next) => {
      try {
        const cards = await db.collection('GIFT_CARDS')
          .find({ purchasedBy: new ObjectId(req.user.userId) })
          .sort({ createdAt: -1 }).toArray();
        res.json({ success: true, data: cards });
      } catch (err) { next(err); }
    });

    // GET /gift-cards/admin — admin view all gift cards
    app.get('/gift-cards/admin', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const cards = await db.collection('GIFT_CARDS').find({}).sort({ createdAt: -1 }).limit(100).toArray();
        res.json({ success: true, data: cards });
      } catch (err) { next(err); }
    });
    // ══════════════════════════════════════════════════════════════════════

    // ══════════════════════════════════════════════════════════════════════
    // GET /analytics — combined business analytics for admin dashboard
    // ══════════════════════════════════════════════════════════════════════
    app.get('/analytics', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const range = req.query.range || '30'; // days
        const days  = Math.min(365, Math.max(7, parseInt(range, 10)));
        const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
        const today = new Date(); today.setHours(0, 0, 0, 0);
        const yesterday = new Date(today); yesterday.setDate(yesterday.getDate() - 1);

        const [
          // Booking stats
          totalBookings, bookingsToday, bookingsPeriod,
          bookingsByStatus, bookingsByService, bookingsByStaff,
          dailyBookings,
          // Revenue stats
          totalRevenue, revenueToday, revenuePeriod,
          dailyRevenue, revenueByMethod,
          // Shop stats
          shopRevenuePeriod, shopOrdersPeriod,
          // Client stats
          totalClients, newClientsPeriod, topClients,
          // Loyalty stats
          totalLoyaltyPoints, avgLoyaltyPoints,
        ] = await Promise.all([
          // Bookings
          db.collection('APPOINTMENTS').countDocuments({}),
          db.collection('APPOINTMENTS').countDocuments({ createdAt: { $gte: today } }),
          db.collection('APPOINTMENTS').countDocuments({ createdAt: { $gte: since } }),
          db.collection('APPOINTMENTS').aggregate([
            { $group: { _id: '$status', count: { $sum: 1 } } },
          ]).toArray(),
          db.collection('APPOINTMENTS').aggregate([
            { $match: { createdAt: { $gte: since } } },
            { $unwind: '$serviceIds' },
            { $group: { _id: '$serviceIds', count: { $sum: 1 } } },
            { $sort: { count: -1 } }, { $limit: 8 },
          ]).toArray(),
          db.collection('APPOINTMENTS').aggregate([
            { $match: { createdAt: { $gte: since } } },
            { $group: { _id: '$employeeId', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
          ]).toArray(),
          db.collection('APPOINTMENTS').aggregate([
            { $match: { createdAt: { $gte: since } } },
            { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
            { $sort: { _id: 1 } },
          ]).toArray(),
          // Revenue
          db.collection('PAYMENTS').aggregate([
            { $match: { status: 'paid' } },
            { $group: { _id: null, total: { $sum: { $toDouble: '$amount' } } } },
          ]).toArray(),
          db.collection('PAYMENTS').aggregate([
            { $match: { status: 'paid', createdAt: { $gte: today } } },
            { $group: { _id: null, total: { $sum: { $toDouble: '$amount' } } } },
          ]).toArray(),
          db.collection('PAYMENTS').aggregate([
            { $match: { status: 'paid', createdAt: { $gte: since } } },
            { $group: { _id: null, total: { $sum: { $toDouble: '$amount' } } } },
          ]).toArray(),
          db.collection('PAYMENTS').aggregate([
            { $match: { status: 'paid', createdAt: { $gte: since } } },
            { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, revenue: { $sum: { $toDouble: '$amount' } }, count: { $sum: 1 } } },
            { $sort: { _id: 1 } },
          ]).toArray(),
          db.collection('PAYMENTS').aggregate([
            { $match: { status: 'paid', createdAt: { $gte: since } } },
            { $group: { _id: '$method', total: { $sum: { $toDouble: '$amount' } }, count: { $sum: 1 } } },
          ]).toArray(),
          // Shop
          db.collection('ORDERS').aggregate([
            { $match: { paymentStatus: 'paid', createdAt: { $gte: since } } },
            { $group: { _id: null, total: { $sum: { $toDouble: '$totalAmount' } } } },
          ]).toArray(),
          db.collection('ORDERS').countDocuments({ paymentStatus: 'paid', createdAt: { $gte: since } }),
          // Clients
          db.collection('USERS').countDocuments({ role: 'user' }),
          db.collection('USERS').countDocuments({ role: 'user', createdAt: { $gte: since } }),
          db.collection('APPOINTMENTS').aggregate([
            { $group: { _id: '$userId', bookings: { $sum: 1 } } },
            { $sort: { bookings: -1 } }, { $limit: 5 },
          ]).toArray(),
          // Loyalty
          db.collection('LOYALTY').aggregate([
            { $group: { _id: null, total: { $sum: '$points' }, avg: { $avg: '$points' }, members: { $sum: 1 } } },
          ]).toArray(),
          db.collection('LOYALTY').aggregate([
            { $group: { _id: null, avg: { $avg: '$points' } } },
          ]).toArray(),
        ]);

        // Enrich service names
        const serviceIds  = bookingsByService.map(b => b._id).filter(Boolean);
        const staffIds    = bookingsByStaff.map(b => b._id).filter(Boolean);
        const clientIds   = topClients.map(c => c._id).filter(Boolean);
        const [services, staff, clientUsers] = await Promise.all([
          db.collection('SERVICES').find({ _id: { $in: serviceIds } }).project({ name:1 }).toArray(),
          db.collection('EMPLOYEES').find({ _id: { $in: staffIds } }).project({ name:1 }).toArray(),
          db.collection('USERS').find({ _id: { $in: clientIds } }).project({ firstName:1, lastName:1, email:1 }).toArray(),
        ]);
        const svcMap    = Object.fromEntries(services.map(s  => [s._id.toString(), s.name]));
        const staffMap  = Object.fromEntries(staff.map(s     => [s._id.toString(), s.name]));
        const clientMap = Object.fromEntries(clientUsers.map(u => [u._id.toString(), u]));

        const bookingStatusMap = Object.fromEntries(bookingsByStatus.map(b => [b._id, b.count]));
        const completionRate = totalBookings > 0
          ? Math.round(((bookingStatusMap.completed || 0) / totalBookings) * 100)
          : 0;
        const cancellationRate = totalBookings > 0
          ? Math.round(((bookingStatusMap.cancelled || 0) / totalBookings) * 100)
          : 0;

        const shopRev   = shopRevenuePeriod[0]?.total || 0;
        const bookingRev = revenuePeriod[0]?.total || 0;
        const combinedRev = shopRev + bookingRev;

        res.json({
          success: true,
          data: {
            range: days,
            // Bookings
            bookings: {
              total: totalBookings,
              today: bookingsToday,
              period: bookingsPeriod,
              completionRate,
              cancellationRate,
              byStatus: bookingsByStatus,
              byService: bookingsByService.map(b => ({ ...b, name: svcMap[b._id?.toString()] || 'Unknown' })),
              byStaff:   bookingsByStaff.map(b => ({ ...b, name: staffMap[b._id?.toString()] || 'Unknown' })),
              daily: dailyBookings,
            },
            // Revenue
            revenue: {
              total:    totalRevenue[0]?.total || 0,
              today:    revenueToday[0]?.total || 0,
              period:   bookingRev,
              shopPeriod: shopRev,
              combined: combinedRev,
              daily:    dailyRevenue,
              byMethod: revenueByMethod,
            },
            // Clients
            clients: {
              total:   totalClients,
              newInPeriod: newClientsPeriod,
              top: topClients.map(c => ({ ...c, user: clientMap[c._id?.toString()] })),
            },
            // Shop
            shop: {
              orders: shopOrdersPeriod,
              revenue: shopRev,
            },
            // Loyalty
            loyalty: {
              totalPoints: totalLoyaltyPoints[0]?.total || 0,
              avgPoints:   Math.round(totalLoyaltyPoints[0]?.avg || 0),
              members:     totalLoyaltyPoints[0]?.members || 0,
            },
          },
        });
      } catch (err) { next(err); }
    });
    // ══════════════════════════════════════════════════════════════════════

    // GET /shop/admin/stats — admin  ← BEFORE /:id
    app.get('/shop/admin/stats', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const today = new Date(); today.setHours(0,0,0,0);
        const weekAgo  = new Date(Date.now() - 7  * 24*60*60*1000);
        const monthAgo = new Date(Date.now() - 30 * 24*60*60*1000);
        const [
          totalProducts, activeProducts, lowStock,
          totalOrders, pendingOrders, todayOrders,
          revenueWeekArr, revenueMonthArr,
          dailyRevenueArr, topProductsArr,
        ] = await Promise.all([
          db.collection('PRODUCTS').countDocuments({}),
          db.collection('PRODUCTS').countDocuments({ isActive:true }),
          db.collection('PRODUCTS').countDocuments({ isActive:true, stock:{ $lte:5 } }),
          db.collection('ORDERS').countDocuments({}),
          db.collection('ORDERS').countDocuments({ status:{ $in:['pending','confirmed','processing'] } }),
          db.collection('ORDERS').countDocuments({ createdAt:{ $gte:today } }),
          db.collection('ORDERS').aggregate([{ $match:{ paymentStatus:'paid', createdAt:{ $gte:weekAgo } } }, { $group:{ _id:null, total:{ $sum:{ $toDouble:'$totalAmount' } } } }]).toArray(),
          db.collection('ORDERS').aggregate([{ $match:{ paymentStatus:'paid', createdAt:{ $gte:monthAgo } } }, { $group:{ _id:null, total:{ $sum:{ $toDouble:'$totalAmount' } } } }]).toArray(),
          // Daily revenue for last 30 days
          db.collection('ORDERS').aggregate([
            { $match:{ paymentStatus:'paid', createdAt:{ $gte:monthAgo } } },
            { $group:{ _id:{ $dateToString:{ format:'%Y-%m-%d', date:'$createdAt' } }, revenue:{ $sum:{ $toDouble:'$totalAmount' } }, orders:{ $sum:1 } } },
            { $sort:{ _id:1 } },
          ]).toArray(),
          // Top 5 products by units sold
          db.collection('ORDERS').aggregate([
            { $match:{ paymentStatus:'paid' } },
            { $unwind:'$items' },
            { $group:{ _id:'$items.productId', name:{ $first:'$items.productName' }, sold:{ $sum:'$items.quantity' }, revenue:{ $sum:{ $toDouble:'$items.lineTotal' } } } },
            { $sort:{ sold:-1 } },
            { $limit:5 },
          ]).toArray(),
        ]);
        res.json({ success:true, data:{ totalProducts, activeProducts, lowStock, totalOrders, pendingOrders, todayOrders, revenueWeek:revenueWeekArr[0]?.total||0, revenueMonth:revenueMonthArr[0]?.total||0, dailyRevenue:dailyRevenueArr, topProducts:topProductsArr } });
      } catch (err) { next(err); }
    });

    // GET /shop/products/:id — public  ← AFTER specific routes
    app.get('/shop/products/:id', async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid product ID' });
        const product = await db.collection('PRODUCTS').findOne({ _id:new ObjectId(req.params.id), isActive:true });
        if (!product) return res.status(404).json({ success:false, error:'Product not found' });
        const reviews = await db.collection('REVIEWS').find({ productId:new ObjectId(req.params.id) }).sort({ createdAt:-1 }).limit(20).toArray();
        const userIds = [...new Set(reviews.map(r => r.userId))];
        const users = await db.collection('USERS').find({ _id:{ $in:userIds } }).project({ firstName:1, lastName:1 }).toArray();
        const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
        const enrichedReviews = reviews.map(r => ({ ...r, reviewerName:userMap[r.userId.toString()] ? `${userMap[r.userId.toString()].firstName} ${userMap[r.userId.toString()].lastName[0]}.` : 'Anonymous' }));
        const avgRating = reviews.length ? reviews.reduce((s, r) => s + r.rating, 0) / reviews.length : 0;
        res.json({ success:true, data:{ ...product, price:parseFloat(product.price?.toString()||0), comparePrice:product.comparePrice?parseFloat(product.comparePrice.toString()):null, reviews:enrichedReviews, rating:avgRating, reviewCount:reviews.length } });
      } catch (err) { next(err); }
    });

    // POST /shop/products — admin
    app.post('/shop/products', authenticateToken, authorizeRole('admin'),
      body('name').isString().notEmpty(),
      body('price').isFloat({ min:0.01 }),
      body('category').isIn(['nails','hair','skincare','accessories','professional','other']),
      body('stock').isInt({ min:0 }),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const now = new Date();
          const product = {
            name:sanitiseText(req.body.name, 200), description:sanitiseText(req.body.description||'', 2000),
            price:Decimal128.fromString(parseFloat(req.body.price).toFixed(2)),
            comparePrice:req.body.comparePrice ? Decimal128.fromString(parseFloat(req.body.comparePrice).toFixed(2)) : null,
            category:req.body.category,
            images:Array.isArray(req.body.images) ? req.body.images : (req.body.images ? [req.body.images] : []),
            stock:parseInt(req.body.stock), sku:req.body.sku||'', brand:req.body.brand||'',
            tags:Array.isArray(req.body.tags) ? req.body.tags : [],
            isActive:req.body.isActive !== false, isFeatured:req.body.isFeatured === true,
            createdAt:now, updatedAt:now,
          };
          const result = await db.collection('PRODUCTS').insertOne(product);
          res.status(201).json({ success:true, data:{ _id:result.insertedId, ...product, price:parseFloat(product.price.toString()) } });
        } catch (err) { next(err); }
      }
    );

    // PUT /shop/products/:id — admin
    app.put('/shop/products/:id', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const update = { updatedAt:new Date() };
        if (req.body.name         !== undefined) update.name         = sanitiseText(req.body.name, 200);
        if (req.body.description  !== undefined) update.description  = sanitiseText(req.body.description||'', 2000);
        if (req.body.price        !== undefined) update.price        = Decimal128.fromString(parseFloat(req.body.price).toFixed(2));
        if (req.body.comparePrice !== undefined) update.comparePrice = req.body.comparePrice ? Decimal128.fromString(parseFloat(req.body.comparePrice).toFixed(2)) : null;
        if (req.body.category     !== undefined) update.category     = req.body.category;
        if (req.body.images       !== undefined) update.images       = Array.isArray(req.body.images) ? req.body.images : [req.body.images];
        if (req.body.stock        !== undefined) update.stock        = parseInt(req.body.stock);
        if (req.body.sku          !== undefined) update.sku          = req.body.sku;
        if (req.body.brand        !== undefined) update.brand        = req.body.brand;
        if (req.body.tags         !== undefined) update.tags         = Array.isArray(req.body.tags) ? req.body.tags : [];
        if (req.body.isActive     !== undefined) update.isActive     = req.body.isActive;
        if (req.body.isFeatured   !== undefined) update.isFeatured   = req.body.isFeatured;
        const result = await db.collection('PRODUCTS').findOneAndUpdate({ _id:new ObjectId(req.params.id) }, { $set:update }, { returnDocument:'after' });
        if (!result) return res.status(404).json({ success:false, error:'Product not found' });
        res.json({ success:true, data:{ ...result, price:parseFloat(result.price?.toString()||0) } });
      } catch (err) { next(err); }
    });

    // DELETE /shop/products/:id — admin
    app.delete('/shop/products/:id', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const result = await db.collection('PRODUCTS').updateOne({ _id:new ObjectId(req.params.id) }, { $set:{ isActive:false, updatedAt:new Date() } });
        if (result.matchedCount === 0) return res.status(404).json({ success:false, error:'Product not found' });
        res.json({ success:true, message:'Product deactivated' });
      } catch (err) { next(err); }
    });

    // POST /shop/products/:id/reviews
    app.post('/shop/products/:id/reviews', authenticateToken,
      body('rating').isInt({ min:1, max:5 }),
      body('comment').optional().isString(),
      async (req, res, next) => {
        try {
          if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const purchased = await db.collection('ORDERS').findOne({ userId:new ObjectId(req.user.userId), 'items.productId':new ObjectId(req.params.id), paymentStatus:'paid' });
          if (!purchased) return res.status(403).json({ success:false, error:'You can only review products you have purchased' });
          const review = { productId:new ObjectId(req.params.id), userId:new ObjectId(req.user.userId), rating:parseInt(req.body.rating), comment:req.body.comment||'', createdAt:new Date() };
          try { await db.collection('REVIEWS').insertOne(review); }
          catch (e) { if (e.code === 11000) return res.status(409).json({ success:false, error:'You have already reviewed this product' }); throw e; }
          res.status(201).json({ success:true, data:review });
        } catch (err) { next(err); }
      }
    );

    // =========================================================================
    // SHOP — ORDER ROUTES
    // *** IMPORTANT: specific routes BEFORE parameterized /:id routes ***
    // =========================================================================

    // POST /shop/orders
    app.post('/shop/orders', authenticateToken, orderLimiter, async (req, res, next) => {
      try {
        const { items, shippingAddress, notes, discountCode, fulfillmentType } = req.body;
        if (!items || !items.length) return res.status(400).json({ success:false, error:'Cart is empty' });
        const isPickup = fulfillmentType === 'pickup';
        // For pickup only contact info required; for delivery full address required
        if (!shippingAddress?.fullName || !shippingAddress?.phone) {
          return res.status(400).json({ success:false, error:'Name and phone number are required' });
        }
        if (!isPickup && (!shippingAddress?.address || !shippingAddress?.city)) {
          return res.status(400).json({ success:false, error:'Delivery address is required for home delivery' });
        }
        const productIds = items.map(i => new ObjectId(i.productId));
        const products = await db.collection('PRODUCTS').find({ _id:{ $in:productIds }, isActive:true }).toArray();
        if (products.length !== productIds.length) return res.status(400).json({ success:false, error:'One or more products are unavailable' });
        const productMap = Object.fromEntries(products.map(p => [p._id.toString(), p]));
        const enrichedItems = [];
        let subtotal = 0;
        for (const item of items) {
          const product = productMap[item.productId];
          if (!product) return res.status(400).json({ success:false, error:`Product ${item.productId} not found` });
          if (product.stock < item.quantity) return res.status(400).json({ success:false, error:`Insufficient stock for "${product.name}" (available: ${product.stock})` });
          const itemPrice = parseFloat(product.price.toString());
          subtotal += itemPrice * item.quantity;
          enrichedItems.push({ productId:product._id, productName:product.name, productImage:(product.images||[])[0]||'', quantity:item.quantity, unitPrice:Decimal128.fromString(itemPrice.toFixed(2)), lineTotal:Decimal128.fromString((itemPrice*item.quantity).toFixed(2)) });
        }

        // Discount code validation
        let discountAmount = 0;
        let appliedCode    = null;
        if (discountCode) {
          const code = await db.collection('DISCOUNT_CODES').findOne({
            code: discountCode.toUpperCase().trim(), isActive: true,
            $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
          });
          if (!code) return res.status(400).json({ success:false, error:'Invalid or expired discount code.' });
          if (code.usageLimit && code.usedCount >= code.usageLimit) return res.status(400).json({ success:false, error:'This discount code has reached its usage limit.' });
          if (code.minOrderAmount && subtotal < code.minOrderAmount) return res.status(400).json({ success:false, error:`This code requires a minimum order of R${code.minOrderAmount.toFixed(2)}.` });
          discountAmount = code.type === 'percentage' ? Math.round((subtotal * code.value / 100) * 100) / 100 : Math.min(code.value, subtotal);
          appliedCode = { code: code.code, type: code.type, value: code.value, discountAmount };
          await db.collection('DISCOUNT_CODES').updateOne({ _id: code._id }, { $inc: { usedCount: 1 } });
          logger.info(`[DISCOUNT] Code ${code.code} applied`, { userId: req.user.userId, discountAmount });
        }

        const discountedSubtotal = subtotal - discountAmount;

        // ── Loyalty points redemption ─────────────────────────────────────
        let loyaltyDiscount   = 0;
        let loyaltyPtsToRedeem = 0;
        const { loyaltyPointsToRedeem, giftCardCode } = req.body;
        if (loyaltyPointsToRedeem && parseInt(loyaltyPointsToRedeem) >= LOYALTY_CONFIG.minRedemption) {
          const loyaltyAccount = await getLoyaltyAccount(new ObjectId(req.user.userId));
          const ptsAvail  = Math.min(parseInt(loyaltyPointsToRedeem), loyaltyAccount.points);
          const maxDisc   = discountedSubtotal * (LOYALTY_CONFIG.maxRedemptionPct / 100);
          loyaltyDiscount  = Math.min(ptsAvail * LOYALTY_CONFIG.pointValue, maxDisc);
          loyaltyPtsToRedeem = Math.round(loyaltyDiscount / LOYALTY_CONFIG.pointValue);
        }

        // ── Gift card redemption ──────────────────────────────────────────
        let giftCardDiscount = 0;
        let appliedGiftCard  = null;
        if (giftCardCode) {
          const card = await db.collection('GIFT_CARDS').findOne({ code: giftCardCode.trim().toUpperCase(), status: 'active' });
          if (card && card.balance > 0 && new Date() < card.expiresAt) {
            giftCardDiscount = Math.min(card.balance, discountedSubtotal - loyaltyDiscount);
            appliedGiftCard  = { code: card.code, cardId: card._id, discountAmount: giftCardDiscount };
          }
        }
        // ─────────────────────────────────────────────────────────────────

        const shippingFee = isPickup ? 0 : (discountedSubtotal >= 500 ? 0 : 80);
        const totalAmount = Math.max(0, discountedSubtotal - loyaltyDiscount - giftCardDiscount + shippingFee);
        const now = new Date();
        const order = {
          userId: new ObjectId(req.user.userId),
          items: enrichedItems,
          fulfillmentType: isPickup ? 'pickup' : 'delivery',
          subtotal:        Decimal128.fromString(subtotal.toFixed(2)),
          discountAmount:  Decimal128.fromString(discountAmount.toFixed(2)),
          discountCode:    appliedCode || null,
          loyaltyDiscount: Decimal128.fromString(loyaltyDiscount.toFixed(2)),
          loyaltyPointsRedeemed: loyaltyPtsToRedeem,
          giftCardDiscount: Decimal128.fromString(giftCardDiscount.toFixed(2)),
          giftCardCode:    appliedGiftCard?.code || null,
          shippingFee:     Decimal128.fromString(shippingFee.toFixed(2)),
          totalAmount:     Decimal128.fromString(totalAmount.toFixed(2)),
          status: 'pending', paymentStatus: 'unpaid', paymentMethod: 'yoco',
          shippingAddress, notes: sanitiseText(notes || '', 500),
          createdAt: now, updatedAt: now,
        };
        const result = await db.collection('ORDERS').insertOne(order);
        const orderId = result.insertedId.toString();
        const frontendUrl = process.env.FRONTEND_URL || 'https://nxlbeautybar.co.za';
        const yocoResponse = await fetchFn('https://payments.yoco.com/api/checkouts', {
          method:'POST',
          headers:{ 'Content-Type':'application/json', 'Authorization':`Bearer ${process.env.YOCO_SECRET_KEY}` },
          body:JSON.stringify({ amount:Math.round(totalAmount*100), currency:'ZAR', successUrl:`${frontendUrl}/shop/order-success?orderId=${orderId}`, cancelUrl:`${frontendUrl}/cart?cancelled=true`, failureUrl:`${frontendUrl}/cart?failed=true`, metadata:{ orderId, userId:req.user.userId, type:'shop_order' } }),
        });
        if (!yocoResponse.ok) {
          const errBody = await yocoResponse.json().catch(()=>({}));
          logger.error('Yoco shop checkout failed', { status:yocoResponse.status, body:errBody });
          return res.status(500).json({ success:false, error:'Payment gateway error. Please try again.' });
        }
        const yocoData = await yocoResponse.json();
        await db.collection('ORDERS').updateOne({ _id:result.insertedId }, { $set:{ yocoCheckoutId:yocoData.id, updatedAt:new Date() } });
        logger.info('Shop order created', { orderId, totalAmount, itemCount:enrichedItems.length });
        res.status(201).json({ success:true, orderId, checkoutUrl:yocoData.redirectUrl, checkoutId:yocoData.id, order:{ ...order, _id:result.insertedId, subtotal, discountAmount, shippingFee, totalAmount } });
      } catch (err) { next(err); }
    });


    // POST /shop/orders/verify  ← BEFORE /shop/orders/:id
    app.post('/shop/orders/verify', authenticateToken, async (req, res, next) => {
      try {
        const { orderId } = req.body;
        if (!orderId) return res.status(400).json({ success:false, error:'orderId is required' });
        const order = await db.collection('ORDERS').findOne({ _id:new ObjectId(orderId) });
        if (!order) return res.status(404).json({ success:false, error:'Order not found' });
        if (order.status === 'confirmed' && order.paymentStatus === 'paid') return res.json({ success:true, alreadyConfirmed:true, order });
        await db.collection('ORDERS').updateOne({ _id:new ObjectId(orderId) }, { $set:{ status:'confirmed', paymentStatus:'paid', updatedAt:new Date() } });
        for (const item of order.items||[]) { await db.collection('PRODUCTS').updateOne({ _id:item.productId }, { $inc:{ stock:-item.quantity } }); }

        // ── Award loyalty points for shop order ───────────────────────────
        try {
          const amountSpent = parseFloat(order.totalAmount?.toString() || 0);
          // Points not awarded for shop orders — bookings only
          // Deduct redeemed points if any
          if (order.loyaltyPointsRedeemed > 0) {
            await redeemPoints(order.userId, order.loyaltyPointsRedeemed, `Redeemed at checkout — order #${orderId.slice(-6).toUpperCase()}`, new ObjectId(orderId));
          }
          // Deduct gift card balance
          if (order.giftCardCode) {
            const gcDiscount = parseFloat(order.giftCardDiscount?.toString() || 0);
            await db.collection('GIFT_CARDS').updateOne(
              { code: order.giftCardCode },
              { $inc: { balance: -gcDiscount, redeemedAmount: gcDiscount },
                $push: { redemptions: { orderId: new ObjectId(orderId), amount: gcDiscount, redeemedAt: new Date() } },
                $set:  { status: gcDiscount >= parseFloat((await db.collection('GIFT_CARDS').findOne({ code: order.giftCardCode }))?.balance?.toString() || 0) ? 'redeemed' : 'active', updatedAt: new Date() } }
            );
          }
        } catch (loyaltyErr) { logger.error(`[LOYALTY] Shop order award failed: ${loyaltyErr.message}`); }

        // ── In-app: order confirmed ────────────────────────────────────────
        try {
          await notifyClient(order.userId, {
            type:  'order_confirmed',
            title: `Order #${orderId.slice(-6).toUpperCase()} Confirmed 🛒`,
            body:  `Your order has been confirmed. ${order.fulfillmentType === 'pickup' ? "We'll notify you when it's ready to collect." : "We'll notify you when it ships."}`,
            link:  `/track/${orderId}`,
            meta:  { orderId },
          });
        } catch {}
        // ──────────────────────────────────────────────────────────────────

        // ── Low stock check after deduction ────────────────────────────────
        if (process.env.RESEND_API_KEY && process.env.ADMIN_EMAIL) {
          try {
            const productIds = (order.items||[]).map(i => i.productId).filter(Boolean);
            const lowStockProducts = await db.collection('PRODUCTS').find({
              _id: { $in: productIds }, isActive: true, stock: { $lte: 5 },
            }).toArray();
            if (lowStockProducts.length > 0) {
              const resend = new Resend(process.env.RESEND_API_KEY);
              const itemRows = lowStockProducts.map(p =>
                `<tr><td style="padding:0.5rem 0.75rem;border-bottom:1px solid #e0ccc4;font-weight:600;color:#3d1f15;">${p.name}</td><td style="padding:0.5rem 0.75rem;border-bottom:1px solid #e0ccc4;text-align:center;font-weight:800;color:${p.stock===0?'#dc2626':'#c05621'};font-size:1rem;">${p.stock}</td><td style="padding:0.5rem 0.75rem;border-bottom:1px solid #e0ccc4;color:#9e7060;font-size:0.82rem;">${p.stock===0?'🔴 Out of stock':'🟡 Low stock'}</td></tr>`
              ).join('');
              await resend.emails.send({
                from:    'NXL Beauty Bar <onboarding@resend.dev>',
                to:      process.env.ADMIN_EMAIL,
                subject: `⚠️ Low Stock Alert — ${lowStockProducts.length} product${lowStockProducts.length>1?'s need':' needs'} restocking`,
                html:`<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;"><h2 style="font-family:Georgia,serif;color:#3d1f15;margin-bottom:0.25rem;">NXL Beauty Bar</h2><h3 style="color:#c05621;margin-top:0;">⚠️ Low Stock Alert</h3><p style="color:#555;line-height:1.65;">The following product${lowStockProducts.length>1?'s are':' is'} running low after a recent sale:</p><table style="width:100%;border-collapse:collapse;margin:1.25rem 0;background:#fff;border-radius:10px;overflow:hidden;"><thead><tr style="background:#f9f1ec;"><th style="padding:0.6rem 0.75rem;text-align:left;font-size:0.72rem;color:#9e7060;text-transform:uppercase;">Product</th><th style="padding:0.6rem 0.75rem;text-align:center;font-size:0.72rem;color:#9e7060;text-transform:uppercase;">Stock Left</th><th style="padding:0.6rem 0.75rem;text-align:left;font-size:0.72rem;color:#9e7060;text-transform:uppercase;">Status</th></tr></thead><tbody>${itemRows}</tbody></table><div style="text-align:center;margin:1.5rem 0;"><a href="${(process.env.CORS_ORIGIN||'https://nxlbeautybar.co.za').replace(/\/$/,'')}/admin-dashboard" style="background:#3d1f15;color:#ffe8d6;text-decoration:none;padding:0.75rem 2rem;border-radius:50px;font-weight:700;font-size:0.88rem;display:inline-block;">Go to Admin Dashboard →</a></div></div>`,
              });
              logger.info(`[LOW STOCK EMAIL] Sent after payment — ${lowStockProducts.length} product(s) low`);
            }
          } catch (e) { logger.error(`[LOW STOCK EMAIL] ${e.message}`); }
        }
        // ──────────────────────────────────────────────────────────────────
        if (process.env.RESEND_API_KEY) {
          try {
            const resend = new Resend(process.env.RESEND_API_KEY);
            const user = await db.collection('USERS').findOne({ _id:order.userId });
            const itemsList = (order.items||[]).map(i => `<tr><td style="padding:6px 0">${i.productName}</td><td style="padding:6px 0;text-align:right">x${i.quantity}</td><td style="padding:6px 0;text-align:right">R${parseFloat(i.lineTotal?.toString()||0).toFixed(2)}</td></tr>`).join('');
            await resend.emails.send({
              from:'NXL Beauty Bar <onboarding@resend.dev>',
              to:user?.email || order.shippingAddress?.email,
              subject:`Order Confirmed — NXL Beauty Bar #${orderId.slice(-6).toUpperCase()}`,
              html:`<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;"><h2 style="color:#3d1f15;font-family:Georgia,serif;">NXL Beauty Bar</h2><h3 style="color:#6b3528;">Order Confirmed! 🎉</h3><p>Hi ${user?.firstName||order.shippingAddress?.fullName},</p><p>Thank you for your order!</p><table style="width:100%;border-collapse:collapse;margin:1rem 0;"><thead><tr style="border-bottom:2px solid #e0ccc4;"><th style="text-align:left;padding:6px 0">Item</th><th style="text-align:right;padding:6px 0">Qty</th><th style="text-align:right;padding:6px 0">Total</th></tr></thead><tbody>${itemsList}</tbody><tfoot><tr style="border-top:1px solid #e0ccc4;"><td colspan="2" style="padding:6px 0">Shipping</td><td style="text-align:right;padding:6px 0">R${parseFloat(order.shippingFee?.toString()||0).toFixed(2)}</td></tr><tr><td colspan="2" style="padding:6px 0;font-weight:700">Total Paid</td><td style="text-align:right;padding:6px 0;font-weight:700">R${parseFloat(order.totalAmount?.toString()||0).toFixed(2)}</td></tr></tfoot></table><p style="color:#9e7060;font-size:0.78rem;">Order ref: #${orderId.slice(-6).toUpperCase()}</p><hr style="border:none;border-top:1px solid #e0ccc4;margin:1.5rem 0;"/><p style="color:#b08070;font-size:0.7rem;text-align:center;">NXL Beauty Bar &middot; 1948 Mahalefele Rd, Dube, Soweto, 1800</p></div>`,
            });
          } catch (emailErr) { logger.error('Order confirmation email failed:', emailErr.message); }
        }
        logger.info('Shop order confirmed', { orderId });
        res.json({ success:true, order:{ ...order, status:'confirmed', paymentStatus:'paid' } });
      } catch (err) { next(err); }
    });

    // ── GET /appointments/:id/receipt — public receipt for PaymentSuccess page ──
    app.get('/appointments/:id/receipt', async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i))
          return res.status(400).json({ success:false, error:'Invalid ID' });

        const appt = await db.collection('APPOINTMENTS').findOne({ _id: new ObjectId(req.params.id) });
        if (!appt) return res.status(404).json({ success:false, error:'Appointment not found' });

        // Verify by email query param
        const emailParam = req.query.email?.toLowerCase()?.trim();
        if (!emailParam) return res.status(400).json({ success:false, error:'Email required' });

        const user = await db.collection('USERS').findOne({ _id: appt.userId });
        if (!user || user.email.toLowerCase() !== emailParam)
          return res.status(403).json({ success:false, error:'Email does not match booking' });

        const svcIds = appt.serviceIds || [];
        const [services, employee] = await Promise.all([
          db.collection('SERVICES').find({ _id:{ $in:svcIds } }).project({ name:1, durationMinutes:1 }).toArray(),
          appt.employeeId ? db.collection('EMPLOYEES').findOne({ _id:appt.employeeId }, { projection:{ name:1 } }) : null,
        ]);
        const totalDuration = services.reduce((sum, s) => sum + (s.durationMinutes || 30), 0);

        res.json({ success:true, data: {
          name:                 `${user.firstName} ${user.lastName}`.trim(),
          email:                user.email,
          appointmentDate:      appt.date,
          appointmentTime:      appt.time,
          selectedServices:     services.map(s => s.name),
          selectedEmployee:     employee?.name || '',
          totalPrice:           parseFloat(appt.totalPrice?.toString() || 0),
          totalDuration:        totalDuration || 60,
          paymentStatus:        appt.paymentStatus,
          loyaltyPointsRedeemed:  appt.loyaltyPointsRedeemed || 0,
          loyaltyBalanceDiscount: parseFloat(appt.loyaltyBalanceDiscount?.toString() || 0),
          discountCode:           appt.discountCode || null,
          discountAmount:         parseFloat(appt.discountAmount?.toString() || 0),
        }});
      } catch (err) { next(err); }
    });
    // ──────────────────────────────────────────────────────────────────────

    // GET /shop/orders — user's own orders  ← BEFORE /shop/orders/:id
    app.get('/shop/orders', authenticateToken, async (req, res, next) => {
      try {
        const orders = await db.collection('ORDERS').find({ userId:new ObjectId(req.user.userId) }).sort({ createdAt:-1 }).toArray();
        res.json({ success:true, data:orders.map(o => ({ ...o, subtotal:parseFloat(o.subtotal?.toString()||0), shippingFee:parseFloat(o.shippingFee?.toString()||0), totalAmount:parseFloat(o.totalAmount?.toString()||0), items:(o.items||[]).map(i => ({ ...i, unitPrice:parseFloat(i.unitPrice?.toString()||0), lineTotal:parseFloat(i.lineTotal?.toString()||0) })) })) });
      } catch (err) { next(err); }
    });

    // GET /shop/admin/orders — admin  ← BEFORE /shop/orders/:id
    app.get('/shop/admin/orders', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const { status, page=1, limit=50 } = req.query;
        const query = {};
        if (status && status !== 'all') query.status = status;
        const skip = (parseInt(page)-1) * parseInt(limit);
        const [orders, total] = await Promise.all([
          db.collection('ORDERS').find(query).sort({ createdAt:-1 }).skip(skip).limit(parseInt(limit)).toArray(),
          db.collection('ORDERS').countDocuments(query),
        ]);
        const userIds = [...new Set(orders.map(o => o.userId))];
        const users = await db.collection('USERS').find({ _id:{ $in:userIds } }).project({ firstName:1, lastName:1, email:1 }).toArray();
        const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
        res.json({ success:true, total, data:orders.map(o => ({ ...o, subtotal:parseFloat(o.subtotal?.toString()||0), shippingFee:parseFloat(o.shippingFee?.toString()||0), totalAmount:parseFloat(o.totalAmount?.toString()||0), customer:userMap[o.userId?.toString()]||null, items:(o.items||[]).map(i => ({ ...i, unitPrice:parseFloat(i.unitPrice?.toString()||0), lineTotal:parseFloat(i.lineTotal?.toString()||0) })) })) });
      } catch (err) { next(err); }
    });

    // PUT /shop/admin/orders/:id — admin  ← BEFORE /shop/orders/:id
    app.put('/shop/admin/orders/:id', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const ORDER_TRANSITIONS = {
          pending:    ['pending','confirmed','cancelled'],
          confirmed:  ['confirmed','processing','ready','cancelled'],
          processing: ['processing','shipped','ready','cancelled'],
          ready:      ['ready','delivered'],           // pickup: ready → collected (delivered)
          shipped:    ['shipped','delivered'],
          delivered:  ['delivered','refunded'],
          cancelled:  ['cancelled'],
          refunded:   ['refunded'],
        };
        const order = await db.collection('ORDERS').findOne({ _id:new ObjectId(req.params.id) });
        if (!order) return res.status(404).json({ success:false, error:'Order not found' });
        if (req.body.status) {
          const allowed = ORDER_TRANSITIONS[order.status] || [];
          if (!allowed.includes(req.body.status)) return res.status(400).json({ success:false, error:`Cannot transition from "${order.status}" to "${req.body.status}"` });
        }
        const update = { updatedAt:new Date() };
        if (req.body.status         !== undefined) update.status         = req.body.status;
        if (req.body.trackingNumber !== undefined) update.trackingNumber = sanitiseText(req.body.trackingNumber, 100);
        if (req.body.notes          !== undefined) update.notes          = sanitiseText(req.body.notes, 500);
        if (req.body.paymentStatus  !== undefined) update.paymentStatus  = req.body.paymentStatus;
        const updated = await db.collection('ORDERS').findOneAndUpdate({ _id:new ObjectId(req.params.id) }, { $set:update }, { returnDocument:'after' });

        // ── Order shipped / ready-to-collect email ────────────────────────
        const isShippedEmail = req.body.status === 'shipped' || req.body.status === 'ready';
        if (isShippedEmail && process.env.RESEND_API_KEY) {
          try {
            const resend      = new Resend(process.env.RESEND_API_KEY);
            const customer    = await db.collection('USERS').findOne({ _id: order.userId }, { projection:{ email:1, firstName:1 } });
            const toEmail     = customer?.email || order.shippingAddress?.email;
            const tracking    = req.body.trackingNumber || order.trackingNumber;
            const shortId     = req.params.id.slice(-6).toUpperCase();
            const isPickupOrder = order.fulfillmentType === 'pickup';
            const itemsList   = (order.items || []).map(i =>
              `<tr>
                <td style="padding:0.5rem 0;color:#555;">${i.productName}</td>
                <td style="padding:0.5rem 0;text-align:right;color:#555;">x${i.quantity}</td>
              </tr>`
            ).join('');

            if (toEmail) {
              await resend.emails.send({
                from:    'NXL Beauty Bar <onboarding@resend.dev>',
                to:      toEmail,
                subject: isPickupOrder
                  ? `Your Order #${shortId} is Ready to Collect! 🏪`
                  : `Your Order #${shortId} Has Shipped! 🚚`,
                html: `
                  <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;">
                    <h2 style="font-family:Georgia,serif;color:#3d1f15;margin-bottom:0.25rem;">NXL Beauty Bar</h2>
                    <h3 style="color:#6b3528;margin-top:0;">${isPickupOrder ? 'Your Order is Ready to Collect! 🏪' : 'Your Order is on its Way! 🚚'}</h3>
                    <p style="color:#555;line-height:1.65;">Hi ${customer?.firstName || order.shippingAddress?.fullName},</p>
                    <p style="color:#555;line-height:1.65;">
                      ${isPickupOrder
                        ? `Great news — your order <strong>#${shortId}</strong> is ready for collection at our salon!`
                        : `Great news — your order <strong>#${shortId}</strong> has been shipped and is on its way to you!`
                      }
                    </p>

                    ${isPickupOrder ? `
                    <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:1rem 1.25rem;margin:1.25rem 0;">
                      <p style="margin:0;font-size:0.85rem;font-weight:700;color:#15803d;">📍 Collection Address</p>
                      <p style="margin:0.35rem 0 0;font-size:0.85rem;color:#555;">NXL Beauty Bar</p>
                      <p style="margin:0.15rem 0 0;font-size:0.82rem;color:#9e7060;">1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                      <p style="margin:0.15rem 0 0;font-size:0.82rem;color:#9e7060;">📞 068 511 3394 &nbsp;|&nbsp; 🕐 Mon–Sat 9AM–5PM</p>
                      <p style="margin:0.5rem 0 0;font-size:0.8rem;color:#6b3528;font-weight:600;">Please bring your order number: <span style="font-family:monospace;font-size:0.95rem;">#${shortId}</span></p>
                    </div>
                    ` : `
                    ${tracking ? `
                    <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:1rem 1.25rem;margin:1.25rem 0;text-align:center;">
                      <p style="margin:0;font-size:0.78rem;color:#15803d;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;">Tracking Number</p>
                      <p style="margin:0.4rem 0 0;font-size:1.25rem;font-weight:700;color:#3d1f15;font-family:monospace;">${tracking}</p>
                      <p style="margin:0.35rem 0 0;font-size:0.75rem;color:#9e7060;">Use this number to track your parcel</p>
                    </div>
                    ` : ''}
                    <div style="background:#fff8f3;border:1px solid #e0ccc4;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.25rem;">
                      <p style="margin:0;font-size:0.82rem;font-weight:700;color:#6b3528;">📦 Delivering to</p>
                      <p style="margin:0.35rem 0 0;font-size:0.82rem;color:#9e7060;line-height:1.65;">
                        ${order.shippingAddress?.fullName}<br/>
                        ${order.shippingAddress?.address}, ${order.shippingAddress?.city}<br/>
                        ${order.shippingAddress?.province || ''} ${order.shippingAddress?.postalCode || ''}
                      </p>
                    </div>
                    `}

                    <div style="background:#fff;border:1px solid #e0ccc4;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.25rem;">
                      <p style="margin:0 0 0.75rem;font-weight:700;color:#3d1f15;font-size:0.85rem;">Items in this order:</p>
                      <table style="width:100%;border-collapse:collapse;">
                        ${itemsList}
                      </table>
                      <hr style="border:none;border-top:1px solid #e0ccc4;margin:0.75rem 0;"/>
                      <div style="display:flex;justify-content:space-between;font-weight:700;color:#3d1f15;">
                        <span>Total Paid</span>
                        <span>R${parseFloat(order.totalAmount?.toString()||0).toFixed(2)}</span>
                      </div>
                    </div>

                    <p style="color:#9e7060;font-size:0.8rem;line-height:1.65;">Questions? WhatsApp us at <a href="https://wa.me/27685113394" style="color:#a0502e;">068 511 3394</a> or email <a href="mailto:nxlbeautybar@gmail.com" style="color:#a0502e;">nxlbeautybar@gmail.com</a>.</p>
                    <div style="text-align:center;margin:1.25rem 0;">
                      <a href="${(process.env.CORS_ORIGIN||'https://nxlbeautybar.co.za').replace(/\/$/,'')}/track/${req.params.id}" style="background:#3d1f15;color:#ffe8d6;text-decoration:none;padding:0.75rem 1.75rem;border-radius:50px;font-weight:700;font-size:0.85rem;display:inline-block;">📦 Track Your Order →</a>
                    </div>
                    <hr style="border:none;border-top:1px solid #e0ccc4;margin:1.5rem 0;"/>
                    <p style="color:#b08070;font-size:0.7rem;text-align:center;margin:0;">NXL Beauty Bar &middot; 1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                  </div>
                `,
              });
              logger.info(`[${isPickupOrder ? 'PICKUP' : 'SHIPPED'} EMAIL] Sent to ${toEmail}`, { orderId: req.params.id });
            }
          } catch (emailErr) {
            logger.error(`[SHIPPED EMAIL] Failed: ${emailErr.message}`);
          }
        }
        // ──────────────────────────────────────────────────────────────────

        // ── In-app notification for order status changes ─────────────────
        try {
          const notifMap = {
            shipped:   { type:'order_shipped',   title:`Order #${req.params.id.slice(-6).toUpperCase()} Shipped 🚚`,     body:'Your order is on its way! Track it to see the latest updates.' },
            ready:     { type:'order_ready',     title:`Order Ready to Collect 🏪`,                                       body:`Your order #${req.params.id.slice(-6).toUpperCase()} is ready for pickup at NXL Beauty Bar.` },
            delivered: { type:'order_delivered', title:`Order #${req.params.id.slice(-6).toUpperCase()} Delivered ✅`,   body:'Your order has been delivered. Enjoy your products!' },
            cancelled: { type:'booking_cancelled',title:`Order #${req.params.id.slice(-6).toUpperCase()} Cancelled`,     body:'Your order has been cancelled. Contact us if you have questions.' },
            refunded:  { type:'booking_cancelled',title:`Order #${req.params.id.slice(-6).toUpperCase()} Refunded ↩️`,   body:'Your refund has been processed. It may take 3–5 business days to appear.' },
          };
          const n = notifMap[req.body.status];
          if (n && order.userId) {
            await notifyClient(order.userId, { ...n, link: `/track/${req.params.id}`, meta: { orderId: req.params.id } });
          }
        } catch {}
        // ──────────────────────────────────────────────────────────────────

        // ── Stock management on status change ────────────────────────────
        if (req.body.status === 'cancelled' || req.body.status === 'refunded') {
          // Restore stock for each item when order is cancelled or refunded
          try {
            for (const item of order.items || []) {
              await db.collection('PRODUCTS').updateOne(
                { _id: item.productId },
                { $inc: { stock: item.quantity } }
              );
            }
            logger.info(`[STOCK] Restored stock for ${order.items?.length || 0} item(s) — order ${req.params.id} ${req.body.status}`);
          } catch (stockErr) {
            logger.error(`[STOCK] Failed to restore stock: ${stockErr.message}`);
          }
        }

        // ── Low stock alert email to admin after any stock-affecting update ──
        if (
          (req.body.status === 'cancelled' || req.body.status === 'refunded' ||
           req.body.status === 'delivered' || req.body.status === 'shipped') &&
          process.env.RESEND_API_KEY && process.env.ADMIN_EMAIL
        ) {
          try {
            const LOW_STOCK_THRESHOLD = 5;
            const productIds = (order.items || []).map(i => i.productId).filter(Boolean);
            const lowStockProducts = await db.collection('PRODUCTS').find({
              _id: { $in: productIds },
              isActive: true,
              stock: { $lte: LOW_STOCK_THRESHOLD },
            }).toArray();

            if (lowStockProducts.length > 0) {
              const resend = new Resend(process.env.RESEND_API_KEY);
              const itemRows = lowStockProducts.map(p =>
                `<tr>
                  <td style="padding:0.5rem 0.75rem;border-bottom:1px solid #e0ccc4;font-weight:600;color:#3d1f15;">${p.name}</td>
                  <td style="padding:0.5rem 0.75rem;border-bottom:1px solid #e0ccc4;text-align:center;">
                    <span style="font-weight:800;color:${p.stock === 0 ? '#dc2626' : '#c05621'};font-size:1rem;">${p.stock}</span>
                  </td>
                  <td style="padding:0.5rem 0.75rem;border-bottom:1px solid #e0ccc4;color:#9e7060;font-size:0.82rem;">${p.stock === 0 ? '🔴 Out of stock' : '🟡 Low stock'}</td>
                </tr>`
              ).join('');

              await resend.emails.send({
                from:    'NXL Beauty Bar <onboarding@resend.dev>',
                to:      process.env.ADMIN_EMAIL,
                subject: `⚠️ Low Stock Alert — ${lowStockProducts.length} product${lowStockProducts.length > 1 ? 's need' : ' needs'} restocking`,
                html: `
                  <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;">
                    <h2 style="font-family:Georgia,serif;color:#3d1f15;margin-bottom:0.25rem;">NXL Beauty Bar</h2>
                    <h3 style="color:#c05621;margin-top:0;">⚠️ Low Stock Alert</h3>
                    <p style="color:#555;line-height:1.65;">The following product${lowStockProducts.length > 1 ? 's are' : ' is'} running low and need${lowStockProducts.length === 1 ? 's' : ''} restocking:</p>
                    <table style="width:100%;border-collapse:collapse;margin:1.25rem 0;background:#fff;border-radius:10px;overflow:hidden;">
                      <thead>
                        <tr style="background:#f9f1ec;">
                          <th style="padding:0.6rem 0.75rem;text-align:left;font-size:0.72rem;color:#9e7060;text-transform:uppercase;letter-spacing:0.06em;">Product</th>
                          <th style="padding:0.6rem 0.75rem;text-align:center;font-size:0.72rem;color:#9e7060;text-transform:uppercase;letter-spacing:0.06em;">Stock Left</th>
                          <th style="padding:0.6rem 0.75rem;text-align:left;font-size:0.72rem;color:#9e7060;text-transform:uppercase;letter-spacing:0.06em;">Status</th>
                        </tr>
                      </thead>
                      <tbody>${itemRows}</tbody>
                    </table>
                    <p style="color:#9e7060;font-size:0.82rem;line-height:1.65;">Log in to your admin dashboard to update stock levels.</p>
                    <div style="text-align:center;margin:1.5rem 0;">
                      <a href="${(process.env.CORS_ORIGIN||'https://nxlbeautybar.co.za').replace(/\/$/,'')}/admin-dashboard" style="background:#3d1f15;color:#ffe8d6;text-decoration:none;padding:0.75rem 2rem;border-radius:50px;font-weight:700;font-size:0.88rem;display:inline-block;">Go to Admin Dashboard →</a>
                    </div>
                    <hr style="border:none;border-top:1px solid #e0ccc4;margin:1.5rem 0;"/>
                    <p style="color:#b08070;font-size:0.7rem;text-align:center;margin:0;">NXL Beauty Bar &middot; 1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                  </div>
                `,
              });
              logger.info(`[LOW STOCK EMAIL] Sent to admin — ${lowStockProducts.length} product(s) low`);
            }
          } catch (stockEmailErr) {
            logger.error(`[LOW STOCK EMAIL] Failed: ${stockEmailErr.message}`);
          }
        }
        // ─────────────────────────────────────────────────────────────────

        res.json({ success:true, data:updated });
      } catch (err) { next(err); }
    });

    // ── robots.txt ────────────────────────────────────────────────────────
    app.get('/robots.txt', (req, res) => {
      const frontendUrl = (process.env.CORS_ORIGIN || 'https://nxlbeautybar.co.za').replace(/\/$/, '');
      res.type('text/plain').send(
`# NXL Beauty Bar — robots.txt
# Generated dynamically by nxlbeautybar.co.za

User-agent: *
Allow: /

# Private pages
Disallow: /admin-dashboard
Disallow: /dashboard
Disallow: /profile
Disallow: /cart
Disallow: /checkout
Disallow: /orders
Disallow: /payment
Disallow: /payment-cancel
Disallow: /reset-password
Disallow: /shop/order-success

# Allow bots to crawl public pages
Allow: /shop
Allow: /shop/product/
Allow: /gallery
Allow: /book
Allow: /subscriptions
Allow: /login
Allow: /signup

# Crawl delay for polite bots
Crawl-delay: 1

Sitemap: ${frontendUrl}/sitemap.xml
Sitemap: ${frontendUrl}/sitemap-images.xml`
      );
    });

    // ── sitemap.xml — dynamic, all public pages ───────────────────────────
    app.get('/sitemap.xml', async (req, res) => {
      try {
        const frontendUrl = (process.env.CORS_ORIGIN || 'https://nxlbeautybar.co.za').replace(/\/$/, '');
        const now = new Date().toISOString().slice(0, 10);

        const [products, services, galleryPosts] = await Promise.all([
          db.collection('PRODUCTS').find({ isActive:true }, { projection:{ _id:1, name:1, updatedAt:1, category:1 } }).toArray(),
          db.collection('SERVICES').find({ isActive:true }, { projection:{ _id:1, name:1, updatedAt:1, category:1 } }).toArray(),
          db.collection('CLIENT_GALLERY').find({ status:'approved' }, { projection:{ _id:1, createdAt:1 } }).limit(100).toArray(),
        ]);

        const staticPages = [
          { url:'/',             priority:'1.0', freq:'weekly'  },
          { url:'/shop',         priority:'0.9', freq:'daily'   },
          { url:'/book',         priority:'0.9', freq:'weekly'  },
          { url:'/gallery',      priority:'0.7', freq:'weekly'  },
          { url:'/subscriptions',priority:'0.8', freq:'monthly' },
          { url:'/login',        priority:'0.5', freq:'monthly' },
          { url:'/signup',       priority:'0.5', freq:'monthly' },
        ];

        const productPages = products.map(p => ({
          url:     `/shop/product/${p._id}`,
          priority:'0.8',
          freq:    'weekly',
          lastmod: p.updatedAt ? new Date(p.updatedAt).toISOString().slice(0,10) : now,
        }));

        const allPages = [
          ...staticPages.map(p => ({ ...p, lastmod:now })),
          ...productPages,
        ];

        const urlEntries = allPages.map(p => `
  <url>
    <loc>${frontendUrl}${p.url}</loc>
    <lastmod>${p.lastmod}</lastmod>
    <changefreq>${p.freq}</changefreq>
    <priority>${p.priority}</priority>
  </url>`).join('');

        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
${urlEntries}
</urlset>`;

        res.type('application/xml').send(xml);
        logger.info(`[SITEMAP] Served ${allPages.length} URLs`);
      } catch (err) {
        logger.error(`[SITEMAP] Error: ${err.message}`);
        res.status(500).send('Error generating sitemap');
      }
    });

    // ── sitemap-images.xml — all product + gallery images ─────────────────
    app.get('/sitemap-images.xml', async (req, res) => {
      try {
        const frontendUrl = (process.env.CORS_ORIGIN || 'https://nxlbeautybar.co.za').replace(/\/$/, '');
        const [products, galleryPosts] = await Promise.all([
          db.collection('PRODUCTS').find({ isActive:true }, { projection:{ _id:1, name:1, images:1 } }).toArray(),
          db.collection('CLIENT_GALLERY').find({ status:'approved' }, { projection:{ _id:1, afterImageUrl:1, caption:1 } }).limit(100).toArray(),
        ]);

        const entries = [
          ...products.flatMap(p => (p.images||[]).slice(0,3).map(img => ({
            pageUrl: `${frontendUrl}/shop/product/${p._id}`,
            imageUrl: img,
            title:    p.name,
            caption:  `${p.name} — NXL Beauty Bar`,
          }))),
          ...galleryPosts.map(g => ({
            pageUrl:  `${frontendUrl}/gallery`,
            imageUrl: g.afterImageUrl,
            title:    g.caption || 'Before & After — NXL Beauty Bar',
            caption:  g.caption || 'Client transformation at NXL Beauty Bar, Soweto',
          })),
        ].filter(e => e.imageUrl?.startsWith('http'));

        const urlEntries = entries.map(e => `
  <url>
    <loc>${e.pageUrl}</loc>
    <image:image>
      <image:loc>${e.imageUrl}</image:loc>
      <image:title>${e.title.replace(/[<>&'"]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;',"'":'&apos;','"':'&quot;'}[c]))}</image:title>
      <image:caption>${e.caption.replace(/[<>&'"]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;',"'":'&apos;','"':'&quot;'}[c]))}</image:caption>
    </image:image>
  </url>`).join('');

        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
${urlEntries}
</urlset>`;

        res.type('application/xml').send(xml);
        logger.info(`[SITEMAP-IMAGES] Served ${entries.length} image URLs`);
      } catch (err) {
        logger.error(`[SITEMAP-IMAGES] Error: ${err.message}`);
        res.status(500).send('Error generating image sitemap');
      }
    });
    // ──────────────────────────────────────────────────────────────────────
    app.get('/shop/orders/:id', authenticateToken, async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const order = await db.collection('ORDERS').findOne({ _id:new ObjectId(req.params.id) });
        if (!order) return res.status(404).json({ success:false, error:'Order not found' });
        if (req.user.role !== 'admin' && order.userId.toString() !== req.user.userId) return res.status(403).json({ success:false, error:'Access denied' });
        res.json({ success:true, data:{ ...order, subtotal:parseFloat(order.subtotal?.toString()||0), shippingFee:parseFloat(order.shippingFee?.toString()||0), totalAmount:parseFloat(order.totalAmount?.toString()||0), items:(order.items||[]).map(i => ({ ...i, unitPrice:parseFloat(i.unitPrice?.toString()||0), lineTotal:parseFloat(i.lineTotal?.toString()||0) })) } });
      } catch (err) { next(err); }
    });

    // =====================
    // DISCOUNT CODES
    // =====================

    // ══════════════════════════════════════════════════════════════════════
    // LOYALTY PROGRAM
    // ══════════════════════════════════════════════════════════════════════
    // Config — edit these to change the program rules
    const LOYALTY_CONFIG = {
      pointsPerRand:      1,      // 1 point per R1 spent on bookings only
      bookingBonus:       0,      // no extra bonus per booking
      signupBonus:        0,      // no welcome points on registration
      pointValue:         0.10,   // 1 point = R0.10 discount (100 pts = R10)
      minRedemption:      100,    // minimum points to redeem
      maxRedemptionPct:   50,     // max % of order value that can be paid with points
    };

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

    // ── POST /loyalty/redeem-on-payment — redeem points when payment success page loads ──
    app.post('/loyalty/redeem-on-payment', authenticateToken, async (req, res, next) => {
      try {
        const { appointmentId, pointsToRedeem } = req.body;
        if (!appointmentId) return res.status(400).json({ success:false, error:'appointmentId required' });
        if (!pointsToRedeem || parseInt(pointsToRedeem) < LOYALTY_CONFIG.minRedemption) {
          return res.json({ success:true, data:{ redeemed:false, reason:'No points to redeem' } });
        }

        let apptId;
        try { apptId = new ObjectId(appointmentId); } catch { return res.status(400).json({ success:false, error:'Invalid appointmentId' }); }

        const userId = new ObjectId(req.user.userId);
        const appt = await db.collection('APPOINTMENTS').findOne({ _id:apptId, userId });
        if (!appt) return res.status(404).json({ success:false, error:'Appointment not found' });

        const account = await getLoyaltyAccount(userId);
        const pts = Math.min(parseInt(pointsToRedeem), account.points);

        if (pts >= LOYALTY_CONFIG.minRedemption) {
          const discount = parseFloat((pts * LOYALTY_CONFIG.pointValue).toFixed(2));
          console.log(`[REDEEM ON PAYMENT] Redeeming ${pts} pts for user ${userId}`);
          
          await redeemPoints(userId, pts, `Redeemed on payment success — ${pts} pts = R${discount} off`, apptId);
          console.log(`[REDEEM ON PAYMENT] ✅ Successfully redeemed ${pts} pts`);

          // Update appointment with redemption info if not already set
          await db.collection('APPOINTMENTS').updateOne(
            { _id:apptId },
            { $set:{ loyaltyPointsRedeemed:pts, loyaltyBalanceDiscount:discount, updatedAt:new Date() } }
          );

          return res.json({
            success:true,
            data:{
              redeemed:true,
              pointsRedeemed:pts,
              discountAmount:discount,
              remainingPoints:account.points-pts,
            },
          });
        }

        res.json({ success:true, data:{ redeemed:false, reason:'Points less than minimum' } });
      } catch (err) { 
        console.error('[REDEEM ON PAYMENT] Error:', err.message);
        next(err); 
      }
    });

    // ── GET /loyalty/me — get current user's loyalty account ──────────────
    app.get('/loyalty/me', authenticateToken, async (req, res, next) => {
      try {
        const userId  = new ObjectId(req.user.userId);
        const account = await getLoyaltyAccount(userId);
        const txns    = await db.collection('LOYALTY_TRANSACTIONS')
          .find({ userId })
          .sort({ createdAt: -1 })
          .limit(20)
          .toArray();
        const randValue = (account.points * LOYALTY_CONFIG.pointValue).toFixed(2);
        res.json({
          success: true,
          data: {
            ...account,
            randValue,
            config: {
              pointValue:      LOYALTY_CONFIG.pointValue,
              minRedemption:   LOYALTY_CONFIG.minRedemption,
              maxRedemptionPct: LOYALTY_CONFIG.maxRedemptionPct,
            },
            transactions: txns,
          },
        });
      } catch (err) { next(err); }
    });

    // ── POST /loyalty/redeem — validate & reserve points for checkout ──────
    app.post('/loyalty/redeem', authenticateToken, async (req, res, next) => {
      try {
        const { pointsToRedeem, orderSubtotal } = req.body;
        const userId  = new ObjectId(req.user.userId);
        const account = await getLoyaltyAccount(userId);

        if (!pointsToRedeem || pointsToRedeem < LOYALTY_CONFIG.minRedemption)
          return res.status(400).json({ success: false, error: `Minimum redemption is ${LOYALTY_CONFIG.minRedemption} points.` });

        if (pointsToRedeem > account.points)
          return res.status(400).json({ success: false, error: 'Insufficient points.' });

        const maxDiscount = (orderSubtotal || 0) * (LOYALTY_CONFIG.maxRedemptionPct / 100);
        const discount    = Math.min(pointsToRedeem * LOYALTY_CONFIG.pointValue, maxDiscount);
        const finalPoints = Math.round(discount / LOYALTY_CONFIG.pointValue);

        res.json({
          success: true,
          data: {
            pointsRedeemed: finalPoints,
            discountAmount: parseFloat(discount.toFixed(2)),
            remainingPoints: account.points - finalPoints,
          },
        });
      } catch (err) { next(err); }
    });

    // ── GET /loyalty/admin/:userId — admin view user loyalty ──────────────
    app.get('/loyalty/admin/:userId', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const userId  = new ObjectId(req.params.userId);
        const account = await getLoyaltyAccount(userId);
        const txns    = await db.collection('LOYALTY_TRANSACTIONS')
          .find({ userId }).sort({ createdAt: -1 }).limit(50).toArray();
        res.json({ success: true, data: { ...account, transactions: txns } });
      } catch (err) { next(err); }
    });

    // ── POST /loyalty/admin/adjust — admin manually adjust points ─────────
    app.post('/loyalty/admin/adjust', authenticateToken, authorizeRole('admin'),
      body('userId').isMongoId(),
      body('points').isInt(),
      body('reason').isString().notEmpty(),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const userId = new ObjectId(req.body.userId);
          const pts    = parseInt(req.body.points, 10);
          if (pts > 0) await awardPoints(userId, pts, `Admin adjustment: ${req.body.reason}`);
          else if (pts < 0) {
            const account = await getLoyaltyAccount(userId);
            const deduct  = Math.min(Math.abs(pts), account.points);
            await redeemPoints(userId, deduct, `Admin adjustment: ${req.body.reason}`);
          }
          const updated = await getLoyaltyAccount(userId);
          res.json({ success: true, data: updated });
        } catch (err) { next(err); }
      }
    );

    // ── GET /loyalty/admin/leaderboard — top 20 members ───────────────────
    app.get('/loyalty/leaderboard', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const top = await db.collection('LOYALTY').find({})
          .sort({ totalEarned: -1 }).limit(20).toArray();
        const userIds = top.map(t => t.userId);
        const users   = await db.collection('USERS').find({ _id: { $in: userIds } })
          .project({ firstName:1, lastName:1, email:1 }).toArray();
        const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
        const result  = top.map(t => ({
          ...t,
          user: userMap[t.userId.toString()],
          randValue: (t.points * LOYALTY_CONFIG.pointValue).toFixed(2),
        }));
        res.json({ success: true, data: result });
      } catch (err) { next(err); }
    });
    // ══════════════════════════════════════════════════════════════════════

    // ── POST /appointments/:id/whatsapp-reminder — manual WhatsApp send ───
    app.post('/appointments/:id/whatsapp-reminder', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const appt = await db.collection('APPOINTMENTS').findOne({ _id: new ObjectId(req.params.id) });
        if (!appt) return res.status(404).json({ success:false, error:'Appointment not found' });
        const client = await db.collection('USERS').findOne({ _id: appt.userId });
        const phone  = client?.phone || req.body.phone;
        if (!phone) return res.status(400).json({ success:false, error:'No phone number on file. Provide phone in request body.' });

        const services = await db.collection('SERVICES').find({ _id: { $in: appt.serviceIds || [] } }).project({ name:1 }).toArray();
        const svcNames = services.map(s => s.name).join(', ') || 'your appointment';
        const text = `Hi ${client?.firstName || 'there'}! 👋 This is a reminder from NXL Beauty Bar. You have an appointment for ${svcNames} on ${appt.date} at ${appt.time}. 📍 1948 Mahalefele Rd, Dube, Soweto. Please arrive 5 mins early. See you soon! 💅`;
        const waUrl = `https://wa.me/${phone.replace(/\D/g,'')}?text=${encodeURIComponent(text)}`;

        res.json({ success:true, data:{ waUrl, phone, message: text } });
      } catch (err) { next(err); }
    });
    // ──────────────────────────────────────────────────────────────────────

    // ══════════════════════════════════════════════════════════════════════
    // SUBSCRIPTION PACKAGES
    // ══════════════════════════════════════════════════════════════════════

    // ── GET /subscription-plans — public list of available plans ──────────
    app.get('/subscription-plans', async (req, res, next) => {
      try {
        const plans = await db.collection('SUBSCRIPTION_PLANS')
          .find({ isActive: true })
          .sort({ sortOrder: 1, price: 1 })
          .toArray();
        res.json({ success: true, data: plans.map(p => ({ ...p, price: parseFloat(p.price?.toString() || 0) })) });
      } catch (err) { next(err); }
    });

    // ── CRUD for plans (admin) ─────────────────────────────────────────────
    app.post('/subscription-plans', authenticateToken, authorizeRole('admin'),
      body('name').isString().notEmpty(),
      body('price').isFloat({ min: 0 }),
      body('bookingsPerMonth').isInt({ min: 1 }),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const { name, description, price, bookingsPerMonth, discountPct, features, color, isPopular, sortOrder } = req.body;
          const plan = {
            name: sanitiseText(name, 80),
            description: sanitiseText(description || '', 300),
            price: Decimal128.fromString(parseFloat(price).toFixed(2)),
            bookingsPerMonth: parseInt(bookingsPerMonth),
            discountPct: discountPct ? parseInt(discountPct) : 0,
            features: Array.isArray(features) ? features.map(f => sanitiseText(f, 100)) : [],
            color: color || '#6366f1',
            isPopular: !!isPopular,
            sortOrder: sortOrder || 0,
            isActive: true,
            subscriberCount: 0,
            createdAt: new Date(), updatedAt: new Date(),
          };
          const result = await db.collection('SUBSCRIPTION_PLANS').insertOne(plan);
          res.status(201).json({ success: true, data: { _id: result.insertedId, ...plan } });
        } catch (err) { next(err); }
      }
    );

    app.put('/subscription-plans/:id', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const allowed = ['name','description','price','bookingsPerMonth','discountPct','features','color','isPopular','isActive','sortOrder'];
        const update  = {};
        allowed.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });
        if (update.price) update.price = Decimal128.fromString(parseFloat(update.price).toFixed(2));
        update.updatedAt = new Date();
        await db.collection('SUBSCRIPTION_PLANS').updateOne({ _id: new ObjectId(req.params.id) }, { $set: update });
        const updated = await db.collection('SUBSCRIPTION_PLANS').findOne({ _id: new ObjectId(req.params.id) });
        res.json({ success: true, data: updated });
      } catch (err) { next(err); }
    });

    app.delete('/subscription-plans/:id', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        // Soft delete — don't delete if active subscribers
        const activeCount = await db.collection('SUBSCRIPTIONS').countDocuments({ planId: new ObjectId(req.params.id), status: 'active' });
        if (activeCount > 0) return res.status(400).json({ success:false, error:`Cannot delete — ${activeCount} active subscriber(s). Deactivate the plan instead.` });
        await db.collection('SUBSCRIPTION_PLANS').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { isActive: false, updatedAt: new Date() } });
        res.json({ success: true });
      } catch (err) { next(err); }
    });

    // ── POST /subscriptions — subscribe to a plan ──────────────────────────
    app.post('/subscriptions', authenticateToken, async (req, res, next) => {
      try {
        const { planId } = req.body;
        if (!planId?.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid plan ID' });

        const userId = new ObjectId(req.user.userId);
        const plan   = await db.collection('SUBSCRIPTION_PLANS').findOne({ _id: new ObjectId(planId), isActive: true });
        if (!plan) return res.status(404).json({ success:false, error:'Plan not found or no longer available' });

        // Check for existing active subscription
        const existing = await db.collection('SUBSCRIPTIONS').findOne({ userId, status: 'active' });
        if (existing) return res.status(409).json({ success:false, error:'You already have an active subscription. Cancel it before subscribing to a new plan.' });

        const planPrice = parseFloat(plan.price?.toString() || 0);
        const frontendUrl = process.env.FRONTEND_URL || 'https://nxlbeautybar.co.za';

        // Create pending subscription
        const now = new Date();
        const renewalDate = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
        const sub = {
          userId, planId: new ObjectId(planId),
          planName: plan.name, planPrice: plan.price,
          status: 'pending_payment',
          bookingsRemaining: plan.bookingsPerMonth,
          bookingsPerMonth:  plan.bookingsPerMonth,
          renewalDate, startDate: now,
          autoRenew: true,
          payments: [],
          createdAt: now, updatedAt: now,
        };
        const result = await db.collection('SUBSCRIPTIONS').insertOne(sub);
        const subId  = result.insertedId.toString();

        // Create Yoco checkout
        const yocoResp = await fetchFn('https://payments.yoco.com/api/checkouts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.YOCO_SECRET_KEY}` },
          body: JSON.stringify({
            amount:     Math.round(planPrice * 100),
            currency:   'ZAR',
            successUrl: `${frontendUrl}/subscriptions/success?subId=${subId}`,
            cancelUrl:  `${frontendUrl}/subscriptions?cancelled=true`,
            metadata:   { subId, type: 'subscription', userId: req.user.userId, planId },
          }),
        });
        const yocoData = await yocoResp.json();
        if (!yocoData.redirectUrl) return res.status(500).json({ success:false, error:'Payment init failed.' });

        await db.collection('SUBSCRIPTIONS').updateOne({ _id: result.insertedId }, { $set: { yocoCheckoutId: yocoData.id, updatedAt: new Date() } });
        res.json({ success: true, data: { subId, checkoutUrl: yocoData.redirectUrl } });
      } catch (err) { next(err); }
    });

    // ── POST /subscriptions/confirm — called after successful Yoco payment ──
    app.post('/subscriptions/confirm', authenticateToken, async (req, res, next) => {
      try {
        const { subId } = req.body;
        if (!subId?.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid subscription ID' });

        const sub = await db.collection('SUBSCRIPTIONS').findOne({ _id: new ObjectId(subId) });
        if (!sub) return res.status(404).json({ success:false, error:'Subscription not found' });
        if (sub.status === 'active') return res.json({ success: true, data: sub }); // already confirmed

        const now = new Date();
        await db.collection('SUBSCRIPTIONS').updateOne(
          { _id: new ObjectId(subId) },
          {
            $set:  { status: 'active', activatedAt: now, updatedAt: now },
            $push: { payments: { amount: parseFloat(sub.planPrice?.toString() || 0), date: now, type: 'initial' } },
          }
        );

        // Increment subscriber count on plan
        await db.collection('SUBSCRIPTION_PLANS').updateOne({ _id: sub.planId }, { $inc: { subscriberCount: 1 } });

        // Award loyalty points for subscribing
        try { await awardPoints(sub.userId, 100, `Subscribed to ${sub.planName}`); } catch {}

        // In-app notification
        try {
          await notifyClient(sub.userId, {
            type:  'order_confirmed',
            title: `${sub.planName} Subscription Active! 💅`,
            body:  `Your subscription is now active. You have ${sub.bookingsPerMonth} bookings this month. Book anytime!`,
            link:  '/profile',
          });
        } catch {}

        // Confirmation email
        if (process.env.RESEND_API_KEY) {
          try {
            const resend = new Resend(process.env.RESEND_API_KEY);
            const user   = await db.collection('USERS').findOne({ _id: sub.userId }, { projection:{ email:1, firstName:1 } });
            if (user?.email) {
              await resend.emails.send({
                from:    'NXL Beauty Bar <onboarding@resend.dev>',
                to:      user.email,
                subject: `Your ${sub.planName} Subscription is Active! 💅`,
                html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;">
                  <h2 style="font-family:Georgia,serif;color:#3d1f15;">NXL Beauty Bar</h2>
                  <h3 style="color:#6b3528;">Subscription Confirmed! 💅</h3>
                  <p>Hi ${user.firstName},</p>
                  <p>Your <strong>${sub.planName}</strong> subscription is now active.</p>
                  <div style="background:#fff8f3;border:1px solid #e0ccc4;border-radius:10px;padding:1rem;margin:1rem 0;">
                    <p style="margin:0;font-size:0.85rem;color:#6b3528;"><strong>📅 Bookings this month:</strong> ${sub.bookingsPerMonth}</p>
                    <p style="margin:0.5rem 0 0;font-size:0.85rem;color:#6b3528;"><strong>🔄 Renewal date:</strong> ${new Date(sub.renewalDate).toLocaleDateString('en-ZA', { day:'numeric', month:'long', year:'numeric' })}</p>
                  </div>
                  <p>Book your appointments at <a href="${process.env.CORS_ORIGIN || 'https://nxlbeautybar.co.za'}" style="color:#a0502e;">nxlbeautybar.co.za</a></p>
                </div>`,
              });
            }
          } catch (emailErr) { logger.error(`[SUB EMAIL] ${emailErr.message}`); }
        }

        const updated = await db.collection('SUBSCRIPTIONS').findOne({ _id: new ObjectId(subId) });
        res.json({ success: true, data: updated });
      } catch (err) { next(err); }
    });

    // ── GET /subscriptions/my — current user's subscription ───────────────
    app.get('/subscriptions/my', authenticateToken, async (req, res, next) => {
      try {
        const userId = new ObjectId(req.user.userId);
        const sub    = await db.collection('SUBSCRIPTIONS').findOne({ userId, status: { $in: ['active', 'pending_payment', 'past_due'] } });
        if (!sub) return res.json({ success: true, data: null });

        const plan = await db.collection('SUBSCRIPTION_PLANS').findOne({ _id: sub.planId });
        res.json({
          success: true,
          data: { ...sub, planPrice: parseFloat(sub.planPrice?.toString() || 0), plan },
        });
      } catch (err) { next(err); }
    });

    // ── POST /subscriptions/:id/cancel — cancel subscription ──────────────
    app.post('/subscriptions/:id/cancel', authenticateToken, async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });

        const sub = await db.collection('SUBSCRIPTIONS').findOne({ _id: new ObjectId(req.params.id) });
        if (!sub) return res.status(404).json({ success:false, error:'Subscription not found' });

        // Only owner or admin can cancel
        if (req.user.role !== 'admin' && String(sub.userId) !== String(req.user.userId))
          return res.status(403).json({ success:false, error:'Not authorized' });

        await db.collection('SUBSCRIPTIONS').updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status: 'cancelled', cancelledAt: new Date(), autoRenew: false, updatedAt: new Date() } }
        );

        // Decrement subscriber count
        await db.collection('SUBSCRIPTION_PLANS').updateOne({ _id: sub.planId }, { $inc: { subscriberCount: -1 } });

        // Notify user
        try {
          await notifyClient(sub.userId, {
            type:  'booking_cancelled',
            title: 'Subscription Cancelled',
            body:  `Your ${sub.planName} subscription has been cancelled. Your remaining ${sub.bookingsRemaining} booking credits are still valid until ${new Date(sub.renewalDate).toLocaleDateString('en-ZA')}.`,
            link:  '/subscriptions',
          });
        } catch {}

        res.json({ success: true });
      } catch (err) { next(err); }
    });

    // ── GET /subscriptions/admin — admin view all subscriptions ───────────
    app.get('/subscriptions/admin', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const { status } = req.query;
        const filter = status && status !== 'all' ? { status } : {};
        const page   = Math.max(1, parseInt(req.query.page || '1'));
        const limit  = Math.min(100, parseInt(req.query.limit || '50'));

        const [subs, total] = await Promise.all([
          db.collection('SUBSCRIPTIONS').find(filter).sort({ createdAt:-1 }).skip((page-1)*limit).limit(limit).toArray(),
          db.collection('SUBSCRIPTIONS').countDocuments(filter),
        ]);

        const userIds = [...new Set(subs.map(s => s.userId))];
        const users   = await db.collection('USERS').find({ _id: { $in: userIds } }).project({ firstName:1, lastName:1, email:1, phone:1 }).toArray();
        const uMap    = Object.fromEntries(users.map(u => [u._id.toString(), u]));

        const enriched = subs.map(s => ({
          ...s,
          planPrice: parseFloat(s.planPrice?.toString() || 0),
          user: uMap[s.userId?.toString()],
        }));

        // Stats
        const stats = {
          active:    await db.collection('SUBSCRIPTIONS').countDocuments({ status: 'active' }),
          cancelled: await db.collection('SUBSCRIPTIONS').countDocuments({ status: 'cancelled' }),
          total:     await db.collection('SUBSCRIPTIONS').countDocuments({}),
          mrr:       (await db.collection('SUBSCRIPTIONS').aggregate([
            { $match: { status: 'active' } },
            { $group: { _id: null, total: { $sum: { $toDouble: '$planPrice' } } } },
          ]).toArray())[0]?.total || 0,
        };

        res.json({ success:true, data: enriched, stats, total, page, pages: Math.ceil(total/limit) });
      } catch (err) { next(err); }
    });

    // ── POST /subscriptions/:id/use-credit — deduct a booking credit ───────
    app.post('/subscriptions/:id/use-credit', authenticateToken, async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });

        const sub = await db.collection('SUBSCRIPTIONS').findOne({
          _id: new ObjectId(req.params.id),
          userId: new ObjectId(req.user.userId),
          status: 'active',
        });
        if (!sub) return res.status(404).json({ success:false, error:'Active subscription not found' });
        if (sub.bookingsRemaining <= 0) return res.status(400).json({ success:false, error:'No booking credits remaining this month.' });

        await db.collection('SUBSCRIPTIONS').updateOne(
          { _id: new ObjectId(req.params.id) },
          { $inc: { bookingsRemaining: -1 }, $set: { updatedAt: new Date() } }
        );

        res.json({ success: true, data: { bookingsRemaining: sub.bookingsRemaining - 1 } });
      } catch (err) { next(err); }
    });
    // ══════════════════════════════════════════════════════════════════════

    // ══════════════════════════════════════════════════════════════════════
    // REFERRAL PROGRAM
    // ══════════════════════════════════════════════════════════════════════

    const REFERRAL_CONFIG = {
      referrerPoints:    200,   // points awarded to referrer when friend books
      refereeDiscount:   50,    // rand discount for the new friend's first order
      signupBonus:       0,     // no points on signup — only on first booking
      maxReferrals:      null,
    };

    // Helper: generate unique referral code
    async function generateReferralCode(userId) {
      const base    = userId.toString().slice(-4).toUpperCase();
      const chars   = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      let code;
      let attempts = 0;
      do {
        const rand = Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        code = `NXL${base}${rand}`;
        attempts++;
      } while (attempts < 10 && await db.collection('USERS').findOne({ referralCode: code }));
      return code;
    }

    // Helper: get or create referral code for a user
    async function getOrCreateReferralCode(userId) {
      const user = await db.collection('USERS').findOne({ _id: userId }, { projection: { referralCode: 1 } });
      if (user?.referralCode) return user.referralCode;
      const code = await generateReferralCode(userId);
      await db.collection('USERS').updateOne({ _id: userId }, { $set: { referralCode: code, updatedAt: new Date() } });
      return code;
    }

    // GET /referrals/my — get current user's referral info + stats
    app.get('/referrals/my', authenticateToken, async (req, res, next) => {
      try {
        const userId = new ObjectId(req.user.userId);
        const code   = await getOrCreateReferralCode(userId);

        const [referrals, pendingCount, completedCount] = await Promise.all([
          db.collection('REFERRALS')
            .find({ referrerId: userId })
            .sort({ createdAt: -1 })
            .limit(20)
            .toArray(),
          db.collection('REFERRALS').countDocuments({ referrerId: userId, status: 'signed_up' }),
          db.collection('REFERRALS').countDocuments({ referrerId: userId, status: 'rewarded' }),
        ]);

        const totalPointsEarned = referrals
          .filter(r => r.status === 'rewarded')
          .reduce((sum, r) => sum + (r.pointsAwarded || 0), 0);

        // Enrich with referee names
        const refereeIds = referrals.map(r => r.refereeId).filter(Boolean);
        const referees   = await db.collection('USERS').find({ _id: { $in: refereeIds } })
          .project({ firstName: 1, lastName: 1 }).toArray();
        const refereeMap = Object.fromEntries(referees.map(u => [u._id.toString(), u]));

        const enriched = referrals.map(r => ({
          ...r,
          refereeName: r.refereeId ? `${refereeMap[r.refereeId.toString()]?.firstName || ''} ${refereeMap[r.refereeId.toString()]?.lastName || ''}`.trim() || 'Friend' : 'Pending',
        }));

        const frontendUrl = (process.env.CORS_ORIGIN || 'https://nxlbeautybar.co.za').replace(/\/$/, '');

        res.json({
          success: true,
          data: {
            referralCode: code,
            referralUrl:  `${frontendUrl}/signup?ref=${code}`,
            stats: {
              totalReferrals:     referrals.length,
              pendingReferrals:   pendingCount,
              completedReferrals: completedCount,
              totalPointsEarned,
            },
            config: REFERRAL_CONFIG,
            referrals: enriched,
          },
        });
      } catch (err) { next(err); }
    });

    // POST /referrals/validate — check a referral code (called on signup page)
    app.post('/referrals/validate', async (req, res, next) => {
      try {
        const { code } = req.body;
        if (!code) return res.status(400).json({ success: false, error: 'Code required' });

        const referrer = await db.collection('USERS').findOne(
          { referralCode: code.trim().toUpperCase() },
          { projection: { firstName: 1, lastName: 1 } }
        );
        if (!referrer) return res.status(404).json({ success: false, error: 'Invalid referral code.' });

        res.json({
          success: true,
          data: {
            valid:        true,
            referrerName: `${referrer.firstName} ${referrer.lastName}`,
            discount:     REFERRAL_CONFIG.refereeDiscount,
            message:      `You were referred by ${referrer.firstName}! You'll get a R${REFERRAL_CONFIG.refereeDiscount} discount on your first order.`,
          },
        });
      } catch (err) { next(err); }
    });

    // GET /referrals/admin — admin view all referrals
    app.get('/referrals/admin', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const page  = Math.max(1, parseInt(req.query.page || '1'));
        const limit = Math.min(100, parseInt(req.query.limit || '50'));
        const referrals = await db.collection('REFERRALS').find({}).sort({ createdAt: -1 }).skip((page-1)*limit).limit(limit).toArray();
        const total     = await db.collection('REFERRALS').countDocuments({});

        // Enrich
        const allIds = [...new Set([...referrals.map(r=>r.referrerId), ...referrals.map(r=>r.refereeId)].filter(Boolean))];
        const users  = await db.collection('USERS').find({ _id:{ $in:allIds } }).project({ firstName:1, lastName:1, email:1 }).toArray();
        const uMap   = Object.fromEntries(users.map(u => [u._id.toString(), u]));

        const enriched = referrals.map(r => ({
          ...r,
          referrer: uMap[r.referrerId?.toString()],
          referee:  r.refereeId ? uMap[r.refereeId.toString()] : null,
        }));

        res.json({ success:true, data:enriched, total, page, pages:Math.ceil(total/limit) });
      } catch (err) { next(err); }
    });
    // ══════════════════════════════════════════════════════════════════════

    // ══════════════════════════════════════════════════════════════════════
    // CLIENT NOTIFICATIONS — in-app notification centre for customers
    // ══════════════════════════════════════════════════════════════════════

    // Notification types:
    // booking_confirmed, booking_cancelled, booking_reminder,
    // order_confirmed, order_shipped, order_ready, order_delivered,
    // loyalty_earned, loyalty_redeemed, loyalty_tier_up,
    // gift_card_received, promotion, system

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

    // GET /client-notifications — get current user's notifications
    app.get('/client-notifications', authenticateToken, async (req, res, next) => {
      try {
        const userId = new ObjectId(req.user.userId);
        const page   = Math.max(1, parseInt(req.query.page || '1'));
        const limit  = Math.min(50, parseInt(req.query.limit || '20'));

        const [notifications, total, unreadCount] = await Promise.all([
          db.collection('CLIENT_NOTIFICATIONS')
            .find({ userId })
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .toArray(),
          db.collection('CLIENT_NOTIFICATIONS').countDocuments({ userId }),
          db.collection('CLIENT_NOTIFICATIONS').countDocuments({ userId, read: false }),
        ]);

        res.json({
          success: true,
          data: notifications,
          total, unreadCount,
          page,
          pages: Math.ceil(total / limit),
        });
      } catch (err) { next(err); }
    });

    // GET /client-notifications/unread-count — lightweight poll
    app.get('/client-notifications/unread-count', authenticateToken, async (req, res, next) => {
      try {
        const userId = new ObjectId(req.user.userId);
        const count  = await db.collection('CLIENT_NOTIFICATIONS').countDocuments({ userId, read: false });
        res.json({ success: true, data: { count } });
      } catch (err) { next(err); }
    });

    // POST /client-notifications/mark-read — mark one or all as read
    app.post('/client-notifications/mark-read', authenticateToken, async (req, res, next) => {
      try {
        const userId = new ObjectId(req.user.userId);
        const { id } = req.body; // if id provided, mark single; else mark all

        if (id && id.match(/^[a-f\d]{24}$/i)) {
          await db.collection('CLIENT_NOTIFICATIONS').updateOne(
            { _id: new ObjectId(id), userId },
            { $set: { read: true, readAt: new Date() } }
          );
        } else {
          await db.collection('CLIENT_NOTIFICATIONS').updateMany(
            { userId, read: false },
            { $set: { read: true, readAt: new Date() } }
          );
        }
        res.json({ success: true });
      } catch (err) { next(err); }
    });

    // DELETE /client-notifications/:id — delete one notification
    app.delete('/client-notifications/:id', authenticateToken, async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i))
          return res.status(400).json({ success: false, error: 'Invalid ID' });
        await db.collection('CLIENT_NOTIFICATIONS').deleteOne({
          _id: new ObjectId(req.params.id),
          userId: new ObjectId(req.user.userId),
        });
        res.json({ success: true });
      } catch (err) { next(err); }
    });

    // DELETE /client-notifications — clear all for user
    app.delete('/client-notifications', authenticateToken, async (req, res, next) => {
      try {
        await db.collection('CLIENT_NOTIFICATIONS').deleteMany({ userId: new ObjectId(req.user.userId) });
        res.json({ success: true });
      } catch (err) { next(err); }
    });

    // POST /client-notifications/admin-send — admin broadcast to all or specific user
    app.post('/client-notifications/admin-send', authenticateToken, authorizeRole('admin'),
      body('title').isString().notEmpty(),
      body('body').isString().notEmpty(),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());

          const { title, body: msgBody, type = 'promotion', link, userId: targetUserId } = req.body;

          if (targetUserId?.match(/^[a-f\d]{24}$/i)) {
            // Single user
            await notifyClient(new ObjectId(targetUserId), { type, title, body: msgBody, link });
            res.json({ success: true, data: { sent: 1 } });
          } else {
            // All users
            const users = await db.collection('USERS').find({ role: 'user', isActive: { $ne: false } }).project({ _id: 1 }).toArray();
            await Promise.all(users.map(u => notifyClient(u._id, { type, title, body: msgBody, link })));
            res.json({ success: true, data: { sent: users.length } });
          }
        } catch (err) { next(err); }
      }
    );
    // ══════════════════════════════════════════════════════════════════════

    // ══════════════════════════════════════════════════════════════════════
    // CLIENT GALLERY — before/after photos
    // ══════════════════════════════════════════════════════════════════════

    // POST /client-gallery — client submits before/after photo
    app.post('/client-gallery', authenticateToken,
      body('afterImageUrl').isURL(),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());

          const { afterImageUrl, beforeImageUrl, appointmentId, caption, serviceNames, rating } = req.body;
          const userId = new ObjectId(req.user.userId);

          // Verify appointment belongs to this user
          let appt = null;
          if (appointmentId?.match(/^[a-f\d]{24}$/i)) {
            appt = await db.collection('APPOINTMENTS').findOne({ _id:new ObjectId(appointmentId), userId, status:'completed' });
          }

          const user = await db.collection('USERS').findOne({ _id: userId }, { projection:{ firstName:1, lastName:1 } });

          const post = {
            userId,
            appointmentId:  appt ? new ObjectId(appointmentId) : null,
            afterImageUrl,
            beforeImageUrl: beforeImageUrl || null,
            caption:        sanitiseText(caption || '', 200),
            serviceNames:   Array.isArray(serviceNames) ? serviceNames : [],
            rating:         rating ? Math.min(5, Math.max(1, parseInt(rating))) : null,
            clientName:     `${user?.firstName || ''} ${user?.lastName || ''}`.trim() || 'Anonymous',
            status:         'pending',  // admin must approve before it shows publicly
            likes:          0,
            createdAt:      new Date(),
          };

          const result = await db.collection('CLIENT_GALLERY').insertOne(post);

          // Notify admin
          await db.collection('NOTIFICATIONS').insertOne({
            message:   `New before/after photo submitted by ${post.clientName} — pending approval`,
            target:    'staff', read: false, createdAt: new Date(),
          });

          res.status(201).json({ success:true, data:{ _id:result.insertedId, status:'pending' } });
        } catch (err) { next(err); }
      }
    );

    // GET /client-gallery/public — approved posts for public display
    app.get('/client-gallery/public', async (req, res, next) => {
      try {
        const page  = Math.max(1, parseInt(req.query.page || '1'));
        const limit = Math.min(50, parseInt(req.query.limit || '12'));
        const posts = await db.collection('CLIENT_GALLERY')
          .find({ status:'approved' })
          .sort({ createdAt:-1 })
          .skip((page-1)*limit).limit(limit)
          .toArray();
        const total = await db.collection('CLIENT_GALLERY').countDocuments({ status:'approved' });
        res.json({ success:true, data:posts, total, page, pages:Math.ceil(total/limit) });
      } catch (err) { next(err); }
    });

    // GET /client-gallery/my — user's own submissions
    app.get('/client-gallery/my', authenticateToken, async (req, res, next) => {
      try {
        const posts = await db.collection('CLIENT_GALLERY')
          .find({ userId: new ObjectId(req.user.userId) })
          .sort({ createdAt:-1 }).limit(20).toArray();
        res.json({ success:true, data:posts });
      } catch (err) { next(err); }
    });

    // GET /client-gallery/admin — admin view all submissions
    app.get('/client-gallery/admin', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const { status } = req.query;
        const filter = status && status !== 'all' ? { status } : {};
        const posts  = await db.collection('CLIENT_GALLERY').find(filter).sort({ createdAt:-1 }).limit(100).toArray();
        res.json({ success:true, data:posts });
      } catch (err) { next(err); }
    });

    // PUT /client-gallery/:id/approve — admin approves/rejects
    app.put('/client-gallery/:id/approve', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const { status } = req.body; // 'approved' | 'rejected'
        if (!['approved','rejected'].includes(status)) return res.status(400).json({ success:false, error:'status must be approved or rejected' });
        await db.collection('CLIENT_GALLERY').updateOne({ _id:new ObjectId(req.params.id) }, { $set:{ status, reviewedAt:new Date() } });

        // If approved, also add to main GALLERY for homepage display
        if (status === 'approved') {
          const post = await db.collection('CLIENT_GALLERY').findOne({ _id:new ObjectId(req.params.id) });
          if (post) {
            await db.collection('GALLERY').insertOne({
              imageUrl:    post.afterImageUrl,
              clientName:  post.clientName,
              caption:     post.caption || post.serviceNames.join(', '),
              source:      'client_upload',
              refId:       post._id,
              createdAt:   new Date(),
            });
          }
        }
        res.json({ success:true });
      } catch (err) { next(err); }
    });

    // POST /client-gallery/:id/like — like a photo
    app.post('/client-gallery/:id/like', authenticateToken, async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        await db.collection('CLIENT_GALLERY').updateOne({ _id:new ObjectId(req.params.id) }, { $inc:{ likes:1 } });
        res.json({ success:true });
      } catch (err) { next(err); }
    });

    // DELETE /client-gallery/:id — owner or admin can delete
    app.delete('/client-gallery/:id', authenticateToken, async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const post = await db.collection('CLIENT_GALLERY').findOne({ _id:new ObjectId(req.params.id) });
        if (!post) return res.status(404).json({ success:false, error:'Post not found' });
        if (req.user.role !== 'admin' && String(post.userId) !== String(req.user.userId))
          return res.status(403).json({ success:false, error:'Not authorized' });
        await db.collection('CLIENT_GALLERY').deleteOne({ _id:new ObjectId(req.params.id) });
        res.json({ success:true });
      } catch (err) { next(err); }
    });
    // ══════════════════════════════════════════════════════════════════════

    // ══════════════════════════════════════════════════════════════════════
    // INVENTORY MANAGEMENT
    // ══════════════════════════════════════════════════════════════════════

    // GET /inventory — stock levels + restock alerts
    app.get('/inventory', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const products = await db.collection('PRODUCTS')
          .find({ isActive: true })
          .project({ name:1, stock:1, sku:1, brand:1, category:1, images:1, price:1 })
          .toArray();

        const LOW_THRESHOLD  = 5;
        const ZERO_THRESHOLD = 0;

        const withStatus = products.map(p => ({
          ...p,
          price: parseFloat(p.price?.toString() || 0),
          stockStatus: p.stock === 0 ? 'out' : p.stock <= LOW_THRESHOLD ? 'low' : 'ok',
        }));

        const stats = {
          total:    products.length,
          ok:       withStatus.filter(p => p.stockStatus === 'ok').length,
          low:      withStatus.filter(p => p.stockStatus === 'low').length,
          out:      withStatus.filter(p => p.stockStatus === 'out').length,
          totalValue: withStatus.reduce((sum, p) => sum + p.stock * p.price, 0),
        };

        res.json({ success:true, data: { products: withStatus, stats } });
      } catch (err) { next(err); }
    });

    // POST /inventory/restock — record a stock purchase
    app.post('/inventory/restock',
      authenticateToken, authorizeRole('admin'),
      body('productId').isMongoId(),
      body('quantity').isInt({ min:1 }),
      body('costPerUnit').isFloat({ min:0 }),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());

          const { productId, quantity, costPerUnit, supplier, notes, invoiceRef } = req.body;
          const prodId = new ObjectId(productId);

          const product = await db.collection('PRODUCTS').findOne({ _id: prodId });
          if (!product) return res.status(404).json({ success:false, error:'Product not found' });

          const prevStock = product.stock || 0;
          const newStock  = prevStock + parseInt(quantity);

          // Update product stock
          await db.collection('PRODUCTS').updateOne(
            { _id: prodId },
            { $inc: { stock: parseInt(quantity) }, $set: { updatedAt: new Date() } }
          );

          // Record restock order
          const order = {
            productId:   prodId,
            productName: product.name,
            type:        'restock',
            quantity:    parseInt(quantity),
            costPerUnit: parseFloat(costPerUnit),
            totalCost:   parseInt(quantity) * parseFloat(costPerUnit),
            prevStock,
            newStock,
            supplier:    supplier || null,
            notes:       sanitiseText(notes || '', 300),
            invoiceRef:  invoiceRef || null,
            recordedBy:  new ObjectId(req.user.userId),
            createdAt:   new Date(),
          };

          await db.collection('INVENTORY_ORDERS').insertOne(order);
          logger.info(`[INVENTORY] Restocked ${product.name}: +${quantity} units`);

          res.status(201).json({ success:true, data: { ...order, newStock } });
        } catch (err) { next(err); }
      }
    );

    // GET /inventory/history?productId=xxx — restock history for a product
    app.get('/inventory/history', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const filter = {};
        if (req.query.productId?.match(/^[a-f\d]{24}$/i)) filter.productId = new ObjectId(req.query.productId);
        const page  = Math.max(1, parseInt(req.query.page || '1'));
        const limit = Math.min(100, parseInt(req.query.limit || '50'));

        const [orders, total] = await Promise.all([
          db.collection('INVENTORY_ORDERS').find(filter).sort({ createdAt:-1 }).skip((page-1)*limit).limit(limit).toArray(),
          db.collection('INVENTORY_ORDERS').countDocuments(filter),
        ]);
        res.json({ success:true, data: orders, total, page, pages: Math.ceil(total/limit) });
      } catch (err) { next(err); }
    });

    // CRUD: Suppliers
    app.get('/suppliers',    authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try { const s = await db.collection('SUPPLIERS').find({}).sort({ name:1 }).toArray(); res.json({ success:true, data:s }); } catch (e) { next(e); }
    });
    app.post('/suppliers', authenticateToken, authorizeRole('admin'),
      body('name').isString().notEmpty(),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const { name, email, phone, address, notes } = req.body;
          const result = await db.collection('SUPPLIERS').insertOne({ name: sanitiseText(name,100), email: email||null, phone: phone||null, address: sanitiseText(address||'',200), notes: sanitiseText(notes||'',300), isActive:true, createdAt:new Date(), updatedAt:new Date() });
          res.status(201).json({ success:true, data:{ _id:result.insertedId } });
        } catch (err) { next(err); }
      }
    );
    app.delete('/suppliers/:id', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        await db.collection('SUPPLIERS').deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ success:true });
      } catch (err) { next(err); }
    });
    // ══════════════════════════════════════════════════════════════════════

    // ══════════════════════════════════════════════════════════════════════
    // SMS NOTIFICATIONS
    // Uses Africa's Talking API if AT_API_KEY + AT_USERNAME are set.
    // Falls back to logging a wa.me link so admin can send manually.
    // ══════════════════════════════════════════════════════════════════════

    async function sendSMS(phone, message) {
      const cleaned = phone.replace(/\D/g, '');
      // Normalise to E.164 South African format
      const e164 = cleaned.startsWith('27') ? `+${cleaned}`
        : cleaned.startsWith('0') ? `+27${cleaned.slice(1)}`
        : `+${cleaned}`;

      if (process.env.AT_API_KEY && process.env.AT_USERNAME) {
        try {
          const params = new URLSearchParams({
            username: process.env.AT_USERNAME,
            to:       e164,
            message,
            from:     process.env.AT_SENDER_ID || 'NXLBeauty',
          });
          const resp = await fetchFn('https://api.africastalking.com/version1/messaging', {
            method:  'POST',
            headers: {
              'apiKey':       process.env.AT_API_KEY,
              'Content-Type': 'application/x-www-form-urlencoded',
              'Accept':       'application/json',
            },
            body: params.toString(),
          });
          const data = await resp.json();
          const status = data?.SMSMessageData?.Recipients?.[0]?.status;
          logger.info(`[SMS] Sent to ${e164}: ${status}`);
          return { sent: true, status, provider: 'africastalking' };
        } catch (smsErr) {
          logger.error(`[SMS] Africa's Talking failed: ${smsErr.message}`);
        }
      }

      // Fallback — log WhatsApp link
      const waText = encodeURIComponent(message);
      const waUrl  = `https://wa.me/${e164.replace('+','')}?text=${waText}`;
      logger.info(`[SMS FALLBACK] No AT credentials — wa.me link: ${waUrl}`);
      return { sent: false, waUrl, provider: 'fallback' };
    }

    // POST /sms/send — admin manually sends SMS to a client
    app.post('/sms/send', authenticateToken, authorizeRole('admin'),
      body('phone').isString().notEmpty(),
      body('message').isString().notEmpty().isLength({ max: 160 }),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const result = await sendSMS(req.body.phone, req.body.message);
          res.json({ success: true, data: result });
        } catch (err) { next(err); }
      }
    );

    // POST /sms/bulk — send SMS to multiple clients (e.g. promo blast)
    app.post('/sms/bulk', authenticateToken, authorizeRole('admin'),
      body('phones').isArray({ min:1, max:50 }),
      body('message').isString().notEmpty().isLength({ max: 160 }),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const results = await Promise.allSettled(
            req.body.phones.map(phone => sendSMS(phone, req.body.message))
          );
          const sent   = results.filter(r => r.status === 'fulfilled' && r.value?.sent).length;
          const failed = results.length - sent;
          res.json({ success: true, data: { sent, failed, total: results.length } });
        } catch (err) { next(err); }
      }
    );
    // ══════════════════════════════════════════════════════════════════════

    // ══════════════════════════════════════════════════════════════════════
    // STAFF SCHEDULE ROUTES
    // ══════════════════════════════════════════════════════════════════════

    // GET /employees/:id/schedule?start=YYYY-MM-DD&end=YYYY-MM-DD
    // Returns appointments + blocked slots for a staff member in a date range
    app.get('/employees/:id/schedule', authenticateToken, async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i))
          return res.status(400).json({ success:false, error:'Invalid employee ID' });

        const { start, end } = req.query;
        if (!start || !end) return res.status(400).json({ success:false, error:'start and end dates required' });

        const empId = new ObjectId(req.params.id);
        const employee = await db.collection('EMPLOYEES').findOne({ _id: empId });
        if (!employee) return res.status(404).json({ success:false, error:'Employee not found' });

        const [appointments, blockedSlots] = await Promise.all([
          db.collection('APPOINTMENTS').find({
            employeeId: empId,
            date: { $gte: start, $lte: end },
            status: { $nin: ['cancelled'] },
          }).toArray(),
          db.collection('AVAILABILITY').find({
            employeeId: { $in: [req.params.id, 'ALL'] },
            date: { $gte: start, $lte: end },
          }).toArray(),
        ]);

        // Enrich appointments with client + service names
        const userIds  = [...new Set(appointments.map(a => a.userId))];
        const svcIds   = [...new Set(appointments.flatMap(a => a.serviceIds || []))];
        const [users, services] = await Promise.all([
          db.collection('USERS').find({ _id: { $in: userIds } }).project({ firstName:1, lastName:1, phone:1 }).toArray(),
          db.collection('SERVICES').find({ _id: { $in: svcIds } }).project({ name:1, durationMinutes:1 }).toArray(),
        ]);
        const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
        const svcMap  = Object.fromEntries(services.map(s => [s._id.toString(), s]));

        const enriched = appointments.map(a => ({
          ...a,
          clientName: userMap[a.userId?.toString()] ? `${userMap[a.userId.toString()].firstName} ${userMap[a.userId.toString()].lastName}` : a.userName || '—',
          clientPhone: userMap[a.userId?.toString()]?.phone || '',
          serviceNames: (a.serviceIds || []).map(id => svcMap[id?.toString()]?.name).filter(Boolean),
          durationMinutes: (a.serviceIds || []).reduce((sum, id) => sum + (svcMap[id?.toString()]?.durationMinutes || 30), 0),
        }));

        res.json({ success:true, data: { employee, appointments: enriched, blockedSlots } });
      } catch (err) { next(err); }
    });

    // PUT /employees/:id/working-hours — set weekly working hours
    app.put('/employees/:id/working-hours', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i))
          return res.status(400).json({ success:false, error:'Invalid employee ID' });

        const { workingHours } = req.body;
        // workingHours = { mon:{start:'09:00',end:'17:00',active:true}, tue:{...}, ... }
        if (!workingHours) return res.status(400).json({ success:false, error:'workingHours required' });

        await db.collection('EMPLOYEES').updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { workingHours, updatedAt: new Date() } }
        );
        const updated = await db.collection('EMPLOYEES').findOne({ _id: new ObjectId(req.params.id) });
        res.json({ success:true, data: updated });
      } catch (err) { next(err); }
    });

    // GET /staff/overview?date=YYYY-MM-DD — all staff schedule for a single day
    app.get('/staff/overview', authenticateToken, async (req, res, next) => {
      try {
        const date = req.query.date || new Date().toISOString().slice(0,10);
        const [allStaff, appointments, blocked] = await Promise.all([
          db.collection('EMPLOYEES').find({ isActive: true }).toArray(),
          db.collection('APPOINTMENTS').find({ date, status: { $nin: ['cancelled'] } }).toArray(),
          db.collection('AVAILABILITY').find({ date }).toArray(),
        ]);

        const svcIds  = [...new Set(appointments.flatMap(a => a.serviceIds || []))];
        const userIds = [...new Set(appointments.map(a => a.userId))];
        const [services, users] = await Promise.all([
          db.collection('SERVICES').find({ _id: { $in: svcIds } }).project({ name:1, durationMinutes:1 }).toArray(),
          db.collection('USERS').find({ _id: { $in: userIds } }).project({ firstName:1, lastName:1 }).toArray(),
        ]);
        const svcMap  = Object.fromEntries(services.map(s => [s._id.toString(), s]));
        const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));

        const staffSchedule = allStaff.map(emp => ({
          ...emp,
          appointments: appointments
            .filter(a => String(a.employeeId) === String(emp._id))
            .map(a => ({
              ...a,
              clientName:   userMap[a.userId?.toString()] ? `${userMap[a.userId.toString()].firstName} ${userMap[a.userId.toString()].lastName}` : a.userName || '—',
              serviceNames: (a.serviceIds || []).map(id => svcMap[id?.toString()]?.name).filter(Boolean),
              durationMinutes: (a.serviceIds || []).reduce((sum, id) => sum + (svcMap[id?.toString()]?.durationMinutes || 30), 0),
            })),
          blockedSlots: blocked.filter(b => String(b.employeeId) === String(emp._id) || b.employeeId === 'ALL').map(b => b.time),
        }));

        res.json({ success:true, data: { date, staff: staffSchedule } });
      } catch (err) { next(err); }
    });
    // ══════════════════════════════════════════════════════════════════════

    // ── POST /discount-codes/validate

    // ── GET /services/public ───────────────────────────────────────────────
    app.get('/services/public', async (req, res, next) => {
      try {
        const svcs = await db.collection('SERVICES').find({ isActive: true }).toArray();
        res.json({ success: true, data: svcs.map(s => ({ ...s, price: parseFloat(s.price?.toString() || 0) })) });
      } catch (err) { next(err); }
    });

    // ── GET /employees/public ──────────────────────────────────────────────
    app.get('/employees/public', async (req, res, next) => {
      try {
        const staff = await db.collection('EMPLOYEES').find({ isActive: true }).project({ name:1, role:1, bio:1 }).toArray();
        res.json({ success: true, data: staff });
      } catch (err) { next(err); }
    });

    // ── GET /availability/slots ────────────────────────────────────────────
    app.get('/availability/slots', async (req, res, next) => {
      try {
        const { date, employeeId } = req.query;
        if (!date || !employeeId) return res.status(400).json({ success: false, error: 'date and employeeId are required' });
        const empQuery = employeeId === 'any' ? {} : { employeeId: new ObjectId(employeeId) };
        const blocked  = await db.collection('AVAILABILITY').find({ date, ...empQuery }).project({ time:1 }).toArray();
        const booked   = await db.collection('APPOINTMENTS').find({
          date, ...empQuery, status: { $in: ['booked', 'pending'] },
        }).project({ time:1 }).toArray();
        const taken = [...new Set([...blocked.map(b => b.time), ...booked.map(b => b.time)])];
        res.json({ success: true, data: taken });
      } catch (err) { next(err); }
    });

    // ── POST /appointments/guest — book without login ──────────────────────
    app.post('/appointments/guest',
      body('serviceIds').isArray({ min: 1 }),
      body('date').matches(/^\d{4}-\d{2}-\d{2}$/),
      body('time').matches(/^\d{2}:\d{2}$/),
      body('firstName').isString().notEmpty().trim(),
      body('lastName').isString().notEmpty().trim(),
      body('email').isEmail().normalizeEmail(),
      body('phone').isString().notEmpty(),
      async (req, res, next) => {
        const errs = validationResult(req);
        if (!errs.isEmpty()) return sendValidationError(res, errs.array());
        try {
          const { serviceIds, employeeId, date, time, firstName, lastName, email, phone, notes } = req.body;

          // Resolve userId — logged in or guest
          let userId;
          if (req.headers.authorization) {
            try { const tok = req.headers.authorization.split(' ')[1]; const dec = jwt.verify(tok, process.env.JWT_SECRET); userId = new ObjectId(dec.userId); } catch {}
          }
          if (!userId) {
            let existing = await db.collection('USERS').findOne({ email: email.toLowerCase() });
            if (!existing) {
              const bcrypt = require('bcryptjs');
              const r2 = await db.collection('USERS').insertOne({ email: email.toLowerCase(), password: await bcrypt.hash(Math.random().toString(36), 10), firstName: sanitiseText(firstName, 50), lastName: sanitiseText(lastName, 50), phone: sanitiseText(phone, 20), role: 'user', isActive: true, isGuest: true, createdAt: new Date(), updatedAt: new Date() });
              userId = r2.insertedId;
            } else { userId = existing._id; }
          }

          const svcIds = serviceIds.map(id => new ObjectId(id));
          const svcs   = await db.collection('SERVICES').find({ _id: { $in: svcIds }, isActive: true }).toArray();
          if (svcs.length !== svcIds.length) return res.status(400).json({ success: false, error: 'One or more services not found.' });

          let empId;
          if (!employeeId || employeeId === 'any') {
            const avail = await db.collection('EMPLOYEES').findOne({ isActive: true });
            empId = avail?._id;
          } else { empId = new ObjectId(employeeId); }
          if (!empId) return res.status(400).json({ success: false, error: 'No staff available.' });

          const totalPrice    = svcs.reduce((s, sv) => s + parseFloat(sv.price?.toString() || 0), 0);
          const depositAmount = Number(process.env.DEPOSIT_AMOUNT || 100);
          const result = await db.collection('APPOINTMENTS').insertOne({
            userId, employeeId: empId, serviceIds: svcIds, date, time,
            status: 'pending', paymentStatus: 'unpaid',
            notes: sanitiseText(notes || '', 500),
            totalPrice: Decimal128.fromString(totalPrice.toFixed(2)),
            depositAmount: Decimal128.fromString(depositAmount.toFixed(2)),
            userName: `${sanitiseText(firstName, 50)} ${sanitiseText(lastName, 50)}`,
            createdAt: new Date(), updatedAt: new Date(),
          });

          if (process.env.RESEND_API_KEY) {
            try {
              const resend = new Resend(process.env.RESEND_API_KEY);
              await resend.emails.send({ from:'NXL Beauty Bar <onboarding@resend.dev>', to: email, subject:`Booking Request — NXL Beauty Bar`, html:`<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;"><h2 style="color:#3d1f15;font-family:Georgia,serif;">NXL Beauty Bar</h2><h3 style="color:#6b3528;">Booking Received! 📅</h3><p>Hi ${sanitiseText(firstName, 50)},</p><p>Your booking request for <strong>${date}</strong> at <strong>${time}</strong> has been received.</p><p>Services: <strong>${svcs.map(s => s.name).join(', ')}</strong></p><p style="color:#9e7060;font-size:0.82rem;">We'll confirm shortly. A deposit of R${depositAmount} is required.</p></div>` });
            } catch (em) { logger.error(`[GUEST BOOKING EMAIL] ${em.message}`); }
          }
          await db.collection('NOTIFICATIONS').insertOne({ message: `New booking from ${firstName} ${lastName} — ${date} at ${time}`, target: 'staff', read: false, createdAt: new Date() });
          res.status(201).json({ success: true, data: { _id: result.insertedId, date, time } });
        } catch (err) {
          if (err.code === 11000) return res.status(409).json({ success: false, error: 'That time slot is no longer available.' });
          next(err);
        }
      }
    );
    // ──────────────────────────────────────────────────────────────────────
    app.post('/discount-codes/validate', authenticateToken, discountLimiter, async (req, res, next) => {
      try {
        const { code, subtotal, context } = req.body; // context: 'shop' | 'booking'
        if (!code) return res.status(400).json({ success:false, error:'Code is required' });
        const found = await db.collection('DISCOUNT_CODES').findOne({
          code: code.toUpperCase().trim(), isActive: true,
          $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
        });
        if (!found) return res.status(404).json({ success:false, error:'Invalid or expired discount code.' });
        if (found.usageLimit && found.usedCount >= found.usageLimit) return res.status(400).json({ success:false, error:'This code has already been used.' });
        if (found.minOrderAmount && subtotal < found.minOrderAmount) return res.status(400).json({ success:false, error:`This code requires a minimum of R${found.minOrderAmount.toFixed(2)}.` });

        // If code is tied to a specific user, enforce it
        if (found.forUserId && String(found.forUserId) !== String(req.user.userId)) {
          return res.status(403).json({ success:false, error:'This code is not valid for your account.' });
        }

        const discountAmount = found.type === 'percentage'
          ? Math.round((subtotal * found.value / 100) * 100) / 100
          : Math.min(found.value, subtotal);
        res.json({ success:true, data:{ code:found.code, type:found.type, value:found.value, description:found.description, discountAmount } });
      } catch (err) { next(err); }
    });

    // POST /discount-codes/validate-booking — validate a code against a booking's balance
    app.post('/discount-codes/validate-booking', authenticateToken, discountLimiter, async (req, res, next) => {
      try {
        const { code, appointmentId } = req.body;
        if (!code) return res.status(400).json({ success:false, error:'Code is required' });
        if (!appointmentId?.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid appointment ID' });

        const appt = await db.collection('APPOINTMENTS').findOne({ _id: new ObjectId(appointmentId), userId: new ObjectId(req.user.userId) });
        if (!appt) return res.status(404).json({ success:false, error:'Appointment not found' });

        const found = await db.collection('DISCOUNT_CODES').findOne({
          code: code.toUpperCase().trim(), isActive: true,
          $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
        });
        if (!found) return res.status(404).json({ success:false, error:'Invalid or expired discount code.' });
        if (found.usageLimit && found.usedCount >= found.usageLimit) return res.status(400).json({ success:false, error:'This code has already been used.' });
        if (found.forUserId && String(found.forUserId) !== String(req.user.userId)) {
          return res.status(403).json({ success:false, error:'This code is not valid for your account.' });
        }

        const depositAmount = parseFloat(process.env.DEPOSIT_AMOUNT || 100);
        const totalPrice    = parseFloat(appt.totalPrice?.toString() || 0);
        const balance       = Math.max(0, totalPrice - depositAmount);

        const discountAmount = found.type === 'percentage'
          ? parseFloat((balance * found.value / 100).toFixed(2))
          : Math.min(found.value, balance);

        res.json({
          success: true,
          data: {
            code:           found.code,
            type:           found.type,
            value:          found.value,
            description:    found.description,
            discountAmount,
            balance,
            newBalance:     Math.max(0, balance - discountAmount),
          },
        });
      } catch (err) { next(err); }
    });

    // GET /discount-codes — admin: list all
    app.get('/discount-codes', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const codes = await db.collection('DISCOUNT_CODES').find({}).sort({ createdAt:-1 }).toArray();
        res.json({ success:true, data:codes });
      } catch (err) { next(err); }
    });

    // POST /discount-codes — admin: create
    app.post('/discount-codes', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        const { code, type, value, minOrderAmount, usageLimit, expiresAt, description } = req.body;
        if (!code || !type || value == null) return res.status(400).json({ success:false, error:'code, type and value are required' });
        if (!['percentage','flat'].includes(type)) return res.status(400).json({ success:false, error:'type must be percentage or flat' });
        if (type === 'percentage' && (value <= 0 || value > 100)) return res.status(400).json({ success:false, error:'Percentage must be between 1 and 100' });
        const doc = {
          code:           code.toUpperCase().trim(),
          type,
          value:          Number(value),
          minOrderAmount: minOrderAmount ? Number(minOrderAmount) : null,
          usageLimit:     usageLimit ? parseInt(usageLimit) : null,
          usedCount:      0,
          expiresAt:      expiresAt ? new Date(expiresAt) : null,
          isActive:       true,
          description:    description || '',
          createdAt:      new Date(),
        };
        try {
          const result = await db.collection('DISCOUNT_CODES').insertOne(doc);
          res.status(201).json({ success:true, data:{ _id:result.insertedId, ...doc } });
        } catch (e) {
          if (e.code === 11000) return res.status(409).json({ success:false, error:'A code with that name already exists.' });
          throw e;
        }
      } catch (err) { next(err); }
    });

    // PUT /discount-codes/:id — admin: update (toggle active, extend expiry etc)
    app.put('/discount-codes/:id', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const update = { updatedAt: new Date() };
        const allowed = ['type','value','minOrderAmount','usageLimit','expiresAt','isActive','description'];
        for (const key of allowed) {
          if (req.body[key] !== undefined) {
            update[key] = key === 'expiresAt' && req.body[key] ? new Date(req.body[key]) : req.body[key];
          }
        }
        const result = await db.collection('DISCOUNT_CODES').findOneAndUpdate({ _id:new ObjectId(req.params.id) }, { $set:update }, { returnDocument:'after' });
        if (!result) return res.status(404).json({ success:false, error:'Code not found' });
        res.json({ success:true, data:result });
      } catch (err) { next(err); }
    });

    // DELETE /discount-codes/:id — admin: delete
    app.delete('/discount-codes/:id', authenticateToken, authorizeRole('admin'), async (req, res, next) => {
      try {
        if (!req.params.id.match(/^[a-f\d]{24}$/i)) return res.status(400).json({ success:false, error:'Invalid ID' });
        const result = await db.collection('DISCOUNT_CODES').deleteOne({ _id:new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ success:false, error:'Code not found' });
        res.json({ success:true, message:'Deleted' });
      } catch (err) { next(err); }
    });

    // =====================
    // SWAGGER
    // =====================
    const swaggerDocument = {
      openapi:'3.0.0',
      info:{ title:'NXL Beauty Bar API', version:'2.0.0', description:'API for booking + ecommerce.' },
      components:{ securitySchemes:{ bearerAuth:{ type:'http', scheme:'bearer', bearerFormat:'JWT' } } },
      security:[{ bearerAuth:[] }],
      paths:{ '/appointments':{ get:{ summary:'Get appointments', security:[{ bearerAuth:[] }], responses:{ '200':{ description:'List of appointments' } } } } }
    };
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

    app.get('/', (req, res) => res.status(200).json({ status:'ok', env:process.env.NODE_ENV, version:'2.0.0', uptime:process.uptime() }));

    app.use((req, res) => { res.status(404).json({ success:false, error:`Route ${req.originalUrl} not found.` }); });

    app.use((err, req, res, next) => {
      if (err && err.message === 'Not allowed by CORS') return res.status(403).json({ success:false, error:'CORS blocked this origin' });
      if (res.headersSent) return next(err);
      logger.error(err.stack);
      if (err.name === 'UnauthorizedError') return res.status(401).json({ success:false, error:'Invalid token' });
      res.status(500).json({ success:false, error:'Internal server error' });
    });

    async function cleanupPendingAppointments() {
      try {
        const cutoff = new Date(Date.now() - 24*60*60*1000);
        const unpaid = await db.collection('APPOINTMENTS').find({ paymentStatus:'unpaid', createdAt:{ $lt:cutoff } }).toArray();
        if (unpaid.length > 0) {
          const ids = unpaid.map(a => a._id);
          const r1 = await db.collection('APPOINTMENTS').deleteMany({ _id:{ $in:ids } });
          const r2 = await db.collection('PAYMENTS').deleteMany({ appointmentId:{ $in:ids } });
          logger.info(`Auto-cleaned ${r1.deletedCount} unpaid appointments and ${r2.deletedCount} payment records`);
        }
      } catch (err) { logger.error('Cleanup job error:', err); }
    }

    setInterval(cleanupPendingAppointments, 6*60*60*1000);
    cleanupPendingAppointments();

    // ── 24-hour appointment reminder cron ─────────────────────────────────
    // Runs every hour. Finds all booked appointments happening tomorrow
    // that haven't had a reminder sent yet, sends a reminder email, then
    // marks them so they don't get emailed again.
    async function sendAppointmentReminders() {
      if (!process.env.RESEND_API_KEY) return;
      try {
        const now       = new Date();
        const tomorrow  = new Date(now);
        tomorrow.setDate(tomorrow.getDate() + 1);
        const tomorrowISO = `${tomorrow.getFullYear()}-${String(tomorrow.getMonth()+1).padStart(2,'0')}-${String(tomorrow.getDate()).padStart(2,'0')}`;

        const appointments = await db.collection('APPOINTMENTS').find({
          date:          tomorrowISO,
          status:        { $in: ['booked'] },
          paymentStatus: { $in: ['deposit_paid', 'paid'] },
          reminderSent:  { $ne: true },  // haven't sent yet
        }).toArray();

        if (!appointments.length) return;

        logger.info(`[REMINDER] Found ${appointments.length} appointment(s) to remind for ${tomorrowISO}`);

        const resend = new Resend(process.env.RESEND_API_KEY);
        const frontendUrl = (process.env.CORS_ORIGIN || 'https://nxlbeautybar.co.za').replace(/\/$/, '');
        const depositAmount = Number(process.env.DEPOSIT_AMOUNT || 100);

        for (const appt of appointments) {
          try {
            const clientUser = await db.collection('USERS').findOne(
              { _id: appt.userId },
              { projection: { email:1, firstName:1 } }
            );
            if (!clientUser?.email) continue;

            const services = await db.collection('SERVICES').find({ _id: { $in: appt.serviceIds || [] } }).project({ name:1, durationMinutes:1 }).toArray();
            const svcNames = services.map(s => s.name).join(', ') || 'Appointment';
            const totalDuration = services.reduce((sum, s) => sum + (s.durationMinutes || 0), 0);
            const formattedDate = new Date(appt.date + 'T00:00:00').toLocaleDateString('en-ZA', { weekday:'long', day:'numeric', month:'long', year:'numeric' });

            await resend.emails.send({
              from:    'NXL Beauty Bar <onboarding@resend.dev>',
              to:      clientUser.email,
              subject: `Reminder: Your appointment is tomorrow at ${appt.time} 💅`,
              html: `
                <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;">
                  <h2 style="font-family:Georgia,serif;color:#3d1f15;margin-bottom:0.25rem;">NXL Beauty Bar</h2>
                  <h3 style="color:#6b3528;margin-top:0;">See You Tomorrow! ✨</h3>
                  <p style="color:#555;line-height:1.65;">Hi ${clientUser.firstName},</p>
                  <p style="color:#555;line-height:1.65;">Just a friendly reminder that your appointment is <strong>tomorrow</strong>. We can't wait to see you!</p>
                  <table style="width:100%;border-collapse:collapse;margin:1.25rem 0;background:#fff;border-radius:10px;overflow:hidden;">
                    <tr style="border-bottom:1px solid #e0ccc4;">
                      <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;width:40%;">Service</td>
                      <td style="padding:0.75rem 1rem;color:#555;">${svcNames}</td>
                    </tr>
                    <tr style="border-bottom:1px solid #e0ccc4;">
                      <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;">Date</td>
                      <td style="padding:0.75rem 1rem;color:#555;">${formattedDate}</td>
                    </tr>
                    <tr style="border-bottom:1px solid #e0ccc4;">
                      <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;">Time</td>
                      <td style="padding:0.75rem 1rem;color:#555;font-weight:700;">${appt.time}</td>
                    </tr>
                    ${totalDuration > 0 ? `
                    <tr>
                      <td style="padding:0.75rem 1rem;font-weight:700;color:#3d1f15;">Duration</td>
                      <td style="padding:0.75rem 1rem;color:#555;">${totalDuration} minutes</td>
                    </tr>` : ''}
                  </table>
                  <div style="background:#fff8f3;border:1px solid #e0ccc4;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.25rem;">
                    <p style="margin:0;font-size:0.82rem;font-weight:700;color:#6b3528;">📍 Getting here</p>
                    <p style="margin:0.3rem 0 0;font-size:0.8rem;color:#9e7060;">1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                    <p style="margin:0.2rem 0 0;font-size:0.8rem;color:#9e7060;">📞 068 511 3394</p>
                    <p style="margin:0.4rem 0 0;"><a href="https://www.google.com/maps/search/?api=1&query=1948+Mahalefele+Rd+Dube+Soweto" style="color:#a0502e;font-size:0.8rem;">Get Directions →</a></p>
                  </div>
                  <div style="background:#fff3f3;border:1px solid #fca5a5;border-radius:10px;padding:0.875rem 1.25rem;margin-bottom:1.25rem;">
                    <p style="margin:0;font-size:0.82rem;font-weight:700;color:#c53030;">⏰ Important reminders</p>
                    <ul style="margin:0.4rem 0 0;padding-left:1.25rem;font-size:0.8rem;color:#9e7060;line-height:1.75;">
                      <li>Please arrive on time — a R50 late fee applies per 15 minutes</li>
                      <li>Arriving 30+ minutes late may result in cancellation</li>
                      <li>Need to cancel? Please notify us at least 48 hours in advance</li>
                    </ul>
                  </div>
                  <p style="color:#9e7060;font-size:0.8rem;line-height:1.65;">Need to reschedule? <a href="https://wa.me/27685113394" style="color:#a0502e;">WhatsApp us</a> as soon as possible.</p>
                  <hr style="border:none;border-top:1px solid #e0ccc4;margin:1.5rem 0;"/>
                  <p style="color:#b08070;font-size:0.7rem;text-align:center;margin:0;">NXL Beauty Bar &middot; 1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                </div>
              `,
            });

            // Mark reminder as sent so it doesn't fire again
            await db.collection('APPOINTMENTS').updateOne(
              { _id: appt._id },
              { $set: { reminderSent: true, reminderSentAt: new Date() } }
            );

            logger.info(`[REMINDER] Sent to ${clientUser.email} for appointment ${appt._id}`);

            // ── SMS reminder ──────────────────────────────────────────────
            if (clientUser.phone) {
              try {
                await sendSMS(clientUser.phone,
                  `NXL Beauty Bar reminder: You have an appointment tomorrow ${tomorrowISO} at ${appt.time}. 📍 1948 Mahalefele Rd, Dube, Soweto. Reply STOP to unsubscribe.`
                );
              } catch (smsErr) { logger.error(`[SMS REMINDER] ${smsErr.message}`); }
            }
            // ─────────────────────────────────────────────────────────────

            // ── WhatsApp reminder (via wa.me deep link stored as notification) ──
            // If the user has a phone number, log a WhatsApp-ready notification
            // so admin can see & tap to send. Full automation requires Meta Business API.
            if (clientUser.phone) {
              const waText = encodeURIComponent(
                `Hi ${clientUser.firstName}! 👋 This is a reminder from NXL Beauty Bar. You have an appointment tomorrow, ${tomorrowISO} at ${appt.time}. ` +
                `📍 1948 Mahalefele Rd, Dube, Soweto. Please arrive 5 mins early. See you soon! 💅`
              );
              const waUrl = `https://wa.me/${clientUser.phone.replace(/\D/g, '')}?text=${waText}`;
              await db.collection('NOTIFICATIONS').insertOne({
                type:    'whatsapp_reminder',
                message: `WhatsApp reminder ready for ${clientUser.firstName} ${clientUser.lastName} (${appt.date} ${appt.time})`,
                waUrl,
                phone:   clientUser.phone,
                read:    false,
                target:  'staff',
                createdAt: new Date(),
              });
            }
            // ──────────────────────────────────────────────────────────────────

          } catch (apptErr) {
            logger.error(`[REMINDER] Failed for appointment ${appt._id}: ${apptErr.message}`);
          }
        }
      } catch (err) {
        logger.error(`[REMINDER] Cron error: ${err.message}`);
      }
    }

    // ── Subscription renewal cron — runs daily ─────────────────────────────
    async function processSubscriptionRenewals() {
      try {
        const now = new Date();
        const due = await db.collection('SUBSCRIPTIONS').find({
          status:      'active',
          autoRenew:   true,
          renewalDate: { $lte: now },
        }).toArray();

        for (const sub of due) {
          try {
            const planPrice = parseFloat(sub.planPrice?.toString() || 0);
            // Reset booking credits and set next renewal
            const nextRenewal = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
            await db.collection('SUBSCRIPTIONS').updateOne(
              { _id: sub._id },
              {
                $set:  { bookingsRemaining: sub.bookingsPerMonth, renewalDate: nextRenewal, updatedAt: now },
                $push: { payments: { amount: planPrice, date: now, type: 'renewal' } },
              }
            );

            // Notify client
            await notifyClient(sub.userId, {
              type:  'order_confirmed',
              title: `${sub.planName} Renewed 🔄`,
              body:  `Your subscription has renewed. You have ${sub.bookingsPerMonth} fresh bookings this month!`,
              link:  '/profile',
            });

            // Award loyalty points for renewal
            try { await awardPoints(sub.userId, 50, `Subscription renewal — ${sub.planName}`); } catch {}

            logger.info(`[SUB RENEWAL] Renewed subscription ${sub._id} for user ${sub.userId}`);
          } catch (subErr) {
            logger.error(`[SUB RENEWAL] Failed for sub ${sub._id}: ${subErr.message}`);
          }
        }

        if (due.length > 0) logger.info(`[SUB RENEWAL] Processed ${due.length} subscription renewal(s)`);
      } catch (err) {
        logger.error(`[SUB RENEWAL] Cron error: ${err.message}`);
      }
    }

    // Run once on startup and daily
    processSubscriptionRenewals();
    setInterval(processSubscriptionRenewals, 24 * 60 * 60 * 1000);
    logger.info('[SUB RENEWAL] Subscription renewal cron scheduled (daily)');
    // ──────────────────────────────────────────────────────────────────────

    // ── Subscription renewal cron END
    // Run once on startup then every hour
    sendAppointmentReminders();
    setInterval(sendAppointmentReminders, 60 * 60 * 1000);
    logger.info('[REMINDER] 24-hour reminder cron scheduled (hourly)');
    // ─────────────────────────────────────────────────────────────────────

    if (process.env.NODE_ENV === 'production' && process.env.BACKEND_URL) {
      setInterval(() => {
        fetchFn(`${process.env.BACKEND_URL}/`).then(() => logger.info('Keep-alive ping sent')).catch(err => logger.warn('Keep-alive ping failed:', err.message));
      }, 4*60*1000);
      logger.info('Keep-alive ping scheduled every 4 minutes');
    }

    app.listen(port, () => { console.log(`Server is running on port: ${port}`); });

  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();

// ═══════════════════════════════════════════════════════════════════════
// SMS HELPER — uses Africa's Talking or falls back to WhatsApp link log
// Set env vars: AT_API_KEY, AT_USERNAME (Africa's Talking sandbox/prod)
// Without them, SMS notifications are logged and a wa.me link is created
// ═══════════════════════════════════════════════════════════════════════
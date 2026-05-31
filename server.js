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

  await db.createCollection('SERVICES', { validator: { $jsonSchema: { bsonType:'object', required:['name','durationMinutes','price','isActive','createdAt','updatedAt'], properties: { name:{bsonType:'string',minLength:1}, durationMinutes:{bsonType:'int',minimum:15}, price:{bsonType:'decimal',minimum:0}, isActive:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
  try { await db.collection('SERVICES').dropIndex('name_1'); } catch(e) {}
  await db.collection('SERVICES').createIndex({ name:1 }, { unique:true, name:'service_name_unique_idx' });

  await db.createCollection('EMPLOYEES', { validator: { $jsonSchema: { bsonType:'object', required:['name','servicesOffered','isActive','createdAt','updatedAt'], properties: { name:{bsonType:'string',minLength:1}, email:{bsonType:['string','null'],pattern:'^\\S+@\\S+\\.\\S+$'}, servicesOffered:{bsonType:'array',minItems:1,items:{bsonType:'objectId'}}, isActive:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'strict' }).catch(()=>{});
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

  await db.createCollection('PRODUCTS', { validator: { $jsonSchema: { bsonType:'object', required:['name','price','category','stock','isActive','createdAt','updatedAt'], properties: { name:{bsonType:'string',minLength:1}, description:{bsonType:'string'}, price:{bsonType:'decimal',minimum:0}, comparePrice:{bsonType:['decimal','null']}, category:{bsonType:'string',enum:['nails','hair','skincare','accessories','professional','other']}, images:{bsonType:'array',items:{bsonType:'string'}}, stock:{bsonType:'int',minimum:0}, sku:{bsonType:'string'}, brand:{bsonType:'string'}, tags:{bsonType:'array',items:{bsonType:'string'}}, isActive:{bsonType:'bool'}, isFeatured:{bsonType:'bool'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
  await db.collection('PRODUCTS').createIndex({ name:'text',description:'text',brand:'text',tags:'text' });
  await db.collection('PRODUCTS').createIndex({ category:1 });
  await db.collection('PRODUCTS').createIndex({ isActive:1,isFeatured:-1,createdAt:-1 });

  await db.createCollection('ORDERS', { validator: { $jsonSchema: { bsonType:'object', required:['userId','items','totalAmount','status','paymentStatus','shippingAddress','createdAt','updatedAt'], properties: { userId:{bsonType:'objectId'}, items:{bsonType:'array',minItems:1}, subtotal:{bsonType:'decimal',minimum:0}, shippingFee:{bsonType:'decimal',minimum:0}, totalAmount:{bsonType:'decimal',minimum:0}, status:{bsonType:'string',enum:['pending','confirmed','processing','shipped','delivered','cancelled','refunded']}, paymentStatus:{bsonType:'string',enum:['unpaid','paid','refunded']}, paymentMethod:{bsonType:'string',enum:['yoco','cash','eft']}, yocoCheckoutId:{bsonType:'string'}, shippingAddress:{bsonType:'object'}, trackingNumber:{bsonType:'string'}, notes:{bsonType:'string'}, createdAt:{bsonType:'date'}, updatedAt:{bsonType:'date'} } } }, validationLevel:'moderate' }).catch(()=>{});
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
            if (clientUser) req.body.userName = `${clientUser.firstName} ${clientUser.lastName}`;
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
          let docs = await db.collection(collectionName).find({}).limit(500).toArray();
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
            docs = docs.map(doc => ({ ...doc, userName: userMap[doc.userId.toString()]?.firstName + ' ' + userMap[doc.userId.toString()]?.lastName, user:userMap[doc.userId.toString()], employee:empMap[doc.employeeId.toString()], services:doc.serviceIds.map(id => svcMap[id.toString()]).filter(Boolean), totalDuration:doc.totalDuration || doc.serviceIds.reduce((sum, id) => { const svc = svcMap[id.toString()]; return sum + (svc?.durationMinutes || 0); }, 0) }));
          }
          res.status(200).json({ success:true, data:docs });
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
        const { appointmentId } = req.body;
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
        logger.info('Yoco: creating checkout session', { appointmentId, amountInCents });
        const apptSnapshot = { appointmentId, date:appt.date, time:appt.time, userId:String(appt.userId), employeeId:String(appt.employeeId), serviceIds:(appt.serviceIds||[]).map(String), totalPrice:String(appt.totalPrice), userName:appt.userName||'' };
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
            { $set:{ appointmentId:apptId, type:'deposit', amount:Decimal128.fromString(depositAmount.toFixed(2)), method:'online', status:'pending', yocoCheckoutId:yocoData.id, updatedAt:new Date(), apptSnapshot:{ date:appt.date, time:appt.time, userId:appt.userId, employeeId:appt.employeeId, serviceIds:appt.serviceIds, totalPrice:appt.totalPrice, userName:appt.userName||'' } }, $setOnInsert:{ createdAt:new Date() } },
            { upsert:true }
          );
        } catch (payErr) { logger.error('Yoco: FAILED to save pending payment record', { appointmentId, error:payErr.message }); }
        return res.json({ success:true, checkoutUrl:yocoData.redirectUrl, checkoutId:yocoData.id });
      } catch (err) { logger.error('Yoco payment init error:', err); next(err); }
    });

    app.post('/payments/verify', authenticateToken, async (req, res, next) => {
      try {
        const { appointmentId } = req.body;
        if (!appointmentId) return res.status(400).json({ success:false, error:'appointmentId is required' });
        let apptId;
        try { apptId = new ObjectId(appointmentId); } catch { return res.status(400).json({ success:false, error:'Invalid appointmentId' }); }
        const appt = await db.collection('APPOINTMENTS').findOne({ _id:apptId });
        if (!appt) return res.status(404).json({ success:false, error:'Appointment not found' });
        if (appt.status === 'booked' && appt.paymentStatus === 'deposit_paid') { return res.json({ success:true, alreadyConfirmed:true }); }
        await db.collection('APPOINTMENTS').updateOne({ _id:apptId }, { $set:{ status:'booked', paymentStatus:'deposit_paid', updatedAt:new Date() } });
        await db.collection('PAYMENTS').updateOne({ appointmentId:apptId, status:{ $ne:'paid' } }, { $set:{ status:'paid', paidAt:new Date(), updatedAt:new Date() } });
        return res.json({ success:true });
      } catch (err) { next(err); }
    });

    app.post('/payments/webhook', (req, res) => {
      res.status(200).send('OK');
      setImmediate(async () => {
        try {
          const event = req.body;
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
        const { items, shippingAddress, notes, discountCode } = req.body;
        if (!items || !items.length) return res.status(400).json({ success:false, error:'Cart is empty' });
        if (!shippingAddress?.fullName || !shippingAddress?.address || !shippingAddress?.city || !shippingAddress?.phone) return res.status(400).json({ success:false, error:'Complete shipping address is required (fullName, address, city, phone)' });
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
        const shippingFee = discountedSubtotal >= 500 ? 0 : 80;
        const totalAmount = discountedSubtotal + shippingFee;
        const now = new Date();
        const order = { userId:new ObjectId(req.user.userId), items:enrichedItems, subtotal:Decimal128.fromString(subtotal.toFixed(2)), discountAmount:Decimal128.fromString(discountAmount.toFixed(2)), discountCode:appliedCode||null, shippingFee:Decimal128.fromString(shippingFee.toFixed(2)), totalAmount:Decimal128.fromString(totalAmount.toFixed(2)), status:'pending', paymentStatus:'unpaid', paymentMethod:'yoco', shippingAddress, notes:notes||'', createdAt:now, updatedAt:now };
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
        const ORDER_TRANSITIONS = { pending:['pending','confirmed','cancelled'], confirmed:['confirmed','processing','cancelled'], processing:['processing','shipped','cancelled'], shipped:['shipped','delivered'], delivered:['delivered','refunded'], cancelled:['cancelled'], refunded:['refunded'] };
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

        // ── Order shipped email ────────────────────────────────────────────
        if (req.body.status === 'shipped' && process.env.RESEND_API_KEY) {
          try {
            const resend   = new Resend(process.env.RESEND_API_KEY);
            const customer = await db.collection('USERS').findOne({ _id: order.userId }, { projection:{ email:1, firstName:1 } });
            const toEmail  = customer?.email || order.shippingAddress?.email;
            const tracking = req.body.trackingNumber || order.trackingNumber;
            const shortId  = req.params.id.slice(-6).toUpperCase();
            const itemsList = (order.items || []).map(i =>
              `<tr>
                <td style="padding:0.5rem 0;color:#555;">${i.productName}</td>
                <td style="padding:0.5rem 0;text-align:right;color:#555;">x${i.quantity}</td>
              </tr>`
            ).join('');

            if (toEmail) {
              await resend.emails.send({
                from:    'NXL Beauty Bar <onboarding@resend.dev>',
                to:      toEmail,
                subject: `Your Order #${shortId} Has Shipped! 🚚`,
                html: `
                  <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:2rem;background:#fdf6f0;border-radius:12px;">
                    <h2 style="font-family:Georgia,serif;color:#3d1f15;margin-bottom:0.25rem;">NXL Beauty Bar</h2>
                    <h3 style="color:#6b3528;margin-top:0;">Your Order is on its Way! 🚚</h3>
                    <p style="color:#555;line-height:1.65;">Hi ${customer?.firstName || order.shippingAddress?.fullName},</p>
                    <p style="color:#555;line-height:1.65;">Great news — your order <strong>#${shortId}</strong> has been shipped and is on its way to you!</p>

                    ${tracking ? `
                    <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:1rem 1.25rem;margin:1.25rem 0;text-align:center;">
                      <p style="margin:0;font-size:0.78rem;color:#15803d;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;">Tracking Number</p>
                      <p style="margin:0.4rem 0 0;font-size:1.25rem;font-weight:700;color:#3d1f15;font-family:monospace;">${tracking}</p>
                      <p style="margin:0.35rem 0 0;font-size:0.75rem;color:#9e7060;">Use this number to track your parcel with your courier</p>
                    </div>
                    ` : ''}

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

                    <div style="background:#fff8f3;border:1px solid #e0ccc4;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.25rem;">
                      <p style="margin:0;font-size:0.82rem;font-weight:700;color:#6b3528;">📦 Delivering to</p>
                      <p style="margin:0.35rem 0 0;font-size:0.82rem;color:#9e7060;line-height:1.65;">
                        ${order.shippingAddress?.fullName}<br/>
                        ${order.shippingAddress?.address}, ${order.shippingAddress?.city}<br/>
                        ${order.shippingAddress?.province || ''} ${order.shippingAddress?.postalCode || ''}
                      </p>
                    </div>

                    <p style="color:#9e7060;font-size:0.8rem;line-height:1.65;">Questions about your order? WhatsApp us at <a href="https://wa.me/27685113394" style="color:#a0502e;">068 511 3394</a> or email <a href="mailto:nxlbeautybar@gmail.com" style="color:#a0502e;">nxlbeautybar@gmail.com</a>.</p>
                    <hr style="border:none;border-top:1px solid #e0ccc4;margin:1.5rem 0;"/>
                    <p style="color:#b08070;font-size:0.7rem;text-align:center;margin:0;">NXL Beauty Bar &middot; 1948 Mahalefele Rd, Dube, Soweto, 1800</p>
                  </div>
                `,
              });
              logger.info(`[SHIPPED EMAIL] Sent to ${toEmail}`, { orderId: req.params.id, tracking });
            }
          } catch (emailErr) {
            logger.error(`[SHIPPED EMAIL] Failed: ${emailErr.message}`);
          }
        }
        // ──────────────────────────────────────────────────────────────────

        res.json({ success:true, data:updated });
      } catch (err) { next(err); }
    });

    // GET /shop/orders/:id — single order  ← AFTER all specific /shop/orders routes
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

    // POST /discount-codes/validate — public validate (used by cart before checkout)
    app.post('/discount-codes/validate', authenticateToken, discountLimiter, async (req, res, next) => {
      try {
        const { code, subtotal } = req.body;
        if (!code) return res.status(400).json({ success:false, error:'Code is required' });
        const found = await db.collection('DISCOUNT_CODES').findOne({
          code: code.toUpperCase().trim(), isActive: true,
          $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
        });
        if (!found) return res.status(404).json({ success:false, error:'Invalid or expired discount code.' });
        if (found.usageLimit && found.usedCount >= found.usageLimit) return res.status(400).json({ success:false, error:'This code has reached its usage limit.' });
        if (found.minOrderAmount && subtotal < found.minOrderAmount) return res.status(400).json({ success:false, error:`This code requires a minimum order of R${found.minOrderAmount.toFixed(2)}.` });
        const discountAmount = found.type === 'percentage'
          ? Math.round((subtotal * found.value / 100) * 100) / 100
          : Math.min(found.value, subtotal);
        res.json({ success:true, data:{ code:found.code, type:found.type, value:found.value, description:found.description, discountAmount } });
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

          } catch (apptErr) {
            logger.error(`[REMINDER] Failed for appointment ${appt._id}: ${apptErr.message}`);
          }
        }
      } catch (err) {
        logger.error(`[REMINDER] Cron error: ${err.message}`);
      }
    }

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
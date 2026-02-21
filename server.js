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
const nodemailer = require('nodemailer');

// ---- Date/time normalization helpers ----
function pad2(n) {
  return String(n).padStart(2, '0');
}

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

  if (ampm === 'am') {
    if (hh === 12) hh = 0;
  } else {
    if (hh !== 12) hh += 12;
  }
  return `${pad2(hh)}:${pad2(mm)}`;
}

function normalizeDateToISO(dateRaw) {
  if (typeof dateRaw !== 'string') return null;
  const d = dateRaw.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(d)) return d;

  {
    const m = d
      .replace(/,/g, ' ')
      .replace(/\s+/g, ' ')
      .match(/^([A-Za-z]+)\s+(\d{1,2}|\d{4})\s+(\d{1,2}|\d{4})$/);
    if (m) {
      const monthName = m[1].toLowerCase();
      const a = m[2];
      const b = m[3];

      const months = {
        jan: 0, january: 0,
        feb: 1, february: 1,
        mar: 2, march: 2,
        apr: 3, april: 3,
        may: 4,
        jun: 5, june: 5,
        jul: 6, july: 6,
        aug: 7, august: 7,
        sep: 8, sept: 8, september: 8,
        oct: 9, october: 9,
        nov: 10, november: 10,
        dec: 11, december: 11
      };

      const monthIdx = months[monthName];
      if (monthIdx !== undefined) {
        const aIsYear = /^\d{4}$/.test(a);
        const bIsYear = /^\d{4}$/.test(b);

        let year = null;
        let day = null;
        if (aIsYear && !bIsYear) {
          year = parseInt(a, 10);
          day = parseInt(b, 10);
        } else if (bIsYear && !aIsYear) {
          year = parseInt(b, 10);
          day = parseInt(a, 10);
        }

        if (year && day && day >= 1 && day <= 31) {
          const parsed = new Date(year, monthIdx, day);
          const yyyy = parsed.getFullYear();
          const mm = pad2(parsed.getMonth() + 1);
          const dd = pad2(parsed.getDate());
          return `${yyyy}-${mm}-${dd}`;
        }
      }
    }
  }

  const parsed = new Date(d);
  if (Number.isNaN(parsed.getTime())) return null;

  const yyyy = parsed.getFullYear();
  const mm = pad2(parsed.getMonth() + 1);
  const dd = pad2(parsed.getDate());
  return `${yyyy}-${mm}-${dd}`;
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
  const count = Math.ceil(totalMinutes / 15);

  for (let i = 0; i < count; i++) {
    slots.push(`${pad2(h)}:${pad2(m)}`);
    m += 15;
    if (m >= 60) {
      m = 0;
      h += 1;
    }
  }
  return slots;
}

const app = express();
const port = process.env.PORT;

// --- CORS ---
const allowedOrigins = process.env.NODE_ENV === 'production'
  ? [process.env.CORS_ORIGIN]
  : [/^http:\/\/localhost:\d+$/];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.some(o => (o instanceof RegExp ? o.test(origin) : o === origin))) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 200
};

const refreshTokens = new Set();

// Winston logger
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

function sendValidationError(res, errors) {
  const list = Array.isArray(errors) ? errors : [];
  const msg = list.length
    ? list.map(e => `${e?.path || e?.param || 'field'}: ${e?.msg || 'Invalid value'}`).join(', ')
    : 'Validation failed';
  return res.status(400).json({ success: false, error: msg, errors: list });
}

function decimalToNumber(v) {
  if (v == null) return null;
  if (typeof v === 'number') return v;
  if (typeof v === 'object' && typeof v.toString === 'function') {
    const n = Number(v.toString());
    return Number.isFinite(n) ? n : null;
  }
  const n = Number(String(v));
  return Number.isFinite(n) ? n : null;
}

// Fail fast on missing env vars
const requiredEnv = ['PORT', 'MONGODB_URI', 'DB_NAME', 'JWT_SECRET', 'CORS_ORIGIN'];
const missingEnv = requiredEnv.filter(key => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
  process.exit(1);
}

// --- Core middleware ---
app.use(helmet());
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(bodyParser.json());

// ============================================================
// FIX: Strip /api prefix so frontend calls to /api/payments
// correctly match routes registered as /payments
// ============================================================
app.use((req, _res, next) => {
  if (req.url.startsWith('/api/')) {
    req.url = req.url.slice(4); // "/api/payments" -> "/payments"
  } else if (req.url === '/api') {
    req.url = '/';
  }
  next();
});

// Rate limiter for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many requests, please try again later.' }
});

const uri = process.env.MONGODB_URI;
const dbName = process.env.DB_NAME;
const jwtSecret = process.env.JWT_SECRET;

const client = new MongoClient(uri);
let db;

// Graceful shutdown
function shutdown() {
  client.close().then(() => process.exit(0));
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Production HTTPS redirect
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  });
}

// --- Collection initialization ---
const initCollections = async (db) => {
  // USERS
  await db.createCollection('USERS', {
    validator: {
      $jsonSchema: {
        bsonType: 'object',
        required: ['email', 'password', 'firstName', 'lastName', 'role', 'isActive', 'createdAt', 'updatedAt'],
        properties: {
          email: { bsonType: 'string', pattern: '^\\S+@\\S+\\.\\S+$' },
          password: { bsonType: 'string', minLength: 60 },
          firstName: { bsonType: 'string', minLength: 1 },
          lastName: { bsonType: 'string', minLength: 1 },
          role: { bsonType: 'string', enum: ['user', 'admin'] },
          isActive: { bsonType: 'bool' },
          createdAt: { bsonType: 'date' },
          updatedAt: { bsonType: 'date' }
        }
      }
    },
    validationLevel: 'strict'
  }).catch(() => {});
  try { await db.collection('USERS').dropIndex('email_1'); } catch (e) {}
  await db.collection('USERS').createIndex({ email: 1 }, { unique: true, name: 'email_unique_idx' });

  // SERVICES
  await db.createCollection('SERVICES', {
    validator: {
      $jsonSchema: {
        bsonType: 'object',
        required: ['name', 'durationMinutes', 'price', 'isActive', 'createdAt', 'updatedAt'],
        properties: {
          name: { bsonType: 'string', minLength: 1 },
          durationMinutes: { bsonType: 'int', minimum: 15 },
          price: { bsonType: 'decimal', minimum: 0 },
          isActive: { bsonType: 'bool' },
          createdAt: { bsonType: 'date' },
          updatedAt: { bsonType: 'date' }
        }
      }
    },
    validationLevel: 'strict'
  }).catch(() => {});
  try { await db.collection('SERVICES').dropIndex('name_1'); } catch (e) {}
  await db.collection('SERVICES').createIndex({ name: 1 }, { unique: true, name: 'service_name_unique_idx' });

  // EMPLOYEES
  await db.createCollection('EMPLOYEES', {
    validator: {
      $jsonSchema: {
        bsonType: 'object',
        required: ['name', 'servicesOffered', 'isActive', 'createdAt', 'updatedAt'],
        properties: {
          name: { bsonType: 'string', minLength: 1 },
          email: { bsonType: ['string', 'null'], pattern: '^\\S+@\\S+\\.\\S+$' },
          servicesOffered: { bsonType: 'array', minItems: 1, items: { bsonType: 'objectId' } },
          isActive: { bsonType: 'bool' },
          createdAt: { bsonType: 'date' },
          updatedAt: { bsonType: 'date' }
        }
      }
    },
    validationLevel: 'strict'
  }).catch(() => {});
  try { await db.collection('EMPLOYEES').dropIndex('email_1'); } catch (e) {}
  await db.collection('EMPLOYEES').createIndex({ email: 1 }, { unique: true, sparse: true, name: 'employee_email_unique_idx' });

  // AVAILABILITY
  await db.createCollection('AVAILABILITY', {
    validator: {
      $jsonSchema: {
        bsonType: 'object',
        required: ['date', 'time', 'employeeId', 'reason', 'createdAt'],
        properties: {
          date: { bsonType: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}$' },
          time: { bsonType: 'string', pattern: '^\\d{2}:\\d{2}$' },
          employeeId: { anyOf: [{ bsonType: 'objectId' }, { bsonType: 'string', enum: ['ALL'] }] },
          reason: { bsonType: 'string' },
          createdAt: { bsonType: 'date' }
        }
      }
    },
    validationLevel: 'strict'
  }).catch(() => {});
  try { await db.collection('AVAILABILITY').dropIndex('date_1_time_1_employeeId_1'); } catch (e) {}
  await db.collection('AVAILABILITY').createIndex(
    { date: 1, time: 1, employeeId: 1 },
    { unique: true, name: 'availability_unique_idx' }
  );

  // APPOINTMENTS
  await db.createCollection('APPOINTMENTS', {
    validator: {
      $jsonSchema: {
        bsonType: 'object',
        required: ['date', 'time', 'userId', 'employeeId', 'serviceIds', 'totalPrice', 'status', 'createdAt', 'updatedAt'],
        properties: {
          date: { bsonType: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}$' },
          time: { bsonType: 'string', pattern: '^\\d{2}:\\d{2}$' },
          userId: { bsonType: 'objectId' },
          employeeId: { bsonType: 'objectId' },
          serviceIds: { bsonType: 'array', minItems: 1, items: { bsonType: 'objectId' } },
          totalPrice: { bsonType: 'decimal', minimum: 0 },
          status: { bsonType: 'string', enum: ['booked', 'cancelled', 'completed'] },
          paymentStatus: { bsonType: 'string', enum: ['unpaid', 'deposit_paid', 'paid'] },
          createdAt: { bsonType: 'date' },
          updatedAt: { bsonType: 'date' }
        }
      }
    },
    validationLevel: 'strict'
  }).catch(() => {});
  try { await db.collection('APPOINTMENTS').dropIndex('date_1_time_1_employeeId_1'); } catch (e) {}
  await db.collection('APPOINTMENTS').createIndex(
    { date: 1, time: 1, employeeId: 1 },
    { unique: true, name: 'appointment_unique_idx' }
  );

  // PAYMENTS
  await db.createCollection('PAYMENTS', {
    validator: {
      $jsonSchema: {
        bsonType: 'object',
        required: ['appointmentId', 'type', 'amount', 'method', 'status', 'createdAt'],
        properties: {
          appointmentId: { bsonType: 'objectId' },
          type: { bsonType: 'string', enum: ['deposit', 'full'] },
          amount: { bsonType: 'decimal', minimum: 0 },
          currency: { bsonType: 'string' },
          method: { bsonType: 'string', enum: ['cash', 'card', 'online'] },
          status: { bsonType: 'string', enum: ['pending', 'paid', 'refunded'] },
          createdAt: { bsonType: 'date' }
        }
      }
    },
    validationLevel: 'strict'
  }).catch(() => {});
  try { await db.collection('PAYMENTS').dropIndex('payment_appointment_unique_idx'); } catch (e) {}
  try { await db.collection('PAYMENTS').dropIndex('appointmentId_1'); } catch (e) {}
  await db.collection('PAYMENTS').createIndex(
    { appointmentId: 1, type: 1 },
    { unique: true, name: 'payment_appointment_type_unique_idx' }
  );

  // NOTIFICATIONS
  await db.createCollection('NOTIFICATIONS', {
    validator: {
      $jsonSchema: {
        bsonType: 'object',
        required: ['message', 'target', 'createdBy', 'createdAt', 'read'],
        properties: {
          message: { bsonType: 'string' },
          target: { bsonType: 'string', enum: ['client', 'staff', 'all'] },
          recipientId: { bsonType: ['objectId', 'null'] },
          createdBy: { bsonType: 'objectId' },
          createdAt: { bsonType: 'date' },
          read: { bsonType: 'bool' },
          readAt: { bsonType: ['date', 'null'] }
        }
      }
    },
    validationLevel: 'strict'
  }).catch(() => {});
  await db.collection('NOTIFICATIONS').createIndex({ createdAt: -1 });

  // AUDIT_LOG
  await db.createCollection('AUDIT_LOG', {
    validator: {
      $jsonSchema: {
        bsonType: 'object',
        required: ['collection', 'documentId', 'action', 'performedBy', 'timestamp'],
        properties: {
          collection: { bsonType: 'string' },
          documentId: { bsonType: 'objectId' },
          action: { bsonType: 'string' },
          performedBy: { bsonType: 'objectId' },
          timestamp: { bsonType: 'date' },
          data: { bsonType: 'object' }
        }
      }
    },
    validationLevel: 'strict'
  }).catch(() => {});
};

// --- Start server ---
async function startServer() {
  try {
    await client.connect();
    db = client.db(dbName);
    await initCollections(db);
    console.log('Connected to MongoDB Atlas');

    // Auth middleware
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
        if (!req.user || req.user.role !== role) {
          return res.status(403).json({ success: false, error: 'Forbidden' });
        }
        next();
      };
    }

    const idValidator = param('id').isMongoId().withMessage('Invalid ID format');

    // =====================
    // AUTH ROUTES
    // =====================
    app.post('/auth/register', authLimiter,
      body('email').isEmail().normalizeEmail(),
      body('password').isString().isLength({ min: 8 }).matches(/[A-Z]/).matches(/[a-z]/).matches(/[0-9]/).matches(/[^A-Za-z0-9]/),
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
          const user = { email, password: hashedPassword, firstName, lastName, role: 'user', isActive: true, createdAt: now, updatedAt: now };
          const result = await db.collection('USERS').insertOne(user);

          const token = jwt.sign({ userId: result.insertedId, email: user.email, role: user.role }, jwtSecret, { expiresIn: '1h' });
          res.status(201).json({
            success: true,
            message: 'User registered successfully',
            data: { _id: result.insertedId, email: user.email, firstName: user.firstName, lastName: user.lastName, role: user.role },
            token
          });
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
          if (!user) return res.status(400).json({ success: false, error: 'Invalid credentials' });

          const match = await bcrypt.compare(password, user.password);
          if (!match) return res.status(400).json({ success: false, error: 'Invalid credentials' });

          const normalizedRole = ['admin', 'user'].includes(user.role) ? user.role : 'user';
          if (normalizedRole !== user.role) {
            await db.collection('USERS').updateOne({ _id: user._id }, { $set: { role: normalizedRole, updatedAt: new Date() } });
          }

          const token = jwt.sign({ userId: user._id, email: user.email, role: normalizedRole }, jwtSecret, { expiresIn: '1h' });
          const refreshToken = jwt.sign({ userId: user._id, email: user.email, role: normalizedRole }, jwtSecret, { expiresIn: '7d' });
          refreshTokens.add(refreshToken);

          res.status(200).json({
            success: true,
            message: 'Login successful',
            data: { _id: user._id, email: user.email, firstName: user.firstName, lastName: user.lastName, role: normalizedRole },
            token,
            refreshToken
          });
        } catch (err) { next(err); }
      }
    );

    app.post('/auth/change-password', authenticateToken,
      body('oldPassword').isString().notEmpty(),
      body('newPassword').isString().isLength({ min: 8 }).matches(/[A-Z]/).matches(/[a-z]/).matches(/[0-9]/).matches(/[^A-Za-z0-9]/),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          const user = await db.collection('USERS').findOne({ _id: new ObjectId(req.user.userId) });
          if (!user) return res.status(404).json({ success: false, error: 'User not found' });
          const match = await bcrypt.compare(req.body.oldPassword, user.password);
          if (!match) return res.status(400).json({ success: false, error: 'Old password incorrect' });
          const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
          await db.collection('USERS').updateOne({ _id: user._id }, { $set: { password: hashedPassword, updatedAt: new Date() } });
          res.status(200).json({ success: true, message: 'Password changed successfully' });
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
          if (!user) return res.status(200).json({ success: true, message: 'If the email exists, a reset link has been sent' });

          const resetToken = jwt.sign({ userId: user._id, email: user.email, type: 'password-reset' }, jwtSecret, { expiresIn: '1h' });
          await db.collection('USERS').updateOne(
            { _id: user._id },
            { $set: { passwordResetToken: resetToken, passwordResetExpiry: new Date(Date.now() + 3600000) } }
          );

          if (process.env.NODE_ENV === 'production' && process.env.SMTP_HOST) {
            const transporter = nodemailer.createTransport({
              host: process.env.SMTP_HOST,
              port: process.env.SMTP_PORT,
              auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
            });
            const resetUrl = `${process.env.CORS_ORIGIN}/reset-password?token=${resetToken}`;
            await transporter.sendMail({
              from: process.env.SMTP_USER,
              to: req.body.email,
              subject: 'Password Reset Request',
              html: `<p>Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.</p>`
            });
          } else {
            logger.info(`Password reset token for ${req.body.email}: ${resetToken}`);
          }

          res.status(200).json({ success: true, message: 'If the email exists, a reset link has been sent' });
        } catch (err) { next(err); }
      }
    );

    app.post('/auth/reset-password', authLimiter,
      body('token').isString().notEmpty(),
      body('newPassword').isString().isLength({ min: 8 }).matches(/[A-Z]/).matches(/[a-z]/).matches(/[0-9]/).matches(/[^A-Za-z0-9]/),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());

          let decoded;
          try {
            decoded = jwt.verify(req.body.token, jwtSecret);
            if (decoded.type !== 'password-reset') return res.status(400).json({ success: false, error: 'Invalid reset token' });
          } catch (err) {
            return res.status(400).json({ success: false, error: 'Invalid or expired reset token' });
          }

          const user = await db.collection('USERS').findOne({ _id: new ObjectId(decoded.userId) });
          if (!user) return res.status(404).json({ success: false, error: 'User not found' });
          if (user.passwordResetToken !== req.body.token || new Date() > new Date(user.passwordResetExpiry)) {
            return res.status(400).json({ success: false, error: 'Invalid or expired reset token' });
          }

          const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
          await db.collection('USERS').updateOne(
            { _id: user._id },
            { $set: { password: hashedPassword, updatedAt: new Date() }, $unset: { passwordResetToken: '', passwordResetExpiry: '' } }
          );
          res.status(200).json({ success: true, message: 'Password reset successfully' });
        } catch (err) { next(err); }
      }
    );

    app.post('/auth/refresh-token',
      body('refreshToken').isString().notEmpty(),
      async (req, res, next) => {
        try {
          const { refreshToken } = req.body;
          if (!refreshTokens.has(refreshToken)) return res.status(403).json({ success: false, error: 'Invalid refresh token' });
          jwt.verify(refreshToken, jwtSecret, (err, user) => {
            if (err) return res.status(403).json({ success: false, error: 'Invalid refresh token' });
            const token = jwt.sign({ userId: user.userId, email: user.email, role: user.role }, jwtSecret, { expiresIn: '1h' });
            res.status(200).json({ success: true, token });
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
        validators = [
          body('name').isString().notEmpty(),
          body('durationMinutes').isInt({ min: 15 }).custom(v => v % 15 === 0),
          body('price').isDecimal({ decimal_digits: '0,2' }).custom(v => parseFloat(v) > 0),
          body('isActive').isBoolean().optional()
        ];
      } else if (collectionName === 'EMPLOYEES') {
        validators = [
          body('name').isString().notEmpty(),
          body('email').optional({ nullable: true }).isEmail().normalizeEmail(),
          body('servicesOffered').isArray({ min: 1 }),
          body('servicesOffered.*').isMongoId(),
          body('isActive').isBoolean().optional()
        ];
      } else if (collectionName === 'AVAILABILITY') {
        validators = [
          body('date').matches(/^\d{4}-\d{2}-\d{2}$/),
          body('time').matches(/^\d{2}:\d{2}$/),
          body('employeeId').custom(v => v === 'ALL' || /^[a-f\d]{24}$/i.test(v)),
          body('reason').isString().notEmpty()
        ];
      } else if (collectionName === 'APPOINTMENTS') {
        validators = [
          body('date').custom((v, { req }) => {
            const normalized = normalizeAppointmentDateTime(v, req.body?.time);
            if (!normalized) return false;
            req.body.date = normalized.date;
            req.body.time = normalized.time;
            return true;
          }),
          body('time').custom((v, { req }) => {
            const normalized = normalizeAppointmentDateTime(req.body?.date, v);
            if (!normalized) return false;
            req.body.date = normalized.date;
            req.body.time = normalized.time;
            return true;
          }),
          body('employeeId').isMongoId(),
          body('serviceIds').isArray({ min: 1 }),
          body('serviceIds.*').isMongoId()
        ];
      } else if (collectionName === 'PAYMENTS') {
        validators = [
          body('appointmentId').isMongoId(),
          body('type').optional().isIn(['deposit', 'full']),
          body('amount').isDecimal({ decimal_digits: '0,2' }).custom(v => parseFloat(v) > 0),
          body('method').isIn(['cash', 'card', 'online']),
          body('status').isIn(['pending', 'paid', 'refunded'])
        ];
      }

      const putValidators =
        collectionName === 'SERVICES' ? [
          body('name').optional().isString().notEmpty(),
          body('durationMinutes').optional().isInt({ min: 15 }).custom(v => v % 15 === 0),
          body('price').optional().isDecimal({ decimal_digits: '0,2' }).custom(v => parseFloat(v) > 0),
          body('isActive').optional().isBoolean()
        ] : collectionName === 'EMPLOYEES' ? [
          body('name').optional().isString().notEmpty(),
          body('email').optional({ nullable: true }).isEmail().normalizeEmail(),
          body('servicesOffered').optional().isArray({ min: 1 }),
          body('servicesOffered.*').optional().isMongoId(),
          body('isActive').optional().isBoolean()
        ] : collectionName === 'AVAILABILITY' ? [
          body('date').optional().matches(/^\d{4}-\d{2}-\d{2}$/),
          body('time').optional().matches(/^\d{2}:\d{2}$/),
          body('employeeId').optional().custom(v => v === 'ALL' || /^[a-f\d]{24}$/i.test(v)),
          body('reason').optional().isString().notEmpty()
        ] : collectionName === 'APPOINTMENTS' ? [
          body('date').optional().custom((v, { req }) => {
            const normalized = normalizeAppointmentDateTime(v, req.body?.time);
            if (!normalized) return false;
            req.body.date = normalized.date;
            req.body.time = normalized.time;
            return true;
          }),
          body('time').optional().custom((v, { req }) => {
            const normalized = normalizeAppointmentDateTime(req.body?.date, v);
            if (!normalized) return false;
            req.body.date = normalized.date;
            req.body.time = normalized.time;
            return true;
          }),
          body('employeeId').optional().isMongoId(),
          body('serviceIds').optional().isArray({ min: 1 }),
          body('serviceIds.*').optional().isMongoId()
        ] : collectionName === 'PAYMENTS' ? [
          body('appointmentId').optional().isMongoId(),
          body('type').optional().isIn(['deposit', 'full']),
          body('amount').optional().isDecimal({ decimal_digits: '0,2' }).custom(v => parseFloat(v) > 0),
          body('method').optional().isIn(['cash', 'card', 'online']),
          body('status').optional().isIn(['pending', 'paid', 'refunded'])
        ] : [];

      // --- CREATE ---
      app.post(`/${route}`, authenticateToken, ...validators, async (req, res, next) => {
        if (!db) return res.status(500).json({ success: false, error: 'Database not connected' });
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationError(res, errors.array());

        if (req.body._id) return res.status(400).json({ success: false, error: 'Manual _id injection is not allowed' });

        delete req.body.createdAt;
        delete req.body.updatedAt;
        if (collectionName === 'USERS') delete req.body.role;

        req.body.createdAt = new Date();
        req.body.updatedAt = new Date();

        if (req.body.employeeId && typeof req.body.employeeId === 'string' && req.body.employeeId !== 'ALL') {
          req.body.employeeId = new ObjectId(req.body.employeeId);
        }
        if (Array.isArray(req.body.serviceIds)) {
          req.body.serviceIds = req.body.serviceIds.map(id => new ObjectId(id));
        }
        if (Array.isArray(req.body.servicesOffered)) {
          req.body.servicesOffered = req.body.servicesOffered.map(id => new ObjectId(id));
        }
        if (req.body.appointmentId && typeof req.body.appointmentId === 'string') {
          req.body.appointmentId = new ObjectId(req.body.appointmentId);
        }

        if (collectionName === 'SERVICES' && req.body.price) {
          req.body.price = Decimal128.fromString(String(req.body.price));
        }
        if (collectionName === 'PAYMENTS' && req.body.amount) {
          req.body.amount = Decimal128.fromString(String(req.body.amount));
        }

        if (collectionName === 'EMPLOYEES') {
          const serviceIds = req.body.servicesOffered || [];
          const count = await db.collection('SERVICES').countDocuments({ _id: { $in: serviceIds }, isActive: true });
          if (count !== serviceIds.length) {
            return res.status(400).json({ success: false, error: 'All referenced services must exist and be active' });
          }
        }

        if (collectionName === 'APPOINTMENTS') {
          const emp = await db.collection('EMPLOYEES').findOne({ _id: req.body.employeeId, isActive: true });
          if (!emp) return res.status(400).json({ success: false, error: 'Employee not found or inactive' });

          const serviceIds = req.body.serviceIds || [];
          const count = await db.collection('SERVICES').countDocuments({ _id: { $in: serviceIds }, isActive: true });
          if (count !== serviceIds.length) {
            return res.status(400).json({ success: false, error: 'All services must exist and be active' });
          }

          const services = await db.collection('SERVICES').find({ _id: { $in: req.body.serviceIds } }).toArray();
          const totalDuration = services.reduce((sum, s) => sum + s.durationMinutes, 0);
          const requestedSlots = generateSlotRange(req.body.time, totalDuration);

          const overlapping = await db.collection('APPOINTMENTS').findOne({
            date: req.body.date,
            employeeId: req.body.employeeId,
            time: { $in: requestedSlots }
          });
          if (overlapping) return res.status(400).json({ success: false, error: 'This appointment overlaps with an existing booking' });

          const blocked = await db.collection('AVAILABILITY').findOne({
            date: req.body.date,
            time: { $in: requestedSlots },
            $or: [{ employeeId: req.body.employeeId }, { employeeId: 'ALL' }]
          });
          if (blocked) return res.status(400).json({ success: false, error: 'One or more time slots are unavailable' });

          const totalPrice = services.reduce((sum, s) => sum + parseFloat(s.price), 0);
          req.body.totalPrice = Decimal128.fromString(totalPrice.toFixed(2));
          req.body.status = 'booked';
          if (req.user?.userId) req.body.userId = new ObjectId(req.user.userId);
          req.body.paymentStatus = 'unpaid';
        }

        if (collectionName === 'PAYMENTS') {
          const appt = await db.collection('APPOINTMENTS').findOne({ _id: req.body.appointmentId });
          if (!appt) return res.status(400).json({ success: false, error: 'Appointment does not exist' });

          const paymentType = req.body.type || 'full';
          const depositAmount = decimalToNumber(process.env.DEPOSIT_AMOUNT ?? 100);
          const paidAmount = decimalToNumber(req.body.amount);
          const total = decimalToNumber(appt.totalPrice);
          if (paidAmount == null || total == null) return res.status(400).json({ success: false, error: 'Invalid payment amount' });

          if (paymentType === 'deposit') {
            if (depositAmount == null || paidAmount !== depositAmount) {
              return res.status(400).json({ success: false, error: `Deposit must be ${depositAmount?.toFixed?.(2) ?? depositAmount}` });
            }
            if (paidAmount > total) return res.status(400).json({ success: false, error: 'Deposit cannot exceed appointment totalPrice' });
            req.body.type = 'deposit';
          } else {
            if (paidAmount !== total) return res.status(400).json({ success: false, error: 'Payment amount must match appointment totalPrice' });
            req.body.type = 'full';
          }

          const exists = await db.collection('PAYMENTS').findOne({ appointmentId: req.body.appointmentId, type: req.body.type });
          if (exists) return res.status(400).json({ success: false, error: 'Payment already exists for this appointment' });
          if (!['pending', 'paid'].includes(req.body.status)) return res.status(400).json({ success: false, error: 'Invalid payment status' });
        }

        try {
          const result = await db.collection(collectionName).insertOne(req.body);
          if (!result.insertedId) return res.status(500).json({ success: false, error: 'Failed to create document' });

          if (collectionName === 'PAYMENTS') {
            const nextStatus = req.body.type === 'deposit' ? 'deposit_paid' : 'paid';
            await db.collection('APPOINTMENTS').updateOne(
              { _id: req.body.appointmentId },
              { $set: { paymentStatus: nextStatus, updatedAt: new Date() } }
            );
          }
          res.status(201).json({ success: true, message: 'Created', data: { _id: result.insertedId, ...req.body } });
        } catch (err) {
          if (err.code === 121) return res.status(400).json({ success: false, error: 'Schema validation failed', details: err.errInfo });
          if (err.code === 11000) return res.status(409).json({ success: false, error: 'Duplicate key error' });
          next(err);
        }
      });

      // --- UPDATE ---
      app.put(`/${route}/:id`, authenticateToken, idValidator, ...putValidators, async (req, res, next) => {
        if (!db) return res.status(500).json({ success: false, error: 'Database not connected' });
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationError(res, errors.array());

        if (req.body._id) return res.status(400).json({ success: false, error: 'Manual _id injection is not allowed' });

        delete req.body.createdAt;
        delete req.body.updatedAt;
        if (collectionName === 'USERS') delete req.body.role;
        req.body.updatedAt = new Date();

        if (req.body.employeeId && typeof req.body.employeeId === 'string' && req.body.employeeId !== 'ALL') {
          req.body.employeeId = new ObjectId(req.body.employeeId);
        }
        if (Array.isArray(req.body.serviceIds)) {
          req.body.serviceIds = req.body.serviceIds.map(id => new ObjectId(id));
        }
        if (Array.isArray(req.body.servicesOffered)) {
          req.body.servicesOffered = req.body.servicesOffered.map(id => new ObjectId(id));
        }
        if (req.body.appointmentId && typeof req.body.appointmentId === 'string') {
          req.body.appointmentId = new ObjectId(req.body.appointmentId);
        }

        if (collectionName === 'SERVICES' && req.body.price) {
          req.body.price = Decimal128.fromString(String(req.body.price));
        }
        if (collectionName === 'PAYMENTS' && req.body.amount) {
          req.body.amount = Decimal128.fromString(String(req.body.amount));
        }

        if (collectionName === 'EMPLOYEES' && req.body.servicesOffered) {
          const count = await db.collection('SERVICES').countDocuments({ _id: { $in: req.body.servicesOffered }, isActive: true });
          if (count !== req.body.servicesOffered.length) {
            return res.status(400).json({ success: false, error: 'All referenced services must exist and be active' });
          }
        }

        if (collectionName === 'APPOINTMENTS') {
          const appt = await db.collection('APPOINTMENTS').findOne({ _id: new ObjectId(req.params.id) });
          if (!appt) return res.status(404).json({ success: false, error: 'Appointment not found' });

          const validTransitions = { booked: ['cancelled', 'completed'], cancelled: [], completed: [] };
          if (req.body.status && !validTransitions[appt.status].includes(req.body.status)) {
            return res.status(400).json({ success: false, error: 'Invalid status transition' });
          }

          if (req.body.serviceIds) {
            const count = await db.collection('SERVICES').countDocuments({ _id: { $in: req.body.serviceIds }, isActive: true });
            if (count !== req.body.serviceIds.length) {
              return res.status(400).json({ success: false, error: 'All services must exist and be active' });
            }
            const services = await db.collection('SERVICES').find({ _id: { $in: req.body.serviceIds } }).toArray();
            req.body.totalPrice = Decimal128.fromString(
              services.reduce((sum, s) => sum + parseFloat(s.price), 0).toFixed(2)
            );
          }
        }

        if (collectionName === 'PAYMENTS') {
          const payment = await db.collection('PAYMENTS').findOne({ _id: new ObjectId(req.params.id) });
          if (!payment) return res.status(404).json({ success: false, error: 'Payment not found' });
          const validTransitions = { pending: ['paid', 'refunded'], paid: ['refunded'], refunded: [] };
          if (req.body.status && !validTransitions[payment.status].includes(req.body.status)) {
            return res.status(400).json({ success: false, error: 'Invalid payment status transition' });
          }
        }

        try {
          // FIX: MongoDB driver v5+ returns the document directly, not { value: doc }
          const updatedDoc = await db.collection(collectionName).findOneAndUpdate(
            { _id: new ObjectId(req.params.id) },
            { $set: req.body },
            { returnDocument: 'after' }
          );
          if (!updatedDoc) return res.status(404).json({ success: false, error: 'Document not found' });
          res.status(200).json({ success: true, message: 'Updated', data: updatedDoc });
        } catch (err) {
          if (err.code === 121) return res.status(400).json({ success: false, error: 'Schema validation failed', details: err.errInfo });
          if (err.code === 11000) return res.status(409).json({ success: false, error: 'Duplicate key error' });
          next(err);
        }
      });

      // --- READ ALL ---
      app.get(`/${route}`, authenticateToken, async (req, res, next) => {
        if (!db) return res.status(500).json({ success: false, error: 'Database not connected' });
        try {
          let docs = await db.collection(collectionName).find({}).limit(500).toArray();

          if (collectionName === 'APPOINTMENTS') {
            const userIds = [...new Set(docs.map(d => d.userId))];
            const employeeIds = [...new Set(docs.map(d => d.employeeId))];
            const serviceIds = [...new Set(docs.flatMap(d => d.serviceIds))];

            const users = await db.collection('USERS').find({ _id: { $in: userIds } }).project({ password: 0 }).toArray();
            const employees = await db.collection('EMPLOYEES').find({ _id: { $in: employeeIds } }).toArray();
            const services = await db.collection('SERVICES').find({ _id: { $in: serviceIds } }).toArray();

            const userMap = Object.fromEntries(users.map(u => [u._id.toString(), u]));
            const empMap = Object.fromEntries(employees.map(e => [e._id.toString(), e]));
            const svcMap = Object.fromEntries(services.map(s => [s._id.toString(), s]));

            docs = docs.map(doc => ({
              ...doc,
              userName: userMap[doc.userId.toString()]?.firstName + ' ' + userMap[doc.userId.toString()]?.lastName,
              user: userMap[doc.userId.toString()],
              employee: empMap[doc.employeeId.toString()],
              services: doc.serviceIds.map(id => svcMap[id.toString()]).filter(Boolean),
              totalDuration: doc.totalDuration || doc.serviceIds.reduce((sum, id) => {
                const svc = svcMap[id.toString()];
                return sum + (svc?.durationMinutes || 0);
              }, 0)
            }));
          }

          res.status(200).json({ success: true, data: docs });
        } catch (err) { next(err); }
      });

      // --- READ BY ID ---
      app.get(`/${route}/:id`, authenticateToken, idValidator, async (req, res, next) => {
        if (!db) return res.status(500).json({ success: false, error: 'Database not connected' });
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationError(res, errors.array());
        try {
          let doc = await db.collection(collectionName).findOne({ _id: new ObjectId(req.params.id) });
          if (!doc) return res.status(404).json({ success: false, error: 'Document not found' });

          if (collectionName === 'APPOINTMENTS') {
            const user = await db.collection('USERS').findOne({ _id: doc.userId }, { projection: { password: 0 } });
            const employee = await db.collection('EMPLOYEES').findOne({ _id: doc.employeeId });
            const services = await db.collection('SERVICES').find({ _id: { $in: doc.serviceIds } }).toArray();
            doc = { ...doc, user, employee, services };
          }

          res.status(200).json({ success: true, data: doc });
        } catch (err) { next(err); }
      });

      // --- DELETE ---
      app.delete(`/${route}/:id`, authenticateToken, authorizeRole('admin'), idValidator, async (req, res, next) => {
        if (!db) return res.status(500).json({ success: false, error: 'Database not connected' });
        const errors = validationResult(req);
        if (!errors.isEmpty()) return sendValidationError(res, errors.array());

        if (collectionName === 'EMPLOYEES') {
          const future = await db.collection('APPOINTMENTS').findOne({
            employeeId: new ObjectId(req.params.id),
            date: { $gte: new Date().toISOString().slice(0, 10) }
          });
          if (future) return res.status(400).json({ success: false, error: 'Cannot delete employee with future appointments' });
          const result = await db.collection(collectionName).updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { isActive: false, updatedAt: new Date() } }
          );
          if (result.matchedCount === 0) return res.status(404).json({ success: false, error: 'Document not found' });
          return res.status(200).json({ success: true, message: 'Soft deleted successfully' });
        }

        if (collectionName === 'SERVICES') {
          const future = await db.collection('APPOINTMENTS').findOne({
            serviceIds: new ObjectId(req.params.id),
            date: { $gte: new Date().toISOString().slice(0, 10) }
          });
          if (future) return res.status(400).json({ success: false, error: 'Cannot delete service linked to future appointments' });
          const result = await db.collection(collectionName).updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { isActive: false, updatedAt: new Date() } }
          );
          if (result.matchedCount === 0) return res.status(404).json({ success: false, error: 'Document not found' });
          return res.status(200).json({ success: true, message: 'Soft deleted successfully' });
        }

        try {
          const result = await db.collection(collectionName).deleteOne({ _id: new ObjectId(req.params.id) });
          if (result.deletedCount === 0) return res.status(404).json({ success: false, error: 'Document not found' });
          res.status(200).json({ success: true, message: 'Deleted successfully' });
        } catch (err) { next(err); }
      });
    }

    // Register CRUD routes ONCE each
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
        const { page = 1, limit = 20, email } = req.query;
        const query = {};
        if (email) query.email = email;
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const users = await db.collection('USERS').find(query).project({ password: 0 }).skip(skip).limit(parseInt(limit)).toArray();
        res.status(200).json({ success: true, data: users });
      } catch (err) { next(err); }
    });

    app.get('/users/:id', authenticateToken, authorizeRole('admin'), idValidator, async (req, res, next) => {
      try {
        const user = await db.collection('USERS').findOne({ _id: new ObjectId(req.params.id) }, { projection: { password: 0 } });
        if (!user) return res.status(404).json({ success: false, error: 'User not found' });
        res.status(200).json({ success: true, data: user });
      } catch (err) { next(err); }
    });

    app.put('/users/:id', authenticateToken, authorizeRole('admin'), idValidator,
      body('email').optional().isEmail().normalizeEmail(),
      body('firstName').optional().isString().notEmpty(),
      body('lastName').optional().isString().notEmpty(),
      body('role').optional().isIn(['user', 'admin']),
      async (req, res, next) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) return sendValidationError(res, errors.array());
          delete req.body.password;
          req.body.updatedAt = new Date();
          // FIX: MongoDB driver v5+ returns document directly
          const updatedUser = await db.collection('USERS').findOneAndUpdate(
            { _id: new ObjectId(req.params.id) },
            { $set: req.body },
            { returnDocument: 'after', projection: { password: 0 } }
          );
          if (!updatedUser) return res.status(404).json({ success: false, error: 'User not found' });
          res.status(200).json({ success: true, message: 'User updated', data: updatedUser });
        } catch (err) { next(err); }
      }
    );

    app.delete('/users/:id', authenticateToken, authorizeRole('admin'), idValidator, async (req, res, next) => {
      try {
        const result = await db.collection('USERS').deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ success: false, error: 'User not found' });
        res.status(200).json({ success: true, message: 'User deleted' });
      } catch (err) { next(err); }
    });

    // =====================
    // SWAGGER
    // =====================
    const swaggerDocument = {
      openapi: '3.0.0',
      info: { title: 'NXL Beauty Bar API', version: '1.0.0', description: 'API for booking and managing appointments.' },
      components: {
        securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } },
        schemas: {
          Appointment: {
            type: 'object',
            properties: {
              date: { type: 'string', format: 'date' },
              time: { type: 'string' },
              userId: { type: 'string' },
              employeeId: { type: 'string' },
              serviceIds: { type: 'array', items: { type: 'string' } },
              totalPrice: { type: 'string' },
              status: { type: 'string', enum: ['booked', 'cancelled', 'completed'] }
            }
          }
        }
      },
      security: [{ bearerAuth: [] }],
      paths: {
        '/appointments': {
          get: {
            summary: 'Get appointments',
            security: [{ bearerAuth: [] }],
            responses: { '200': { description: 'List of appointments' } }
          }
        }
      }
    };
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

    // Health check
    app.get('/', (req, res) => res.status(200).json({ status: 'ok', env: process.env.NODE_ENV, version: '1.0.0', uptime: process.uptime() }));

    // 404 handler
    app.use((req, res) => {
      res.status(404).json({ success: false, error: `Route ${req.originalUrl} not found.` });
    });

    // Centralized error handler
    app.use((err, req, res, next) => {
      if (err && err.message === 'Not allowed by CORS') {
        return res.status(403).json({ success: false, error: 'CORS blocked this origin' });
      }
      if (res.headersSent) return next(err);
      logger.error(err.stack);
      if (err.name === 'UnauthorizedError') return res.status(401).json({ success: false, error: 'Invalid token' });
      if (err.status === 400) return res.status(400).json({ success: false, error: err.message });
      if (err.status === 404) return res.status(404).json({ success: false, error: err.message });
      if (err.status === 409) return res.status(409).json({ success: false, error: err.message });
      res.status(500).json({ success: false, error: 'Internal server error' });
    });

    app.listen(port, () => {
      console.log(`Server is running on port: ${port}`);
    });

  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
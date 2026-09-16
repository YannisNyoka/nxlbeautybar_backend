const rateLimit = require('express-rate-limit');

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

module.exports = { authLimiter, paymentLimiter, orderLimiter, discountLimiter };

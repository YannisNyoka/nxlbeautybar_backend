const { param } = require('express-validator');

function sendValidationError(res, errors) {
  const list = Array.isArray(errors) ? errors : [];
  const msg = list.length ? list.map(e => `${e?.path || e?.param || 'field'}: ${e?.msg || 'Invalid value'}`).join(', ') : 'Validation failed';
  return res.status(400).json({ success: false, error: msg, errors: list });
}

const idValidator = param('id').isMongoId().withMessage('Invalid ID format');

module.exports = { sendValidationError, idValidator };

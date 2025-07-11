const jwt = require('jsonwebtoken');

function ensureAuthenticated(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.decode(token); // For quick testing, no signature verification
    if (!decoded) throw new Error('Invalid token');
    req.user = decoded;
    next();
  } catch (err) {
    res.redirect('/login');
  }
}

module.exports = { ensureAuthenticated };

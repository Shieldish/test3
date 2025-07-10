const jwt = require('jsonwebtoken');

function ensureAuthenticated(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect('/login');
  }
}

module.exports = { ensureAuthenticated };
 

/* function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
} */

module.exports = { ensureAuthenticated };

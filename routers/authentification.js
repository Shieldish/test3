const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { User } = require('../models/users');
const { sendOtpEmail } = require('../utils/otp');
const { sendResetEmail } = require('../utils/emails');


const cookieParser = require('cookie-parser');
router.use(cookieParser());

// Page de connexion
router.get('/login', (req, res) => {
  res.render('connection/login');
});

// Page d'inscription
router.get('/register', (req, res) => {
  res.render('connection/register');
});

// Page mot de passe oublié
router.get('/forgot-password', (req, res) => {
  res.render('connection/forgot-password', { error: null, success: null });
});

// Traitement connexion
/* router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.render('connection/login', { error: 'Utilisateur non trouvé.' });
    }
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.render('connection/login', { error: 'Mot de passe incorrect.' });
    }
    req.session.user = { id: user.id, username: user.username };
    res.redirect('/');
  } catch (err) {
    res.render('connection/login', { error: 'Erreur serveur.' });
  }
});
 */


router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ where: { username } });
    if (!user) return res.render('connection/login', { error: 'Utilisateur non trouvé.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.render('connection/login', { error: 'Mot de passe incorrect.' });

    // Générer token JWT
  const token = jwt.sign(
  { userId: user.id, username: user.username },
  process.env.JWT_SECRET || 'secret',
  { expiresIn: '1h' }
);

    // Stocker le token dans un cookie sécurisé
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000 // 1h
    });

    res.redirect('/');
  } catch (err) {
    res.render('connection/login', { error: 'Erreur serveur.' });
  }
});

// Traitement inscription
/* router.post('/register', async (req, res) => {
  const { email, username, password, confirmPassword } = req.body;
  const emailRegex = /^[\w-.]+@[\w-]+\.[a-zA-Z]{2,}$/;
  if (!email || !username || !password || !confirmPassword) {
    return res.render('connection/register', { error: 'Tous les champs sont obligatoires.' });
  }
  if (!emailRegex.test(email)) {
    return res.render('connection/register', { error: 'Format d\'email invalide.' });
  }
  if (password !== confirmPassword) {
    return res.render('connection/register', { error: 'Les mots de passe ne correspondent pas.' });
  }
  try {
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) {
      return res.render('connection/register', { error: 'Nom d\'utilisateur déjà utilisé.' });
    }
    const existingEmail = await User.findOne({ where: { email } });
    if (existingEmail) {
      return res.render('connection/register', { error: 'Email déjà utilisé.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    const user = await User.create({ email, username, password: hashedPassword, otp, otpExpires, active: false });
    await sendOtpEmail(email, otp);
    req.session.pendingUserId = user.id;
    res.redirect('/confirm-account');
  } catch (err) {
    res.render('connection/register', { error: 'Erreur serveur.' });
  }
}); */

router.post('/register', async (req, res) => {
  const { email, username, password, confirmPassword } = req.body;
  const emailRegex = /^[\w-.]+@[\w-]+\.[a-zA-Z]{2,}$/;

  if (!email || !username || !password || !confirmPassword)
    return res.render('connection/register', { error: 'Tous les champs sont obligatoires.' });
  if (!emailRegex.test(email))
    return res.render('connection/register', { error: 'Format d\'email invalide.' });
  if (password !== confirmPassword)
    return res.render('connection/register', { error: 'Les mots de passe ne correspondent pas.' });

  try {
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) return res.render('connection/register', { error: 'Nom d\'utilisateur déjà utilisé.' });

    const existingEmail = await User.findOne({ where: { email } });
    if (existingEmail) return res.render('connection/register', { error: 'Email déjà utilisé.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    const user = await User.create({ email, username, password: hashedPassword, otp, otpExpires, active: false });
    await sendOtpEmail(email, otp);

    // JWT temporaire pour confirmer l’OTP
    const pendingToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'secret', { expiresIn: '15m' });
    res.cookie('pending_token', pendingToken, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000
    });

    res.redirect('/confirm-account');
  } catch (err) {
    res.render('connection/register', { error: 'Erreur serveur.' });
  }
});


// Page de saisie OTP
/* router.get('/confirm-account', (req, res) => {
  if (!req.session.pendingUserId) return res.redirect('/register');
  res.render('connection/confirm-account', { error: null });
}); */

router.get('/confirm-account', (req, res) => {
  if (!req.cookies.pending_token) return res.redirect('/register');
  res.render('connection/confirm-account', { error: null });
});


// Validation OTP
/* router.post('/confirm-account', async (req, res) => {
  const { otp } = req.body;
  const userId = req.session.pendingUserId;
  if (!userId) return res.redirect('/register');
  const user = await User.findByPk(userId);
  if (!user) return res.redirect('/register');
  if (!otp || otp !== user.otp || new Date() > user.otpExpires) {
    return res.render('connection/confirm-account', { error: 'Code OTP invalide ou expiré.' });
  }
  user.active = true;
  user.otp = null;
  user.otpExpires = null;
  await user.save();
  delete req.session.pendingUserId;
  res.redirect('/login');
});
 */

router.post('/confirm-account', async (req, res) => {
  const { otp } = req.body;
  const token = req.cookies.pending_token;
  if (!token) return res.redirect('/register');

  try {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const user = await User.findByPk(userId);
    if (!user) return res.redirect('/register');

    if (!otp || otp !== user.otp || new Date() > user.otpExpires) {
      return res.render('connection/confirm-account', { error: 'Code OTP invalide ou expiré.' });
    }

    user.active = true;
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.clearCookie('pending_token');
    res.redirect('/login');
  } catch (err) {
    res.clearCookie('pending_token');
    res.redirect('/register');
  }
});

// Déconnexion
/* router.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/');
    }
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});
 */

router.get('/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.redirect('/login');
});

// Traitement demande de reset (JWT)
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  // Vérification de présence
  if (!email) {
    return res.render('connection/forgot-password', {
      error: 'Veuillez saisir votre email.',
      success: null
    });
  }

  // Vérification du format email
  if (!emailRegex.test(email)) {
    return res.render('connection/forgot-password', {
      error: 'Adresse email invalide.',
      success: null
    });
  }

  // Vérifier si l'utilisateur existe
  const user = await User.findOne({ where: { email } });
  if (!user) {
    return res.render('connection/forgot-password', {
      error: 'Aucun compte avec cet email.',
      success: null
    });
  }

  // Générer un token JWT
  const token = jwt.sign(
    { userId: user.id },
    process.env.JWT_SECRET || 'reset_secret',
    { expiresIn: '1h' }
  );

  // Construire le lien de réinitialisation
  const resetLink = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password/${token}`;

  // Envoyer l'email
  await sendResetEmail(email, resetLink);

  res.render('connection/forgot-password', {
    error: null,
    success: 'Un email de réinitialisation a été envoyé.'
  });
});


// Page de saisie du nouveau mot de passe (JWT)
router.get('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'reset_secret');
    res.render('connection/reset-password', { error: null, token });
  } catch (err) {
    res.render('connection/reset-password', { error: 'Lien invalide ou expiré.', token: null });
  }
});

// Traitement du nouveau mot de passe (JWT)
router.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;
  if (!password || !confirmPassword) return res.render('connection/reset-password', { error: 'Tous les champs sont obligatoires.', token });
  if (password !== confirmPassword) return res.render('connection/reset-password', { error: 'Les mots de passe ne correspondent pas.', token });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'reset_secret');
    const user = await User.findByPk(decoded.userId);
    if (!user) return res.render('connection/reset-password', { error: 'Utilisateur introuvable.', token: null });
    user.password = await bcrypt.hash(password, 10);
    await user.save();
    res.redirect('/login');
  } catch (err) {
    res.render('connection/reset-password', { error: 'Lien invalide ou expiré.', token: null });
  }
});

module.exports = router;

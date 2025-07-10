const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { User } = require('../models/users');
const { sendOtpEmail } = require('../utils/otp');
const { sendResetEmail } = require('../utils/emails');

router.use(cookieParser());

// GET: Pages de connexion / inscription / mot de passe oublié
router.get('/login', (req, res) => res.render('connection/login'));
router.get('/register', (req, res) => res.render('connection/register'));
router.get('/forgot-password', (req, res) => res.render('connection/forgot-password', { error: null, success: null }));

// POST: Connexion avec JWT
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ where: { username } });
    if (!user) return res.render('connection/login', { error: 'Utilisateur non trouvé.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.render('connection/login', { error: 'Mot de passe incorrect.' });

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '1h' }
    );

    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000
    });

    res.redirect('/');
  } catch {
    res.render('connection/login', { error: 'Erreur serveur.' });
  }
});

// POST: Inscription + envoi OTP
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
    if (await User.findOne({ where: { username } }))
      return res.render('connection/register', { error: 'Nom d\'utilisateur déjà utilisé.' });
    if (await User.findOne({ where: { email } }))
      return res.render('connection/register', { error: 'Email déjà utilisé.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    const user = await User.create({ email, username, password: hashedPassword, otp, otpExpires, active: false });
    await sendOtpEmail(email, otp);

    const pendingToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'secret', { expiresIn: '15m' });
    res.cookie('pending_token', pendingToken, { httpOnly: true, maxAge: 15 * 60 * 1000 });
    res.redirect('/confirm-account');
  } catch {
    res.render('connection/register', { error: 'Erreur serveur.' });
  }
});

// GET: Confirmation OTP
router.get('/confirm-account', (req, res) => {
  if (!req.cookies.pending_token) return res.redirect('/register');
  res.render('connection/confirm-account', { error: null });
});

// POST: Validation OTP
router.post('/confirm-account', async (req, res) => {
  const { otp } = req.body;
  const token = req.cookies.pending_token;
  if (!token) return res.redirect('/register');

  try {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const user = await User.findByPk(userId);
    if (!user || otp !== user.otp || new Date() > user.otpExpires)
      return res.render('connection/confirm-account', { error: 'Code OTP invalide ou expiré.' });

    user.active = true;
    user.otp = null;
    user.otpExpires = null;
    await user.save();
    res.clearCookie('pending_token');
    res.redirect('/login');
  } catch {
    res.clearCookie('pending_token');
    res.redirect('/register');
  }
});

// GET: Déconnexion
router.get('/logout', (req, res) => {
  res.clearCookie('auth_token'); // Remove the JWT cookie

  // If using sessions, destroy it
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        console.error('Erreur de destruction de session :', err);
      }
    });
  }

  res.redirect('/login'); // or any other route
});

// POST: Forgot password (envoi lien)
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!email)
    return res.render('connection/forgot-password', { error: 'Veuillez saisir votre email.', success: null });
  if (!emailRegex.test(email))
    return res.render('connection/forgot-password', { error: 'Adresse email invalide.', success: null });

  const user = await User.findOne({ where: { email } });
  if (!user)
    return res.render('connection/forgot-password', { error: 'Aucun compte avec cet email.', success: null });

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'reset_secret', { expiresIn: '1h' });
  const resetLink = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password/${token}`;
  await sendResetEmail(email, resetLink);
  res.render('connection/forgot-password', { error: null, success: 'Un email de réinitialisation a été envoyé.' });
});

// GET: Page reset password
router.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;
  try {
    jwt.verify(token, process.env.JWT_SECRET || 'reset_secret');
    res.render('connection/reset-password', { error: null, token });
  } catch {
    res.render('connection/reset-password', { error: 'Lien invalide ou expiré.', token: null });
  }
});

// POST: Réinitialisation mot de passe
router.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (!password || !confirmPassword)
    return res.render('connection/reset-password', { error: 'Tous les champs sont obligatoires.', token });
  if (password !== confirmPassword)
    return res.render('connection/reset-password', { error: 'Les mots de passe ne correspondent pas.', token });

  try {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET || 'reset_secret');
    const user = await User.findByPk(userId);
    if (!user)
      return res.render('connection/reset-password', { error: 'Utilisateur introuvable.', token: null });

    user.password = await bcrypt.hash(password, 10);
    await user.save();
    res.redirect('/login');
  } catch {
    res.render('connection/reset-password', { error: 'Lien invalide ou expiré.', token: null });
  }
});

module.exports = router;

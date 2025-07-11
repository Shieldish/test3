const express = require('express');
const axios = require('axios');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { User } = require('../models/users');
const { sendOtpEmail } = require('../utils/otp');
const { sendResetEmail } = require('../utils/emails');

router.use(cookieParser());

/* --------------------- AUTH PAGES --------------------- */

// GET: Custom login / register / forgot-password
router.get('/login', (req, res) => res.render('connection/login', { error: null }));
router.get('/register', (req, res) => res.render('connection/register', { error: null }));
router.get('/forgot-password', (req, res) => res.render('connection/forgot-password', { error: null, success: null }));

/* --------------------- CUSTOM LOGIN --------------------- */

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Request token from Keycloak using ROPC flow
    const tokenResponse = await axios.post(
      'http://localhost:8090/realms/myapp/protocol/openid-connect/token',
      new URLSearchParams({
        grant_type: 'password',
        client_id: 'node-app',
        client_secret: 'hqxLbotT0kdM6UJuTu5mArUTl4Bwt0Tz',
        username:email,
        password
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token } = tokenResponse.data;

    // Store the token in a secure cookie
    res.cookie('auth_token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000 // 1 hour
    });

    res.redirect('/');
  }catch (err) {
  console.error('Keycloak login error:', err.response?.data || err.message);
  const message = err.response?.data?.error_description || 'Erreur de connexion.';
  res.render('connection/login', { error: message });
}

});

/* --------------------- KEYCLOAK REGISTRATION --------------------- */

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
    // 1. Get admin token to create user
    const tokenRes = await axios.post(
      'http://localhost:8090/realms/master/protocol/openid-connect/token',
      new URLSearchParams({
        grant_type: 'password',
        client_id: 'admin-cli',
        username: 'admin', // Keycloak admin
        password: 'admin'  // Keycloak admin password
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const adminToken = tokenRes.data.access_token;

   await axios.post(
  'http://localhost:8090/admin/realms/myapp/users',
  {
    username,
    email,
    enabled: true,
    emailVerified: false,
    credentials: [{
      type: 'password',
      value: password,
      temporary: false
    }],
    requiredActions: [] // Make sure it's empty
  },
  {
    headers: {
      Authorization: `Bearer ${adminToken}`,
      'Content-Type': 'application/json'
    }
  }
);



    res.redirect('/login');
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.render('connection/register', {
      error: 'Erreur lors de la création du compte (peut-être utilisateur ou email déjà existant).'
    });
  }
});
 */
router.post('/register', async (req, res) => {
  const { email, username, password, confirmPassword } = req.body;
  const emailRegex = /^[\w-.]+@[\w-]+\.[a-zA-Z]{2,}$/;

  // Vérification des champs obligatoires
  if (!email || !username || !password || !confirmPassword ) {
    return res.render('connection/register', { error: 'Tous les champs sont obligatoires.' });
  }

  // Validation email
  if (!emailRegex.test(email)) {
    return res.render('connection/register', { error: 'Format d\'email invalide.' });
  }

  // Vérification des mots de passe
  if (password !== confirmPassword) {
    return res.render('connection/register', { error: 'Les mots de passe ne correspondent pas.' });
  }

  try {
    // Obtenir un token d'admin Keycloak
    const tokenRes = await axios.post(
      'http://localhost:8090/realms/master/protocol/openid-connect/token',
      new URLSearchParams({
        grant_type: 'password',
        client_id: 'admin-cli',
        username: 'admin',
        password: 'admin'
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const adminToken = tokenRes.data.access_token;

    // Création de l'utilisateur dans Keycloak
    await axios.post(
      'http://localhost:8090/admin/realms/myapp/users',
      {
        username,
        email,
        firstName :username,
        lastName:username,
        enabled: true,
        emailVerified: false,
        credentials: [{
          type: 'password',
          value: password,
          temporary: false
        }],
        requiredActions: []
      },
      {
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    res.redirect('/login');
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.render('connection/register', {
      error: 'Erreur lors de la création du compte (peut-être utilisateur ou email déjà existant).'
    });
  }
});

/* --------------------- CONFIRMATION OTP (if using local user DB) --------------------- */

router.get('/confirm-account', (req, res) => {
  if (!req.cookies.pending_token) return res.redirect('/register');
  res.render('connection/confirm-account', { error: null });
});

router.post('/confirm-account', async (req, res) => {
  const { otp } = req.body;
  const token = req.cookies.pending_token;
  if (!token) return res.redirect('/register');

  try {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const user = await User.findByPk(userId);
    if (!user || otp !== user.otp || new Date() > user.otpExpires) {
      return res.render('connection/confirm-account', { error: 'Code OTP invalide ou expiré.' });
    }

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

/* --------------------- LOGOUT --------------------- */

router.get('/logout', (req, res) => {
  res.clearCookie('auth_token');
  if (req.session) {
    req.session.destroy(err => {
      if (err) console.error('Erreur session :', err);
    });
  }
  res.redirect('/login');
});

/* --------------------- FORGOT PASSWORD / RESET --------------------- */

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

router.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;
  try {
    jwt.verify(token, process.env.JWT_SECRET || 'reset_secret');
    res.render('connection/reset-password', { error: null, token });
  } catch {
    res.render('connection/reset-password', { error: 'Lien invalide ou expiré.', token: null });
  }
});

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

router.get('/oauth/callback', async (req, res) => {
  const { code } = req.query;

  if (!code) return res.redirect('/login');

  try {
    const tokenRes = await axios.post(
      'http://localhost:8090/realms/myapp/protocol/openid-connect/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://localhost:3000/oauth/callback',
        client_id: 'node-app',
        client_secret: 'hqxLbotT0kdM6UJuTu5mArUTl4Bwt0Tz'
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );

    const { access_token } = tokenRes.data;

    // Tu peux stocker le token dans un cookie sécurisé
    res.cookie('auth_token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000
    });

    res.redirect('/');
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.redirect('/login');
  }
});



module.exports = router;

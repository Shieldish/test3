const express = require('express');
const router = express.Router();
const { ensureAuthenticated } = require('../middlewares/auth');
const { keycloak } = require('../keycloak-config');

// Accueil (auth classique - session)
router.get('/', ensureAuthenticated, (req, res) => {
  res.render('index', {
    nom: req.session?.user?.username || 'Visiteur',
    page: 'index'
  });
});

router.get('/home', ensureAuthenticated, (req, res) => {
  res.render('index', {
    nom: req.session?.user?.username || 'Visiteur',
    page: 'index'
  });
});

// À propos - accessible sans être connecté
router.get('/about', (req, res) => {
  res.render('about', { nom: null });
});

// SSO : profil utilisateur connecté via Keycloak
router.get('/profile', keycloak.protect(), (req, res) => {
  const nom = req.kauth?.grant?.access_token?.content?.preferred_username || 'SSO';
  res.render('profiles', { nom, page: 'profile' });
});

router.get('/settings', keycloak.protect(), (req, res) => {
  const nom = req.kauth?.grant?.access_token?.content?.preferred_username || 'SSO';
  res.render('settings', { nom, page: 'settings' });
});

router.get('/tableau', keycloak.protect(), (req, res) => {
  const nom = req.kauth?.grant?.access_token?.content?.preferred_username || 'SSO';
  res.render('tableau', { nom, page: 'tableau' });
});

router.get('/abouts', keycloak.protect(), (req, res) => {
  const nom = req.kauth?.grant?.access_token?.content?.preferred_username || 'SSO';
  res.render('abouts', { nom, page: 'abouts' });
});

// Exemple d'affichage de données utilisateur (SSO)
router.get('/private', keycloak.protect(), (req, res) => {
  const user = req.kauth?.grant?.access_token?.content;
  res.send(`Bonjour ${user?.preferred_username}, votre email est ${user?.email}`);
});

module.exports = router;

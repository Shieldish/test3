const express = require('express');
const router = express.Router();
const { ensureAuthenticated } = require('../middlewares/auth');

// Accueil (authentification personnalisée avec access_token)
router.get('/', ensureAuthenticated, (req, res) => {
  res.render('index', {
    nom: req.user?.preferred_username || 'Visiteur',
    page: 'index'
  });
});

router.get('/home', ensureAuthenticated, (req, res) => {
  res.render('index', {
    nom: req.user?.preferred_username || 'Visiteur',
    page: 'index'
  });
});

// À propos - accessible sans authentification
router.get('/about', (req, res) => {
  res.render('about', { nom: null });
});

// Profil utilisateur
router.get('/profile', ensureAuthenticated, (req, res) => {
  res.render('profiles', {
    nom: req.user?.preferred_username || 'Profil',
    page: 'profile'
  });
});

router.get('/settings', ensureAuthenticated, (req, res) => {
  res.render('settings', {
    nom: req.user?.preferred_username || 'Settings',
    page: 'settings'
  });
});

router.get('/tableau', ensureAuthenticated, (req, res) => {
  res.render('tableau', {
    nom: req.user?.preferred_username || 'Tableau',
    page: 'tableau'
  });
});

router.get('/abouts', ensureAuthenticated, (req, res) => {
  res.render('abouts', {
    nom: req.user?.preferred_username || 'À propos',
    page: 'abouts'
  });
});

// Exemple affichage infos utilisateur
router.get('/private', ensureAuthenticated, (req, res) => {
  const user = req.user;
  res.send(`Bonjour ${user?.preferred_username}, votre email est ${user?.email}`);
});

module.exports = router;

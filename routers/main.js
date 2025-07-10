const express = require('express');
const router = express.Router();
const { ensureAuthenticated } = require('../middlewares/auth');

// Accueil (tableau de bord)
router.get('/', ensureAuthenticated, (req, res) => {
  res.render('index', { nom: req.user?.username, page: 'tableau' });
});

// About (accessible sans auth)
router.get('/about', (req, res) => {
  // Ici pas de user, donc on peut mettre nom à null ou vide si pas connecté
  res.render('about', { nom: null });
});

// Profile
router.get('/profile', ensureAuthenticated, (req, res) => {
  res.render('profiles', { nom: req.user?.username, page: 'profile' });
});

// Settings
router.get('/settings', ensureAuthenticated, (req, res) => {
  res.render('settings', { nom: req.user?.username, page: 'settings' });
});

// Tableau
router.get('/tableau', ensureAuthenticated, (req, res) => {
  res.render('tableau', { nom: req.user?.username, page: 'tableau' });
});

// Abouts
router.get('/abouts', ensureAuthenticated, (req, res) => {
  res.render('abouts', { nom: req.user?.username, page: 'abouts' });
});

module.exports = router;

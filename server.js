require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { keycloak, memoryStore } = require('./keycloak-config');
const authRouter = require('./routers/authentification');
const mainRouter = require('./routers/main');

const app = express();

// Middlewares
app.use(cookieParser());
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Session configuration (used for Keycloak logout/admin if needed)
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret',
  resave: false,
  saveUninitialized: true,
  store: memoryStore
}));

// Initialize Keycloak middleware (for admin/logout support)
/* app.use(keycloak.middleware({
  logout: '/logout',
  admin: '/admin',
}));
 */
// Set view engine to EJS
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// Register routes
app.use('/', mainRouter);       // Uses ensureAuthenticated for protected pages
app.use('/', authRouter);       // Handles login, register, forgot-pSassword, etc.

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running at: http://localhost:${PORT}`);
});

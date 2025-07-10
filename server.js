require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { ensureAuthenticated } = require('./middlewares/auth');
const { User } = require('./models/users');
const bcrypt = require('bcrypt');
const { sendOtpEmail } = require('./utils/otp');
const authRouter = require('./routers/authentification');
const mainRouter = require('./routers/main');
const { keycloak, memoryStore } = require('./keycloak-config');


const app = express();

const cookieParser = require('cookie-parser');
app.use(cookieParser());


app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));


app.use(session({
  secret: 'some secret',
  resave: false,
  saveUninitialized: true,
  store: memoryStore
}));

// Initialise Keycloak
 app.use(keycloak.middleware({
  logout: '/logout',
  admin: '/admin',
})); 

/* app.get('/logout', (req, res) => {
  // Clear your custom JWT cookie
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax'
  });

});
 */

/* app.use(session({
  secret: process.env.SESSION_SECRET || 'votre_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 60 * 60 * 1000 }
})); */


// Configuration de EJS
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

app.use('/', mainRouter);
app.use('/', authRouter);




// Middleware pour protéger des routes
const protect = keycloak.protect();


const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
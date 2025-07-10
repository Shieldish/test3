require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { ensureAuthenticated } = require('./middlewares/auth');
const { User } = require('./models/users');
const bcrypt = require('bcrypt');
const { sendOtpEmail } = require('./utils/otp');
const authRouter = require('./routers/authentification');
const mainRouter = require('./routers/main');



const app = express();

const cookieParser = require('cookie-parser');
app.use(cookieParser());


app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'votre_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 60 * 60 * 1000 }
}));


// Configuration de EJS
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

app.use('/', mainRouter);
app.use('/', authRouter);



const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
# 🔐 Node.js Auth App (JWT + EJS + PostgreSQL/MySQL)

Une application Node.js complète avec :

* Authentification par JWT
* Interfaces EJS (login, inscription, profil…)
* Réinitialisation du mot de passe par email
* PostgreSQL ou MySQL avec Sequelize ORM
* Middleware de protection de routes
* Gestion OTP pour activer un compte

---

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/Shieldish/test3
cd test3
```

### 2. Installer les dépendances

```bash
npm install
```

### 3. Créer un fichier `.env`

```env
# Base de données
DB_HOST=localhost
DB_USER=root
DB_PASS=motdepasse
DB_NAME=auth_db
DB_DIALECT=mysql

# JWT
JWT_SECRET=super_secret_key

# SMTP (pour l'envoi d'email)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=votre@email.com
SMTP_PASS=motdepasse
SMTP_FROM="Mon App <noreply@monapp.com>"

# App
APP_URL=http://localhost:3000
SESSION_SECRET=session_secret
NODE_ENV=development
```

> Adapte les valeurs à ton environnement (MySQL ou PostgreSQL).

---

## ⚙️ Lancer l'application

```bash
npm start
```

L'application sera disponible sur [http://localhost:3000](http://localhost:3000)

---

## 📁 Structure du projet

```
.
├── app.js                  # Fichier principal Express
├── routes/
│   └── auth.js             # Routes login / register / forgot-password
│   └── main.js             # Routes principales (dashboard, profil…)
├── middlewares/
│   └── auth.js             # Middleware de protection par JWT
├── models/
│   └── users.js            # Modèle Sequelize User
├── utils/
│   └── emails.js           # Envoi d'email (reset password)
│   └── otp.js              # Envoi d'email OTP
├── views/
│   └── connection/         # login, register, forgot-password, etc.
│   └── index.ejs           # Page d'accueil
├── public/                 # Fichiers statiques (CSS, images)
└── .env                    # Variables d'environnement
```

---

## ✉️ Fonctionnalités

* ✅ Authentification avec JWT
* ✅ Cookies sécurisés (httpOnly)
* ✅ Activation de compte via OTP par email
* ✅ Réinitialisation de mot de passe par lien unique
* ✅ Interface utilisateur responsive en EJS
* ✅ Protection des routes avec middleware `ensureAuthenticated`

---

## 🧪 Tests manuels

* [x] Crée un compte
* [x] Reçois l’OTP
* [x] Valide le compte
* [x] Connecte-toi
* [x] Accède aux pages protégées
* [x] Utilise “Mot de passe oublié” pour recevoir un email

---

## 🛠 Dépendances principales

* `express`
* `jsonwebtoken`
* `bcrypt`
* `ejs`
* `sequelize` (ORM)
* `pg` / `mysql2`
* `nodemailer`
* `cookie-parser`
* `dotenv`

---

## 📄 Licence

Ce projet est libre pour un usage éducatif ou personnel.

---

## 🙇‍♂️ Auteur

Samuel GABIAM – 🇹🇳

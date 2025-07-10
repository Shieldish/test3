const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

/**
 * Envoie un email contenant un lien de réinitialisation
 * @param {string} to - Adresse email du destinataire
 * @param {string} resetLink - Lien de réinitialisation
 */
async function sendResetEmail(to, resetLink) {
  const html = `
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://fonts.googleapis.com/css?family=Roboto:400,700&display=swap" rel="stylesheet">
        <style>
          body { background: #f4f6fb; font-family: 'Roboto', Arial, sans-serif; margin: 0; padding: 0; }
          .card {
            max-width: 400px;
            margin: 40px auto;
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.08);
            padding: 32px 24px;
            text-align: center;
            animation: fadeIn 1.2s;
          }
          h2 { color: #2a3b8f; margin-bottom: 12px; }
          .info { color: #555; margin-bottom: 18px; }
          .btn {
            display: inline-block;
            background: #2a3b8f;
            color: #fff !important;
            padding: 12px 32px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 700;
            margin-top: 18px;
            font-size: 1.1em;
            transition: background 0.2s;
          }
          .btn:hover { background: #4f8cff; }
          @keyframes fadeIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
          }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Réinitialisation de votre mot de passe</h2>
          <div class="info">
            Vous avez demandé à réinitialiser votre mot de passe.<br>
            Cliquez sur le bouton ci-dessous pour choisir un nouveau mot de passe :
          </div>
          <a class="btn" href="${resetLink}">Réinitialiser mon mot de passe</a>
          <div style="margin-top:24px; color:#aaa; font-size:0.95em;">
            Ce lien est valable 1 heure.<br>
            Si vous n’êtes pas à l’origine de cette demande, ignorez cet email.
          </div>
        </div>
      </body>
    </html>
  `;

  const mailOptions = {
    from: process.env.SMTP_FROM || 'no-reply@example.com',
    to,
    subject: '🔐 Réinitialisation de votre mot de passe',
    html,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Email de réinitialisation envoyé à ${to}`);
  } catch (err) {
    console.error(`Erreur lors de l'envoi de l'email à ${to}:`, err);
  }
}

module.exports = { sendResetEmail };

const nodemailer = require('nodemailer');

// Transporteur SMTP configuré via les variables d'environnement
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_SECURE === 'true', // true pour 465, false pour autres ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

/**
 * Envoie un email contenant un OTP à l'utilisateur
 * @param {string} to - Adresse email du destinataire
 * @param {string} otp - Code OTP à envoyer
 */
async function sendOtpEmail(to, otp) {
  const mailOptions = {
    from: process.env.SMTP_FROM || 'no-reply@example.com',
    to,
    subject: 'Votre code d’activation (OTP)',
    html: `
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
          .otp {
            display: inline-block;
            font-size: 2.2rem;
            letter-spacing: 0.3em;
            background: linear-gradient(90deg, #2a3b8f 30%, #4f8cff 100%);
            color: #fff;
            border-radius: 8px;
            padding: 12px 24px;
            margin: 18px 0 12px 0;
            font-weight: bold;
            box-shadow: 0 2px 8px rgba(44, 62, 80, 0.08);
            animation: fadeOtp 1.2s;
          }
          .info { color: #555; margin-bottom: 18px; }
          .btn {
            display: inline-block;
            background: #2a3b8f;
            color: #fff !important;
            padding: 10px 28px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 700;
            margin-top: 10px;
            transition: background 0.2s;
          }
          .btn:hover { background: #4f8cff; }
          @keyframes fadeIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
          }
          @keyframes fadeOtp {
            0% { opacity: 0; transform: scale(0.7); }
            60% { opacity: 1; transform: scale(1.1); }
            100% { opacity: 1; transform: scale(1); }
          }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Activation de votre compte</h2>
          <div class="info">Merci de vous être inscrit. Voici votre code d’activation :</div>
          <div class="otp">${otp}</div>
          <div class="info">Ce code est valable 10 minutes.<br>Ne le partagez à personne.</div>
          <a class="btn" href="#" style="pointer-events:none;">Activer mon compte</a>
          <div style="margin-top:24px; color:#aaa; font-size:0.95em;">Si vous n’êtes pas à l’origine de cette demande, ignorez cet email.</div>
        </div>
      </body>
    </html>
    `,
  };
  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP envoyé à ${to}`);
  } catch (err) {
    console.error(`Erreur lors de l'envoi de l'OTP à ${to}:`, err);
  }
}

module.exports = { sendOtpEmail };
// db.js
require('dotenv').config();
const { Client } = require('pg');

const client = new Client({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

client.connect()
  .then(() => console.log('Connecté à PostgreSQL !'))
  .catch(err => console.error('Erreur de connexion', err.stack));

module.exports = client;

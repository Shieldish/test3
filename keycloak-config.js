// keycloak-config.js
const session = require('express-session');
const Keycloak = require('keycloak-connect');

const memoryStore = new session.MemoryStore();

const keycloak = new Keycloak({ store: memoryStore }, {
  realm: 'myapp', // Nom du Realm créé dans Keycloak
  'auth-server-url': 'http://localhost:8090', // Sans /auth depuis les dernières versions
  'ssl-required': 'external',
  resource: 'node-app', // Client ID
  credentials: {
    secret: 'hqxLbotT0kdM6UJuTu5mArUTl4Bwt0Tz' // Copie le secret depuis Keycloak > Clients > node-app > Credentials
  },
  'confidential-port': 0
});

module.exports = { keycloak, memoryStore };

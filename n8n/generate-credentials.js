// n8n/generate-credentials.js
//
// Génère le JSON de credentials n8n (format attendu par `n8n import:credentials`)
// à partir des variables d'environnement chargées depuis api/.env (env_file
// du service n8n dans docker-compose.yml).
//
// ⚠️ CONSTATÉ EN PRODUCTION : `n8n import:credentials` sur un ID déjà présent
// en base NE MET PAS À JOUR la valeur déchiffrée utilisée à l'exécution — le
// CLI répond "Successfully imported" à chaque fois (aucune erreur visible),
// mais le nœud HTTP continue d'envoyer l'ANCIEN mot de passe et échoue en
// 401 côté API, même après un restart complet de n8n. Si ADMIN_PASSWORD_PLAIN
// (ou toute autre valeur d'une credential déjà provisionnée) change,
// **changer aussi son ID ci-dessous** pour forcer une insertion neuve plutôt
// que de compter sur une mise à jour in-place.
//
// Les IDs fixes ci-dessous DOIVENT correspondre aux placeholders
// __CRED_POSTGRES_ID__ / __CRED_OLLAMA_ID__ / __CRED_API_BASICAUTH_ID__
// substitués dans n8n/workflows/*.json par provision-and-start.sh.
const fs = require('fs');

const outputPath = process.argv[2];
if (!outputPath) {
  console.error('[provision] Usage: node generate-credentials.js <output.json>');
  process.exit(1);
}

const creds = [];

if (process.env.POSTGRES_USER && process.env.POSTGRES_DB) {
  creds.push({
    id: 'reconiaPostgresAuto',
    name: 'Postgres recon-ia (auto)',
    type: 'postgres',
    data: {
      host: 'postgres',
      database: process.env.POSTGRES_DB,
      user: process.env.POSTGRES_USER,
      password: process.env.POSTGRES_PASSWORD || '',
      port: 5432,
      ssl: 'disable',
    },
  });
} else {
  console.log('[provision] POSTGRES_USER/POSTGRES_DB absents — credential postgres NON provisionnée.');
}

creds.push({
  id: 'reconiaOllamaAuto',
  name: 'Ollama account (auto)',
  type: 'ollamaApi',
  data: {
    baseUrl: 'http://ollama:11434',
  },
});

if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD_PLAIN) {
  creds.push({
    id: 'reconiaApiBasicAuthAutoV2',
    name: 'Recon IA API account (auto)',
    type: 'httpBasicAuth',
    data: {
      user: process.env.ADMIN_EMAIL,
      password: process.env.ADMIN_PASSWORD_PLAIN,
    },
  });
} else {
  console.log(
    '[provision] ADMIN_EMAIL/ADMIN_PASSWORD_PLAIN absents — credential httpBasicAuth NON ' +
    'provisionnée. Les nœuds HTTP Request du workflow principal resteront sans credential ' +
    'valide tant qu\'elle n\'est pas créée (renseigner ADMIN_PASSWORD_PLAIN dans api/.env, ou ' +
    'créer la credential à la main dans n8n).'
  );
}

fs.writeFileSync(outputPath, JSON.stringify(creds, null, 2));
console.log(`[provision] ${creds.length} credential(s) écrite(s) dans ${outputPath}`);

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
// 401 côté API, même après un restart complet de n8n. Si PIPELINE_SERVICE_TOKEN
// (ou toute autre valeur d'une credential déjà provisionnée) change,
// **changer aussi son ID ci-dessous** pour forcer une insertion neuve plutôt
// que de compter sur une mise à jour in-place.
//
// Les IDs fixes ci-dessous DOIVENT correspondre aux placeholders
// __CRED_POSTGRES_ID__ / __CRED_OLLAMA_ID__ / __CRED_API_SERVICE_ID__ /
// __CRED_WEBHOOK_SECRET_ID__
// substitués dans n8n/workflows/*.json par provision-and-start.sh.
const fs = require('fs');

const outputPath = process.argv[2];
if (!outputPath) {
  console.error('[provision] Usage: node generate-credentials.js <output.json>');
  process.exit(1);
}

const creds = [];

// Credential Postgres du workflow RAG : rôle `rag_writer` à droits minimaux
// (créé par api/migrate.py, accès à rag_documents UNIQUEMENT) — n8n ne reçoit
// plus le mot de passe du compte propriétaire de la base (2026-10-19).
// Nouvel ID (…V2) : import:credentials ne met pas à jour une valeur existante.
if (process.env.RAG_DB_PASSWORD && process.env.POSTGRES_DB) {
  creds.push({
    id: 'reconiaPostgresRagWriterV2',
    name: 'Postgres recon-ia rag_writer (auto)',
    type: 'postgres',
    data: {
      host: 'postgres',
      database: process.env.POSTGRES_DB,
      user: process.env.RAG_DB_USER || 'rag_writer',
      password: process.env.RAG_DB_PASSWORD,
      port: 5432,
      ssl: 'disable',
    },
  });
} else {
  console.log('[provision] RAG_DB_PASSWORD/POSTGRES_DB absents — credential postgres NON provisionnée ' +
    '(workflow RAG inutilisable).');
}

creds.push({
  id: 'reconiaOllamaAuto',
  name: 'Ollama account (auto)',
  type: 'ollamaApi',
  data: {
    baseUrl: 'http://ollama:11434',
  },
});

// Jeton de service de l'API (2026-10-19) — remplace l'ancienne credential
// httpBasicAuth qui embarquait le mot de passe ADMIN en clair. Accepté
// uniquement par les routes du pipeline (api/utils/auth.py
// ::require_service_or_auth), jamais par les routes d'administration.
if ((process.env.PIPELINE_SERVICE_TOKEN || '').length >= 32) {
  creds.push({
    id: 'reconiaApiServiceTokenAutoV1',
    name: 'Recon IA API service token (auto)',
    type: 'httpHeaderAuth',
    data: { name: 'X-Service-Token', value: process.env.PIPELINE_SERVICE_TOKEN },
  });
} else {
  console.log('[provision] PIPELINE_SERVICE_TOKEN absent ou < 32 caractères — les nœuds du ' +
    "pipeline ne pourront pas appeler l'API.");
}

// Secret du webhook déclenché par l'API (api/utils/pipeline_trigger.py) :
// le nœud Webhook refuse toute requête sans cet en-tête.
if ((process.env.N8N_WEBHOOK_SECRET || '').length >= 32) {
  creds.push({
    id: 'reconiaWebhookSecretAutoV1',
    name: 'Recon IA webhook secret (auto)',
    type: 'httpHeaderAuth',
    data: { name: 'X-Pipeline-Secret', value: process.env.N8N_WEBHOOK_SECRET },
  });
} else {
  console.log('[provision] N8N_WEBHOOK_SECRET absent ou < 32 caractères — le webhook du ' +
    'pipeline restera sans authentification valide et refusera les déclenchements.');
}

fs.writeFileSync(outputPath, JSON.stringify(creds, null, 2));
console.log(`[provision] ${creds.length} credential(s) écrite(s) dans ${outputPath}`);

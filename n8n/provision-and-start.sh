#!/bin/sh
# n8n/provision-and-start.sh
#
# Provisionne automatiquement les credentials et workflows recon-ia à chaque
# démarrage du conteneur n8n, puis démarre n8n normalement. Objectif :
# `docker compose up` seul suffit à obtenir une instance n8n prête à traiter
# une demande de génération de rapport, sans étape manuelle dans l'éditeur.
#
# Idempotent pour les WORKFLOWS (IDs fixes, `import:workflow` met bien à jour
# l'existant). PAS idempotent pour les CREDENTIALS : `import:credentials` sur
# un ID déjà présent n'actualise pas la valeur déchiffrée utilisée à
# l'exécution (constaté : mot de passe changé → toujours l'ancien envoyé,
# 401 côté API, même après restart complet). generate-credentials.js utilise
# donc un ID dédié par valeur (ex: `...AutoV2`) plutôt que de compter sur un
# upsert. Best-effort par ailleurs : un échec de provisioning n'empêche
# jamais n8n de démarrer (log un avertissement et continue).

WORKFLOWS_DIR="/workflows"
CRED_FILE="/tmp/recon-ia-credentials.json"

echo "=== [provision] Génération des credentials depuis l'environnement ==="
node /generate-credentials.js "$CRED_FILE" \
  && n8n import:credentials --input="$CRED_FILE" \
  || echo "=== [provision] AVERTISSEMENT : import des credentials échoué, on continue ==="
# $CRED_FILE contient des mots de passe en clair (Postgres, admin API) : ne
# doit pas traîner sur disque une fois importé dans le stockage chiffré n8n.
rm -f "$CRED_FILE"

echo "=== [provision] Import et activation des workflows ==="
# rag-ingestion : importé mais PAS auto-activé (voir CLAUDE.md §8) — son
# exécution complète (~5 Mo de corpus, 6 fichiers) se bloque de façon
# intermittente sur ce poste sans qu'aucune cause identifiable (I/O disque,
# verrou Postgres) n'explique le blocage une fois ces deux causes écartées.
# Le script ponctuel api/utils (voir data/ingest_rag.py, copié manuellement
# dans le conteneur api) reste le moyen fiable de peupler rag_documents en
# attendant un diagnostic plus poussé (à refaire sur le serveur de prod
# Linux, où les caractéristiques I/O diffèrent). Activer manuellement une
# fois le problème résolu : `n8n update:workflow --id=8481rbwSG3V1qzCT --active=true`.
for entry in "rag-ingestion:8481rbwSG3V1qzCT:false" "recon-ia-main:AdOmMwjGgxh9Ljm6:true"; do
  wf_file=$(echo "$entry" | cut -d: -f1)
  wf_id=$(echo "$entry" | cut -d: -f2)
  wf_activate=$(echo "$entry" | cut -d: -f3)
  src="$WORKFLOWS_DIR/$wf_file.json"

  if [ ! -f "$src" ]; then
    echo "=== [provision] AVERTISSEMENT : $src introuvable, on saute ce workflow ==="
    continue
  fi

  sed \
    -e "s/__CRED_POSTGRES_ID__/reconiaPostgresAuto/g" \
    -e "s/__CRED_OLLAMA_ID__/reconiaOllamaAuto/g" \
    -e "s/__CRED_API_BASICAUTH_ID__/reconiaApiBasicAuthAutoV2/g" \
    "$src" > "/tmp/$wf_file.json"

  n8n import:workflow --input="/tmp/$wf_file.json" \
    && n8n update:workflow --id="$wf_id" --active="$wf_activate" \
    || echo "=== [provision] AVERTISSEMENT : import/activation de $wf_file échoué, on continue ==="
  rm -f "/tmp/$wf_file.json"
done

echo "=== [provision] Terminé — démarrage de n8n ==="
exec /docker-entrypoint.sh

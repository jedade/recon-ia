#!/bin/bash

echo "### Synchronisation des certificats pour n8n..."
cp -L ./certbot/conf/live/n8n.idachallenge.bj/fullchain.pem ./n8n_certs/
cp -L ./certbot/conf/live/n8n.idachallenge.bj/privkey.pem ./n8n_certs/

echo "### Redémarrage de n8n..."
docker compose restart n8n

echo "### Synchronisation terminée"
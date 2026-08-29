#!/bin/bash

domains=(n8n.idachallenge.bj)
email="onesime.adefoulou@gmail.com"  # Remplacez par votre vrai email
rsa_key_size=4096
data_path="./certbot"

# Créer les répertoires nécessaires
mkdir -p "$data_path/conf" "$data_path/www"

# Télécharger les paramètres TLS recommandés
if [ ! -e "$data_path/conf/options-ssl-nginx.conf" ] || [ ! -e "$data_path/conf/ssl-dhparams.pem" ]; then
  echo "### Téléchargement des paramètres TLS ..."
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > "$data_path/conf/options-ssl-nginx.conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem > "$data_path/conf/ssl-dhparams.pem"
fi

# Démarrer Nginx temporairement
echo "### Démarrage de Nginx ..."
docker compose up --force-recreate -d nginx

# Demander le certificat
echo "### Demande de certificat Let's Encrypt ..."
docker compose run --rm --entrypoint "\
  certbot certonly --webroot -w /var/www/certbot \
    --email $email \
    -d ${domains[0]} \
    --rsa-key-size $rsa_key_size \
    --agree-tos \
    --noninteractive \
    --force-renewal" certbot

# Redémarrer Nginx avec les nouveaux certificats
echo "### Redémarrage de Nginx ..."
docker compose exec nginx nginx -s reload


echo "### Copie des certificats pour n8n..."
mkdir -p ./n8n_certs
cp -L ./certbot/conf/live/n8n.idachallenge.bj/fullchain.pem ./n8n_certs/
cp -L ./certbot/conf/live/n8n.idachallenge.bj/privkey.pem ./n8n_certs/

# Corriger les permissions
chmod 644 ./n8n_certs/fullchain.pem
chmod 600 ./n8n_certs/privkey.pem
chown -R $(id -u):$(id -g) ./n8n_certs

echo "### Certificats copiés dans ./n8n_certs"
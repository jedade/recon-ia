FROM docker.n8n.io/n8nio/n8n

USER root

# NOTE : l'image officielle n'embarque plus de gestionnaire de paquets (ni
# apt-get ni apk — image durcie). L'ancien `apt-get install bash whois` ne
# fonctionnait déjà plus (cette image n'a jamais été buildée avant, voir
# CLAUDE.md) et n'est pas requis par provision-and-start.sh (/bin/sh suffit).
# Si whois redevient nécessaire pour un workflow, prévoir un binaire statique
# copié depuis une image builder plutôt qu'un gestionnaire de paquets.

# Provisioning automatique des credentials/workflows recon-ia au démarrage
# (voir provision-and-start.sh) — remplace l'ancien entrypoint par un wrapper
# qui provisionne puis exec /docker-entrypoint.sh (comportement n8n normal).
COPY generate-credentials.js /generate-credentials.js
COPY provision-and-start.sh /provision-and-start.sh
RUN chmod +x /provision-and-start.sh

USER node

ENTRYPOINT ["tini", "--", "/provision-and-start.sh"]

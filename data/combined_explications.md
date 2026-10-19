# Explication — CAA — autorités de certification autorisées

Contrôle : caa · Catégorie : DNS · Outils Recon-IA : caa_check

## Pourquoi c'est important

L'enregistrement DNS CAA (Certification Authority Authorization) déclare quelles autorités de certification ont le droit d'émettre un certificat pour le domaine. Depuis 2017, toutes les autorités publiques doivent le vérifier avant émission. Le tag iodef permet en outre d'être averti d'une demande refusée.

## Risque

Sans CAA, n'importe laquelle des centaines d'autorités publiques peut émettre un certificat valide pour votre domaine. Une autorité moins rigoureuse ou un processus de validation contourné suffit alors à obtenir un certificat frauduleux, utilisable pour des attaques de l'homme du milieu ou des sites de hameçonnage crédibles.

## Comment corriger

1. Identifier les autorités réellement utilisées (y compris celles de votre CDN ou hébergeur).
2. Publier un enregistrement CAA « issue » par autorité autorisée, et « issuewild » si besoin de certificats génériques.
3. Ajouter un tag iodef avec une adresse de contact.
4. Mettre à jour l'enregistrement lors de tout changement de fournisseur de certificats.

## Exemple

```
exemple.bj. CAA 0 issue "letsencrypt.org"
exemple.bj. CAA 0 iodef "mailto:securite@exemple.bj"
```

## Références

- RFC 8659 — DNS Certification Authority Authorization (CAA) : https://www.rfc-editor.org/rfc/rfc8659
- CAPEC-459 — Creating a Rogue Certification Authority Certificate : https://capec.mitre.org/data/definitions/459.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — Certificat TLS — validité, expiration et noms couverts

Contrôle : certificat · Catégorie : TLS · Outils Recon-IA : ssl_info, crtsh

## Pourquoi c'est important

Le certificat prouve au visiteur qu'il parle bien au serveur du domaine. Il est émis par une autorité de certification, pour une liste de noms (SAN) et une durée limitée. Les journaux publics Certificate Transparency (consultés via crt.sh) recensent tous les certificats émis, ce qui révèle aussi les sous-domaines de l'organisation.

## Risque

Un certificat expiré, auto-signé ou ne couvrant pas le nom visité provoque des alertes que les utilisateurs apprennent à ignorer, ce qui facilite ensuite les attaques de l'homme du milieu. Une expiration non anticipée rend le service indisponible. Les certificats génériques (*.domaine) partagés entre de nombreux serveurs élargissent l'impact d'une fuite de clé privée.

## Comment corriger

1. Automatiser le renouvellement (ACME / Let's Encrypt ou équivalent) et surveiller les dates d'expiration.
2. Vérifier que le certificat couvre tous les noms servis et que la chaîne intermédiaire est complète.
3. Limiter l'usage des certificats génériques et protéger les clés privées.
4. Surveiller les journaux Certificate Transparency pour détecter une émission non autorisée.

## Références

- RFC 6962 — Certificate Transparency : https://www.rfc-editor.org/rfc/rfc6962
- CWE-298 — Improper Validation of Certificate Expiration : https://cwe.mitre.org/data/definitions/298.html
- CWE-295 — Improper Certificate Validation : https://cwe.mitre.org/data/definitions/295.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — Cookies — attributs Secure, HttpOnly et SameSite

Contrôle : cookies · Catégorie : Web · Outils Recon-IA : headers, security_headers, waf_detection

## Pourquoi c'est important

Les cookies portent souvent la session de l'utilisateur : qui possède le cookie possède la session. Trois attributs les protègent : Secure (envoi uniquement en HTTPS), HttpOnly (inaccessible au JavaScript de la page) et SameSite (non envoyé lors de requêtes initiées par un autre site). Les préfixes __Host- et __Secure- renforcent encore ces garanties.

## Risque

Un cookie de session sans Secure peut être lu sur un réseau non chiffré ; sans HttpOnly, il peut être volé par une faille XSS ; sans SameSite, il facilite les attaques CSRF (un site malveillant déclenche une action au nom de l'utilisateur connecté). Les noms de cookies révèlent aussi la technologie utilisée (PHPSESSID, JSESSIONID, ASP.NET_SessionId).

## Comment corriger

1. Poser Secure et HttpOnly sur tous les cookies de session et d'authentification.
2. Utiliser SameSite=Lax par défaut, Strict pour les cookies très sensibles.
3. Préférer le préfixe __Host- (Secure, Path=/, sans attribut Domain) pour le cookie de session.
4. Limiter la durée de vie des cookies et renouveler l'identifiant de session à la connexion.

## Exemple

```
Set-Cookie: __Host-session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax
```

## Références

- OWASP — Session Management Cheat Sheet : https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- CWE-614 — Sensitive Cookie in HTTPS Session Without Secure Attribute : https://cwe.mitre.org/data/definitions/614.html
- CWE-1004 — Sensitive Cookie Without HttpOnly Flag : https://cwe.mitre.org/data/definitions/1004.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — CSP — politique de sécurité du contenu

Contrôle : csp · Catégorie : Web · Outils Recon-IA : security_headers, http_observatory

## Pourquoi c'est important

L'en-tête Content-Security-Policy déclare au navigateur les origines autorisées pour les scripts, styles, images, cadres et connexions de la page. Tout ce qui n'est pas explicitement permis est bloqué. C'est la principale défense en profondeur contre l'exécution de code injecté dans une page.

## Risque

Sans CSP, une faille d'injection (XSS) ou un script tiers compromis (bibliothèque chargée depuis un CDN, widget publicitaire) peut exécuter n'importe quel code dans le navigateur des visiteurs : vol de session, saisie de formulaires détournée, redirection vers un faux site. Une CSP trop permissive (unsafe-inline, unsafe-eval, joker *) n'apporte presque aucune protection.

## Comment corriger

1. Commencer en mode observation avec Content-Security-Policy-Report-Only et une adresse de rapport.
2. Inventorier les ressources réellement chargées et construire une liste blanche minimale.
3. Éviter unsafe-inline et unsafe-eval : préférer des nonces ou des empreintes (hash) pour les scripts en ligne.
4. Ajouter frame-ancestors (protection contre le clickjacking), base-uri et object-src 'none'.
5. Basculer en mode bloquant une fois les rapports stabilisés.

## Exemple

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

## Références

- OWASP — Content Security Policy Cheat Sheet : https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- W3C — Content Security Policy Level 3 : https://www.w3.org/TR/CSP3/
- CWE-79 — Cross-site Scripting : https://cwe.mitre.org/data/definitions/79.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — DKIM — signature cryptographique des courriels

Contrôle : dkim · Catégorie : Messagerie · Outils Recon-IA : dkim_check

## Pourquoi c'est important

DKIM (DomainKeys Identified Mail) fait signer chaque courriel sortant par le serveur d'envoi ; la clé publique correspondante est publiée dans le DNS sous un sélecteur (selecteur._domainkey.votre-domaine). Le destinataire vérifie que le message n'a pas été modifié et qu'il a bien été émis par un serveur détenant la clé privée du domaine. C'est l'un des deux piliers sur lesquels DMARC s'appuie.

## Risque

Sans DKIM, l'authenticité des messages repose uniquement sur SPF, qui casse lors des transferts (redirections, listes de diffusion). DMARC échoue alors plus souvent pour du courrier légitime, ce qui pousse à rester en p=none. Une clé trop courte (RSA 1024 bits ou moins) peut être cassée et permettre de signer de faux messages. La détection passive ne teste que des sélecteurs courants : un sélecteur personnalisé peut échapper au contrôle.

## Comment corriger

1. Activer la signature DKIM chez chaque fournisseur d'envoi (Microsoft 365, Google Workspace, outil d'emailing).
2. Publier dans le DNS les clés publiques fournies, sous les sélecteurs indiqués.
3. Utiliser des clés RSA d'au moins 2048 bits (ou Ed25519 en complément).
4. Prévoir une rotation périodique des clés et révoquer (p= vide) les sélecteurs abandonnés.

## Exemple

```
selector1._domainkey.exemple.bj. TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqh..."
```

## Références

- RFC 6376 — DKIM Signatures : https://www.rfc-editor.org/rfc/rfc6376
- RFC 8301 — Cryptographic Algorithm and Key Usage Update to DKIM : https://www.rfc-editor.org/rfc/rfc8301

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — DMARC — politique anti-usurpation de l'expéditeur

Contrôle : dmarc · Catégorie : Messagerie · Outils Recon-IA : dmarc_check, email_config

## Pourquoi c'est important

DMARC (Domain-based Message Authentication, Reporting and Conformance) indique aux serveurs de messagerie destinataires ce qu'ils doivent faire d'un courriel qui prétend venir de votre domaine mais échoue aux contrôles SPF et DKIM. Il ajoute la notion d'alignement : le domaine visible par l'utilisateur dans le champ « From » doit correspondre au domaine validé par SPF ou DKIM. Il permet aussi de recevoir des rapports agrégés sur qui envoie du courrier en votre nom.

## Risque

Sans DMARC, ou avec une politique p=none, n'importe qui peut envoyer des courriels affichant votre domaine comme expéditeur : hameçonnage de vos clients, fraude au président, faux avis de paiement. Les destinataires n'ont aucune consigne pour rejeter ces messages, et vous n'avez aucune visibilité sur ces abus.

## Comment corriger

1. Vérifier d'abord que SPF et DKIM sont en place pour toutes vos sources d'envoi légitimes (serveur interne, Microsoft 365, Google Workspace, outil d'emailing, CRM).
2. Publier un enregistrement TXT sur _dmarc.votre-domaine avec p=none et une adresse rua= pour collecter les rapports pendant quelques semaines.
3. Analyser les rapports et corriger les sources légitimes non alignées.
4. Passer progressivement à p=quarantine puis p=reject (le paramètre pct= permet une montée en charge).
5. Couvrir les sous-domaines (sp=) et publier p=reject directement pour les domaines qui n'envoient jamais de courriel.

## Exemple

```
_dmarc.exemple.bj. TXT "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@exemple.bj; adkim=s; aspf=s"
```

## Références

- RFC 7489 — DMARC : https://www.rfc-editor.org/rfc/rfc7489
- CWE-290 — Authentication Bypass by Spoofing : https://cwe.mitre.org/data/definitions/290.html
- CAPEC-98 — Phishing : https://capec.mitre.org/data/definitions/98.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — DNSSEC — signature des réponses DNS

Contrôle : dnssec · Catégorie : DNS · Outils Recon-IA : dnssec, dane_check

## Pourquoi c'est important

Le DNS traduit les noms en adresses IP, sans aucune garantie d'authenticité à l'origine. DNSSEC fait signer cryptographiquement les enregistrements de la zone (RRSIG, DNSKEY) et rattache ces clés à la zone parente (enregistrement DS), formant une chaîne de confiance jusqu'à la racine. Un résolveur validant peut ainsi rejeter une réponse falsifiée. DNSSEC est aussi le prérequis de DANE (épinglage de certificats dans le DNS).

## Risque

Sans DNSSEC, un attaquant capable d'empoisonner un cache de résolveur ou d'intercepter les requêtes DNS peut rediriger les visiteurs et le courrier vers ses propres serveurs (pharming, détournement de MX). Une configuration partielle (clés publiées sans DS chez le registre, signatures expirées) n'apporte aucune protection, voire rend le domaine injoignable pour les résolveurs validants.

## Comment corriger

1. Activer la signature de zone chez l'hébergeur DNS (souvent une simple option).
2. Publier l'enregistrement DS auprès du bureau d'enregistrement (registrar) pour fermer la chaîne de confiance.
3. Utiliser un algorithme moderne (13 — ECDSA P-256 SHA-256) et automatiser le renouvellement des signatures.
4. Surveiller la validité de la chaîne (outils DNSViz, Zonemaster de l'AFNIC).

## Références

- RFC 4033 — DNS Security Introduction and Requirements : https://www.rfc-editor.org/rfc/rfc4033
- ANSSI — Bonnes pratiques pour l'acquisition et l'exploitation de noms de domaine : https://cyber.gouv.fr/publications/bonnes-pratiques-pour-lacquisition-et-lexploitation-de-noms-de-domaine
- CWE-350 — Reliance on Reverse DNS Resolution for a Security-Critical Action : https://cwe.mitre.org/data/definitions/350.html
- CAPEC-142 — DNS Cache Poisoning : https://capec.mitre.org/data/definitions/142.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — Autres en-têtes de sécurité HTTP (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)

Contrôle : en_tetes_securite · Catégorie : Web · Outils Recon-IA : security_headers, http_observatory, headers

## Pourquoi c'est important

Quelques en-têtes HTTP simples durcissent le comportement du navigateur : X-Frame-Options (ou frame-ancestors de CSP) interdit d'afficher le site dans un cadre tiers ; X-Content-Type-Options: nosniff empêche le navigateur de deviner un type de fichier ; Referrer-Policy limite les informations d'URL transmises aux sites tiers ; Permissions-Policy désactive les fonctions sensibles (caméra, micro, géolocalisation) inutiles au site.

## Risque

Leur absence ouvre la porte au clickjacking (l'utilisateur clique à son insu sur un bouton de votre site affiché en transparence), à l'exécution de fichiers téléversés interprétés comme du script, et à la fuite de paramètres sensibles d'URL (jetons, identifiants) vers des tiers. Les en-têtes qui révèlent la version du serveur (Server, X-Powered-By) facilitent en outre le ciblage de vulnérabilités connues.

## Comment corriger

1. Ajouter X-Content-Type-Options: nosniff sur toutes les réponses.
2. Ajouter X-Frame-Options: DENY (ou SAMEORIGIN) et frame-ancestors dans la CSP.
3. Définir Referrer-Policy: strict-origin-when-cross-origin (ou no-referrer).
4. Définir une Permissions-Policy restrictive pour les fonctions non utilisées.
5. Masquer ou réduire les en-têtes Server et X-Powered-By.

## Exemple

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

## Références

- OWASP — HTTP Headers Cheat Sheet : https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- OWASP Secure Headers Project : https://owasp.org/www-project-secure-headers/
- CWE-1021 — Improper Restriction of Rendered UI Layers (clickjacking) : https://cwe.mitre.org/data/definitions/1021.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — Fuites de données touchant les adresses du domaine

Contrôle : fuites_donnees · Catégorie : Réputation · Outils Recon-IA : xposedornot_breaches, github, gau_urls

## Pourquoi c'est important

Lorsqu'un service en ligne est piraté, ses bases d'utilisateurs (adresses électroniques, mots de passe plus ou moins protégés) finissent souvent publiées ou revendues. Recon-IA interroge un service public d'agrégation de fuites pour quelques adresses génériques du domaine (admin@, contact@…), sans tester d'adresses personnelles. Les dépôts de code publics et les archives d'URL peuvent aussi exposer des secrets.

## Risque

Des identifiants issus de fuites servent au « credential stuffing » : les attaquants les essaient automatiquement sur la messagerie, le VPN et les applications de l'organisation. La réutilisation d'un même mot de passe sur plusieurs services transforme une fuite chez un tiers en compromission directe.

## Comment corriger

1. Changer les mots de passe des comptes concernés et interdire leur réutilisation.
2. Activer l'authentification multifacteur sur la messagerie, le VPN et les accès d'administration.
3. Surveiller les fuites du domaine dans la durée (services de notification).
4. Rechercher et révoquer les secrets (clés d'API, mots de passe) publiés dans des dépôts de code.

## Références

- OWASP — Credential Stuffing Prevention Cheat Sheet : https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- CAPEC-600 — Credential Stuffing : https://capec.mitre.org/data/definitions/600.html
- CWE-798 — Use of Hard-coded Credentials : https://cwe.mitre.org/data/definitions/798.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — HSTS — HTTPS obligatoire côté navigateur

Contrôle : hsts · Catégorie : Web · Outils Recon-IA : security_headers, http_observatory, redirect_chain

## Pourquoi c'est important

L'en-tête Strict-Transport-Security indique au navigateur de ne plus jamais contacter le site en HTTP clair pendant la durée max-age. Même si l'utilisateur tape l'adresse sans https ou suit un vieux lien, le navigateur passe directement en HTTPS. Avec includeSubDomains et l'inscription dans la liste « preload » des navigateurs, la protection s'applique dès la toute première visite.

## Risque

Sans HSTS, la première requête (ou toute requête vers un lien http://) peut être interceptée sur un réseau hostile (Wi-Fi public, routeur compromis) : l'attaquant maintient la victime en HTTP (attaque « SSL stripping ») et lit ou modifie le trafic, y compris les identifiants et cookies de session.

## Comment corriger

1. S'assurer que le site et tous ses sous-domaines fonctionnent en HTTPS avec un certificat valide.
2. Rediriger systématiquement HTTP vers HTTPS (redirection 301).
3. Ajouter l'en-tête Strict-Transport-Security avec un max-age court pour tester, puis au moins un an (31536000).
4. Ajouter includeSubDomains, puis preload et inscrire le domaine sur hstspreload.org une fois la configuration stabilisée.

## Exemple

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

## Références

- RFC 6797 — HTTP Strict Transport Security : https://www.rfc-editor.org/rfc/rfc6797
- OWASP — HTTP Strict Transport Security Cheat Sheet : https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- CWE-319 — Cleartext Transmission of Sensitive Information : https://cwe.mitre.org/data/definitions/319.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — Listes de blocage (DNSBL) et réputation des adresses IP

Contrôle : listes_blocage · Catégorie : Réputation · Outils Recon-IA : dnsbl_check, abuseipdb_check, abusech_check, urlscan_search

## Pourquoi c'est important

Les listes de blocage DNS (Spamhaus, SpamCop, Barracuda…) et les bases de réputation communautaires (AbuseIPDB, URLhaus, ThreatFox) recensent les adresses IP et domaines ayant envoyé du spam, hébergé des logiciels malveillants ou servi de relais d'attaque. Les filtres de messagerie et de nombreux pare-feu s'y réfèrent pour bloquer automatiquement.

## Risque

Une présence sur ces listes signale souvent une compromission (serveur détourné pour envoyer du spam, site piraté hébergeant du hameçonnage) et entraîne le rejet du courrier légitime de l'organisation. Sur un hébergement mutualisé, la mauvaise réputation d'un voisin peut aussi vous affecter.

## Comment corriger

1. Identifier la cause : compte de messagerie compromis, formulaire détourné, logiciel malveillant sur le serveur.
2. Nettoyer et sécuriser le système avant toute demande de retrait (sinon la réinscription est immédiate).
3. Demander le retrait via la procédure de chaque liste.
4. Surveiller la réputation des adresses IP d'envoi dans la durée.

## Références

- RFC 5782 — DNS Blacklists and Whitelists : https://www.rfc-editor.org/rfc/rfc5782
- Spamhaus — Blocklist removal : https://check.spamhaus.org/

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — MTA-STS et TLS-RPT — chiffrement imposé du courrier entrant

Contrôle : mta_sts · Catégorie : Messagerie · Outils Recon-IA : mta_sts_check, tlsrpt_check

## Pourquoi c'est important

Entre serveurs de messagerie, le chiffrement STARTTLS est opportuniste : un attaquant placé sur le chemin réseau peut supprimer l'offre de chiffrement et lire le courrier en clair. MTA-STS publie une politique (enregistrement DNS _mta-sts et fichier HTTPS mta-sts.txt) qui oblige les serveurs émetteurs compatibles à utiliser TLS avec un certificat valide vers vos serveurs MX. TLS-RPT permet de recevoir des rapports sur les échecs de connexion TLS.

## Risque

Sans MTA-STS, le courrier entrant peut être intercepté ou détourné par rétrogradation (downgrade) de STARTTLS ou par usurpation DNS des enregistrements MX. Sans TLS-RPT, ces échecs restent invisibles.

## Comment corriger

1. Vérifier que tous les serveurs MX présentent un certificat valide correspondant à leur nom.
2. Publier le fichier https://mta-sts.votre-domaine/.well-known/mta-sts.txt en mode testing, avec la liste des MX.
3. Publier l'enregistrement TXT _mta-sts.votre-domaine (v=STSv1; id=...).
4. Publier _smtp._tls.votre-domaine (v=TLSRPTv1; rua=mailto:...) pour recevoir les rapports.
5. Passer en mode enforce après analyse des rapports.

## Exemple

```
_mta-sts.exemple.bj. TXT "v=STSv1; id=20261019"
```

## Références

- RFC 8461 — SMTP MTA Strict Transport Security : https://www.rfc-editor.org/rfc/rfc8461
- RFC 8460 — SMTP TLS Reporting : https://www.rfc-editor.org/rfc/rfc8460
- CWE-319 — Cleartext Transmission of Sensitive Information : https://cwe.mitre.org/data/definitions/319.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — Ports et services exposés sur Internet

Contrôle : ports_exposes · Catégorie : Réseau · Outils Recon-IA : shodan_internetdb, ip_info, asn_info

## Pourquoi c'est important

Chaque port ouvert sur une adresse IP publique correspond à un service joignable par le monde entier. Des moteurs comme Shodan balaient Internet en permanence et publient ce qu'ils voient : Recon-IA consulte ces observations sans jamais sonder lui-même la cible. Les services d'administration (SSH 22, RDP 3389, bases de données 3306/5432/27017, Redis 6379, Elasticsearch 9200, partage SMB 445) ne devraient presque jamais être exposés directement.

## Risque

Un service d'administration exposé subit en continu des tentatives de force brute et d'exploitation automatisées ; une base de données sans authentification peut être copiée ou chiffrée contre rançon en quelques heures. Les versions logicielles visibles (CPE) associées à des CVE connues sont des cibles prioritaires pour les attaquants, surtout si la vulnérabilité figure au catalogue CISA KEV.

## Comment corriger

1. Inventorier les ports exposés et fermer tout ce qui n'est pas nécessaire au public.
2. Placer l'administration (SSH, RDP, consoles) derrière un VPN ou un bastion avec authentification forte.
3. Ne jamais exposer une base de données ou un cache directement à Internet.
4. Appliquer les correctifs de sécurité en priorité sur les services exposés présentant des CVE connues.

## Références

- CISA — Known Exploited Vulnerabilities Catalog : https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CWE-306 — Missing Authentication for Critical Function : https://cwe.mitre.org/data/definitions/306.html
- CWE-668 — Exposure of Resource to Wrong Sphere : https://cwe.mitre.org/data/definitions/668.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — security.txt — contact pour signaler une vulnérabilité

Contrôle : security_txt · Catégorie : Web · Outils Recon-IA : security_txt

## Pourquoi c'est important

Le fichier /.well-known/security.txt (RFC 9116) indique aux chercheurs en sécurité comment signaler une vulnérabilité : adresse de contact, politique de divulgation, langues acceptées, date d'expiration du fichier. C'est un geste simple qui montre l'existence d'un processus de gestion des signalements.

## Risque

Sans point de contact clair, une personne qui découvre une faille ne sait pas à qui l'adresser : le signalement se perd, arrive tard, ou la faille finit publiée sans que l'organisation ait pu corriger. Un fichier expiré ou pointant vers une adresse abandonnée a le même effet.

## Comment corriger

1. Publier https://votre-domaine/.well-known/security.txt avec au minimum les champs Contact et Expires.
2. Utiliser une adresse dédiée et réellement suivie (securite@ ou un formulaire).
3. Ajouter Policy (politique de divulgation) et Preferred-Languages: fr, en.
4. Renouveler le champ Expires avant échéance (au plus un an).

## Exemple

```
Contact: mailto:securite@exemple.bj
Expires: 2027-10-19T00:00:00Z
Preferred-Languages: fr, en
```

## Références

- RFC 9116 — security.txt : https://www.rfc-editor.org/rfc/rfc9116
- securitytxt.org : https://securitytxt.org/

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — SPF — serveurs autorisés à envoyer du courriel

Contrôle : spf · Catégorie : Messagerie · Outils Recon-IA : spf_analysis, email_config

## Pourquoi c'est important

SPF (Sender Policy Framework) est un enregistrement DNS TXT qui liste les serveurs et services autorisés à envoyer des courriels pour votre domaine. Le serveur destinataire compare l'adresse IP de l'expéditeur à cette liste. Le mécanisme final « all » précise le traitement des serveurs non listés : -all (refus), ~all (suspect), ?all (neutre) ou +all (tout accepter).

## Risque

Un domaine sans SPF, ou avec +all ou ?all, ne donne aucun moyen de distinguer un serveur légitime d'un serveur d'attaquant : l'usurpation est facilitée. Un SPF qui dépasse la limite de 10 recherches DNS (includes imbriqués) devient invalide (permerror) et cesse de protéger. Chaque include tiers élargit aussi la liste des acteurs capables d'envoyer en votre nom.

## Comment corriger

1. Inventorier toutes les sources d'envoi légitimes du domaine.
2. Publier un seul enregistrement TXT commençant par v=spf1, listant ces sources (ip4:, ip6:, include:).
3. Terminer par -all (ou ~all pendant une phase de transition courte).
4. Rester sous 10 recherches DNS et supprimer les includes de services abandonnés.
5. Pour un domaine qui n'envoie aucun courriel : v=spf1 -all.

## Exemple

```
exemple.bj. TXT "v=spf1 include:_spf.google.com ip4:203.0.113.10 -all"
```

## Références

- RFC 7208 — SPF : https://www.rfc-editor.org/rfc/rfc7208
- CWE-290 — Authentication Bypass by Spoofing : https://cwe.mitre.org/data/definitions/290.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — Prise de contrôle de sous-domaine (subdomain takeover)

Contrôle : takeover · Catégorie : DNS · Outils Recon-IA : subdomain_takeover, dns_records, all_subdomains

## Pourquoi c'est important

Un sous-domaine pointe souvent, par un enregistrement CNAME, vers un service externe (hébergement de pages, stockage objet, plateforme SaaS). Si le service est supprimé mais que l'enregistrement DNS reste en place (« CNAME orphelin »), n'importe qui peut parfois créer chez ce fournisseur une ressource du même nom et prendre ainsi le contrôle du sous-domaine. Le projet communautaire can-i-take-over-xyz recense les services concernés et leurs signatures.

## Risque

L'attaquant sert alors son propre contenu sous votre nom de domaine : hameçonnage très crédible, vol de cookies posés sur le domaine parent, contournement de politiques CORS ou CSP qui font confiance aux sous-domaines, atteinte à la réputation. Recon-IA ne fait qu'une détection passive (résolution DNS) : un résultat est un indice à vérifier, pas une preuve.

## Comment corriger

1. Supprimer les enregistrements DNS dès qu'un service externe est décommissionné (et dans cet ordre : DNS d'abord).
2. Tenir un inventaire des sous-domaines et des services tiers vers lesquels ils pointent.
3. Vérifier chaque alerte : la ressource existe-t-elle encore chez le fournisseur ?
4. Réclamer ou recréer la ressource orpheline en urgence si le sous-domaine est encore nécessaire.

## Références

- can-i-take-over-xyz (EdOverflow, CC BY 4.0) : https://github.com/EdOverflow/can-i-take-over-xyz
- OWASP WSTG — Test for Subdomain Takeover : https://owasp.org/www-project-web-security-testing-guide/
- CWE-350 — Reliance on Reverse DNS Resolution for a Security-Critical Action : https://cwe.mitre.org/data/definitions/350.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — TLS — versions de protocole et suites cryptographiques

Contrôle : tls · Catégorie : TLS · Outils Recon-IA : tls_config, ssl_info

## Pourquoi c'est important

TLS chiffre et authentifie la connexion entre le visiteur et le serveur. Sa robustesse dépend des versions de protocole acceptées et des suites cryptographiques proposées. TLS 1.3 et TLS 1.2 avec des suites à confidentialité persistante (ECDHE) et chiffrement authentifié (AES-GCM, ChaCha20-Poly1305) sont aujourd'hui recommandés ; SSLv2, SSLv3, TLS 1.0 et TLS 1.1 sont obsolètes (RFC 8996).

## Risque

Accepter d'anciennes versions ou des suites faibles (RC4, 3DES, CBC avec SHA-1, export, échange RSA sans confidentialité persistante) expose à des attaques connues (POODLE, BEAST, Sweet32, rétrogradation) et à un déchiffrement a posteriori du trafic enregistré si la clé privée est un jour compromise. Les audits de conformité (PCI DSS, référentiels nationaux) signalent systématiquement ces écarts.

## Comment corriger

1. Désactiver SSLv2, SSLv3, TLS 1.0 et TLS 1.1 sur tous les services exposés (web, messagerie, VPN).
2. Activer TLS 1.3 et conserver TLS 1.2 uniquement avec des suites ECDHE + AEAD.
3. S'appuyer sur le profil « intermediate » du générateur de configuration Mozilla (ou « modern » si tous les clients le permettent).
4. Utiliser des clés RSA d'au moins 2048 bits ou ECDSA P-256, et des paramètres Diffie-Hellman d'au moins 2048 bits.
5. Revérifier après chaque mise à jour du serveur, du répartiteur de charge ou du CDN.

## Exemple

```
ssl_protocols TLSv1.2 TLSv1.3;  (nginx)
```

## Références

- Mozilla — Server Side TLS / SSL Configuration Generator : https://ssl-config.mozilla.org/
- RFC 8996 — Deprecating TLS 1.0 and TLS 1.1 : https://www.rfc-editor.org/rfc/rfc8996
- ANSSI — Recommandations de sécurité relatives à TLS : https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-tls
- CWE-327 — Use of a Broken or Risky Cryptographic Algorithm : https://cwe.mitre.org/data/definitions/327.html

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — Classement Tranco — popularité du domaine

Contrôle : tranco · Catégorie : Contexte · Outils Recon-IA : tranco_rank

## Pourquoi c'est important

Tranco est un classement académique des domaines les plus visités, calculé en combinant plusieurs sources (Chrome UX Report, Cloudflare Radar, Majestic…) sur 30 jours pour résister aux manipulations. Il donne un ordre de grandeur de l'audience d'un site, utile pour situer l'exposition et la valeur du domaine comme cible.

## Risque

Le classement n'est pas une vulnérabilité en soi. Un domaine très populaire attire davantage d'attaques ciblées et de campagnes d'usurpation (typosquatting, hameçonnage à la marque) ; un domaine absent du classement peut, à l'inverse, être un domaine récent ou peu surveillé. Il sert à pondérer la priorité des corrections, pas à juger la sécurité.

## Comment corriger

1. Pour un domaine très visible : renforcer en priorité DMARC en p=reject, HSTS preload et la surveillance des domaines ressemblants.
2. Mettre en place une veille sur les enregistrements de domaines proches de la marque.

## Références

- Tranco — A Research-Oriented Top Sites Ranking : https://tranco-list.eu/

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

---

# Explication — Typosquatting — domaines ressemblants

Contrôle : typosquatting · Catégorie : Réputation · Outils Recon-IA : typosquatting

## Pourquoi c'est important

Des attaquants enregistrent des noms proches du vôtre (lettre inversée, doublée, caractère visuellement identique, autre extension) pour tromper vos clients et employés. Recon-IA génère ces variantes et vérifie lesquelles sont réellement enregistrées, en particulier celles équipées d'un serveur de messagerie (MX), signe d'une possible campagne d'hameçonnage.

## Risque

Un domaine ressemblant doté d'un MX permet d'envoyer des courriels très crédibles (fausses factures, changement de RIB) qui ne seront pas bloqués par votre propre DMARC, puisqu'il s'agit d'un autre domaine. Il peut aussi héberger une copie de votre site pour voler des identifiants.

## Comment corriger

1. Surveiller régulièrement les domaines ressemblants nouvellement enregistrés.
2. Enregistrer de manière défensive les variantes les plus évidentes et les extensions principales.
3. Signaler les domaines frauduleux au bureau d'enregistrement et aux services anti-hameçonnage.
4. Sensibiliser les équipes comptables et le support aux demandes inhabituelles par courriel.

## Références

- CAPEC-630 — TypoSquatting : https://capec.mitre.org/data/definitions/630.html
- CAPEC-632 — Homograph Attack via Homoglyphs : https://capec.mitre.org/data/definitions/632.html
- dnstwist : https://github.com/elceef/dnstwist

_Structure inspirée de la page « About » de web-check (Alicia Sykes, licence MIT, https://github.com/Lissy93/web-check). Texte original rédigé en français pour Recon-IA._

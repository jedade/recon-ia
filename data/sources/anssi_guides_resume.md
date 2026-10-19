# ANSSI — Recommandations de sécurité relatives à TLS (synthèse Recon-IA)

Source : ANSSI, « Recommandations de sécurité relatives à TLS » (guide ANSSI-PA-035),
https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-tls
Nature : synthèse rédigée pour Recon-IA à partir du guide, pas une reproduction du texte.
Les publications de l'ANSSI sont diffusées sous Licence Ouverte / Open Licence (Etalab 2.0)
sauf mention contraire : la réutilisation est libre sous réserve de mentionner la source
(« ANSSI »), la date et le lien. Vérifier la mention figurant dans le PDF avant toute
reproduction intégrale.

Principes retenus :
- Privilégier TLS 1.3 ; TLS 1.2 reste acceptable s'il est correctement configuré. SSLv2,
  SSLv3, TLS 1.0 et TLS 1.1 ne doivent plus être proposés.
- N'utiliser que des suites assurant la confidentialité persistante (échange de clés
  éphémère ECDHE, ou DHE avec des groupes suffisamment grands) et un chiffrement
  authentifié (AES-GCM, ChaCha20-Poly1305 ; AES-CCM en TLS 1.3).
- Proscrire les suites d'export, NULL, anonymes, RC4, 3DES, et l'échange de clés RSA
  statique (sans confidentialité persistante).
- Préférer l'ordre de suites défini par le serveur, désactiver la compression TLS et la
  renégociation non sécurisée.
- Certificats : clés RSA de 2048 bits au minimum (3072 bits recommandés pour une longue
  durée de vie) ou ECDSA sur courbes P-256/P-384 ; signatures SHA-256 au minimum ; chaîne
  de certification complète ; durée de validité limitée et renouvellement anticipé.
- Activer HSTS pour les services web, et l'agrafage OCSP lorsque possible.
- Ces recommandations s'appliquent à tous les services TLS exposés (HTTPS, mais aussi
  SMTP avec STARTTLS, IMAPS, VPN TLS), pas seulement au site web principal.

Lien avec Recon-IA : outils tls_config (sslscan), ssl_info, security_headers (HSTS).

---

# ANSSI — Mise en œuvre d'un site web : standards de sécurité côté navigateur (synthèse Recon-IA)

Source : ANSSI, « Recommandations pour la mise en œuvre d'un site web : maîtriser les
standards de sécurité côté navigateur » (guide ANSSI-PA-009),
https://cyber.gouv.fr/publications/recommandations-pour-la-mise-en-oeuvre-dun-site-web-maitriser-les-standards-de-securite
Nature : synthèse rédigée pour Recon-IA (Licence Ouverte Etalab 2.0 pour l'original,
attribution « ANSSI »).

Principes retenus :
- Servir l'intégralité du site en HTTPS, rediriger HTTP vers HTTPS et publier l'en-tête
  Strict-Transport-Security avec une durée longue, idéalement avec includeSubDomains.
- Définir une politique Content-Security-Policy restrictive : origines explicites,
  pas de unsafe-inline ni unsafe-eval, object-src 'none', frame-ancestors pour interdire
  l'intégration non souhaitée dans des cadres (protection contre le clickjacking).
- Envoyer X-Content-Type-Options: nosniff et une Referrer-Policy limitant la fuite
  d'URL vers des tiers.
- Protéger les cookies : attributs Secure, HttpOnly et SameSite ; préfixes __Host- et
  __Secure- pour les cookies sensibles.
- Contrôler l'intégrité des ressources tierces (Subresource Integrity) et limiter les
  dépendances externes chargées par les pages.
- Encadrer le partage de ressources entre origines (CORS) : pas de joker sur des réponses
  authentifiées, liste explicite des origines autorisées.

Lien avec Recon-IA : outils security_headers, http_observatory, headers, js_endpoints.

---

# ANSSI — Sécurisation des sites web (synthèse Recon-IA)

Source : ANSSI, « Recommandations pour la sécurisation des sites web » (note technique
NT-009), https://cyber.gouv.fr/publications/recommandations-pour-la-securisation-des-sites-web
Nature : synthèse rédigée pour Recon-IA (Licence Ouverte Etalab 2.0 pour l'original,
attribution « ANSSI »).

Principes retenus :
- Réduire la surface exposée : ne publier que les services nécessaires, séparer les
  interfaces d'administration du site public (filtrage, VPN, authentification forte).
- Maintenir à jour serveur, CMS, extensions et bibliothèques ; supprimer les composants
  inutilisés ; ne pas afficher les versions logicielles dans les en-têtes et pages d'erreur.
- Ne laisser aucun fichier sensible accessible (sauvegardes, fichiers de configuration,
  dépôts de code, listings de répertoires).
- Valider toutes les entrées côté serveur et encoder les sorties (injections, XSS).
- Journaliser et surveiller les accès, prévoir une procédure de réaction et de
  restauration (sauvegardes testées).
- Prévoir un point de contact pour le signalement de vulnérabilités.

Lien avec Recon-IA : outils tech_stack, headers, robots_txt, sitemap, gau_urls,
archive_history, security_txt, shodan_internetdb.

---

# ANSSI — Acquisition et exploitation de noms de domaine (synthèse Recon-IA)

Source : ANSSI, « Bonnes pratiques pour l'acquisition et l'exploitation de noms de
domaine », https://cyber.gouv.fr/publications/bonnes-pratiques-pour-lacquisition-et-lexploitation-de-noms-de-domaine
Nature : synthèse rédigée pour Recon-IA (Licence Ouverte Etalab 2.0 pour l'original,
attribution « ANSSI »).

Principes retenus :
- Choisir un bureau d'enregistrement et un hébergeur DNS de confiance, activer le
  verrouillage du domaine (registrar lock / registry lock) et l'authentification forte
  sur le compte de gestion.
- Surveiller les dates d'expiration et automatiser le renouvellement : un domaine expiré
  peut être racheté par un tiers.
- Tenir à jour les contacts administratifs et techniques, en évitant les adresses
  personnelles ou hébergées sur le domaine lui-même.
- Disposer d'au moins deux serveurs DNS faisant autorité, sur des réseaux distincts ;
  restreindre les transferts de zone.
- Déployer DNSSEC (signature de zone et publication du DS chez le registre) et
  superviser la validité des signatures.
- Supprimer les enregistrements obsolètes, en particulier ceux qui pointent vers des
  services externes abandonnés (risque de prise de contrôle de sous-domaine).
- Enregistrer de façon défensive les variantes évidentes du nom et surveiller les
  domaines ressemblants (typosquatting).

Lien avec Recon-IA : outils whois, rdap_info, dnssec, dns_records, subdomain_takeover,
typosquatting, caa_check.

---

# ANSSI — Messagerie électronique : recommandations applicables (synthèse Recon-IA)

Source : synthèse rédigée pour Recon-IA en appliquant à la messagerie les principes des
guides ANSSI ci-dessus (TLS, noms de domaine) et les normes IETF (RFC 7208 SPF, RFC 6376
DKIM, RFC 7489 DMARC, RFC 8461 MTA-STS, RFC 8460 TLS-RPT, RFC 7672 DANE pour SMTP).
Aucun guide ANSSI dédié n'a pu être vérifié hors ligne lors de la rédaction : ne pas
citer cette section comme un texte de l'ANSSI.

Principes retenus :
- Publier SPF (terminé par -all), signer le courrier sortant avec DKIM (clés RSA d'au
  moins 2048 bits) et publier DMARC, en visant la politique p=reject après une phase
  d'observation des rapports.
- Protéger aussi les domaines et sous-domaines qui n'envoient pas de courriel
  (v=spf1 -all, DMARC p=reject).
- Chiffrer les échanges entre serveurs : STARTTLS avec les mêmes exigences TLS que pour
  le web, MTA-STS en mode enforce ou DANE (avec DNSSEC), rapports TLS-RPT.
- Surveiller la réputation des adresses IP d'envoi (listes de blocage) et réagir à toute
  inscription, signe fréquent de compte compromis.
- Activer l'authentification multifacteur sur les webmails et accès distants.

Lien avec Recon-IA : outils email_config, spf_analysis, dkim_check, dmarc_check,
mta_sts_check, tlsrpt_check, dane_check, dnsbl_check.

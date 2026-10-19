# Mozilla — recommandations de configuration TLS (guidelines v6.0)

Source : Mozilla SSL Configuration Generator (ssl-config.mozilla.org, licence MPL 2.0). Mozilla publie trois profils de configuration serveur. Un audit passif compare les protocoles et suites observés (outil tls_config / sslscan) à ces profils : un serveur qui accepte des éléments absents du profil « intermediate » présente un écart.

---

# Mozilla TLS — profil modern

Profil « modern » : TLS 1.3 uniquement. À réserver aux services dont tous les clients sont récents (navigateurs à jour, API entre serveurs modernes).

- Versions TLS : TLSv1.3
- Suites TLS 1.3 : TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
- Courbes TLS : X25519MLKEM768, X25519, prime256v1, secp384r1
- Types de certificat : ecdsa
- Courbes de certificat : prime256v1, secp384r1
- Signatures de certificat : ecdsa-with-SHA256, ecdsa-with-SHA384, ecdsa-with-SHA512
- Taille ECDH : 256
- Durée HSTS minimale (secondes) : 63072000
- Durée de vie recommandée du certificat (jours) : 90
- Ordre des suites imposé par le serveur : False
- Clients les plus anciens supportés : Firefox 63, Android 10.0, Chrome 70, Edge 75, Java 11, OpenSSL 1.1.1, Opera 57, Safari 12.1

---

# Mozilla TLS — profil intermediate

Profil « intermediate » : recommandé par défaut pour un site public. TLS 1.2 et 1.3, suites ECDHE avec chiffrement authentifié (AEAD) uniquement.

- Versions TLS : TLSv1.2, TLSv1.3
- Suites TLS 1.3 : TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
- Suites TLS 1.2 et antérieures (OpenSSL) : ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305
- Courbes TLS : X25519MLKEM768, X25519, prime256v1, secp384r1
- Types de certificat : ecdsa, rsa
- Courbes de certificat : prime256v1, secp384r1
- Signatures de certificat : sha256WithRSAEncryption, ecdsa-with-SHA256, ecdsa-with-SHA384, ecdsa-with-SHA512
- Taille minimale de clé RSA : 2048
- Taille des paramètres DH : 2048
- Taille ECDH : 256
- Durée HSTS minimale (secondes) : 63072000
- Durée de vie recommandée du certificat (jours) : 90
- Ordre des suites imposé par le serveur : False
- Clients les plus anciens supportés : Firefox 31.3.0, Android 4.4.2, Chrome 49, Edge 15 on Windows 10, IE 11 on Windows 10, Java 8u161, OpenSSL 1.0.1l, Opera 20, Safari 9

---

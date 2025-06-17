# 🔍 recon-ia

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#)
[![GitHub issues](https://img.shields.io/github/issues/your-user/your-repo.svg)](#)

---

## 📘 Description
Outil de reconnaissance passive OSINT automatisé avec **n8n**, **RAG** et **AI agents**, permettant de :
- Collecter un maximum d’informations sur une cible (domaines, DNS, WHOIS, emails, certificats, réseaux sociaux…)
- Valider et enrichir les données via recherche web en live et AI
- Évaluer la surface d’attaque, les risques (critères OWASP, ISO 27001…), et proposer des recommandations
- Générer automatiquement un rapport HTML/PDF customisable

---

## 🧩 Fonctionnalités
- **Collecte passive** : sous-domaines, WHOIS/DNS, IP/ASN, emails publics, fuites (HIBP), technologies web
- **Indexation RAG** : segmentation + embeddings → Qdrant/Pinecone
- **Recherche en temps réel** : API Web Search + scraping headless (Playwright/Selenium)
- **AI Agent** : validation, enrichissement et analyse des données
- **Évaluation des risques** : classification (impact/probabilité) et recommandations selon normes
- **Génération de rapports** : template HTML → PDF exportable

---

## 🚀 Prérequis
- **n8n** ≥ 1.x
- **API Keys** : OpenAI, SecurityTrails, Hunter.io, HaveIBeenPwned, Bing Search…
- **Vector DB** : Qdrant, Pinecone ou Supabase
- **Python** avec Playwright/Selenium (optionnel pour scraping)
- (Optionnel) Docker, Docker Compose

---

## ⚙️ Installation

```bash
# Cloner le projet
git clone https://github.com/your-user/your-repo.git
cd your-repo

# Copier et compléter les clés dans .env
cp .env.example .env

# Lancer n8n (Docker + Compose)
docker-compose up -d n8n

# Importer le workflow dans n8n via l’interface

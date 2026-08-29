FROM python:3.11-slim

# ============================================================
# Variables d'environnement
# ============================================================
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# ============================================================
# 1. Dépendances système
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Outils de base
    git curl jq wget ca-certificates tzdata \
    # OSINT — DNS / WHOIS
    whois dnsutils \
    # OSINT — SSL
    sslscan \
    # Build (compilations Python C-extensions)
    build-essential libxml2-dev libxslt1-dev libffi-dev libssl-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*

# ============================================================
# 2. Go officiel (version récente, compatible avec les outils OSINT)
# ============================================================
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GOARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then GOARCH="arm64"; \
    else GOARCH="$ARCH"; fi && \
    curl -fsSL "https://go.dev/dl/go1.22.5.linux-${GOARCH}.tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH=/usr/local/go/bin:$GOPATH/bin:$PATH

# ============================================================
# 3. Outils Go (sous-domaines OSINT) — compilés pour l'archi courante
# ============================================================
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master && \
    go install github.com/gwen001/github-subdomains@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# ============================================================
# 4. Dépendances Python de l'API — via requirements.txt
#    (source unique de vérité pour tous les paquets Python)
# ============================================================
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ============================================================
# 5. Code de l'application
# ============================================================
COPY . .

# ============================================================
# 6. Démarrage — migrations automatiques puis API
# ============================================================
RUN chmod +x /app/entrypoint.sh
EXPOSE 8080
CMD ["/bin/sh", "/app/entrypoint.sh"]

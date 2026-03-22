FROM python:3.11-slim
WORKDIR /app

# 1. System packages
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    nmap \
    binwalk \
    yara \
    cppcheck \
    flawfinder \
    ruby-full \
    golang-go \
    default-jdk \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    npm \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# 2. Language-specific security tools
RUN pip install --no-cache-dir bandit semgrep pylint safety && \
    npm install -g eslint retire && \
    gem install brakeman bundler-audit && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install honnef.co/go/tools/cmd/staticcheck@latest

# 3. Nikto
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# 4. whatweb
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

# 5. wafw00f
RUN pip install --no-cache-dir wafw00f

# 6. gitleaks
RUN GITLEAKS_VERSION="8.18.2" && \
    wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -O /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz

# 7. trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# 8. checksec
RUN pip install --no-cache-dir checksec.py

# 9. SpotBugs & Checkstyle
RUN wget -q https://github.com/spotbugs/spotbugs/releases/download/4.8.6/spotbugs-4.8.6.zip && \
    unzip spotbugs-4.8.6.zip && \
    mv spotbugs-4.8.6 /opt/spotbugs && \
    rm spotbugs-4.8.6.zip && \
    wget -q https://github.com/checkstyle/checkstyle/releases/download/checkstyle-10.12.5/checkstyle-10.12.5-all.jar \
    -O /opt/checkstyle.jar

# 10. ClamAV
RUN apt-get update && apt-get install -y clamav && \
    rm -rf /var/lib/apt/lists/* && \
    freshclam || true

# 11. YARA rules
RUN mkdir -p /opt/yara-rules && \
    git clone --depth 1 https://github.com/Yara-Rules/rules.git /opt/yara-rules || true

# 12. Environment paths
ENV PATH="/root/go/bin:/opt/spotbugs/bin:${PATH}"

# 13. Python requirements
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 14. Application code (last — maximises Docker layer cache)
COPY backend /app/backend
COPY config /app/config

CMD ["celery", "-A", "backend.workers.celery_app:celery", "worker", \
     "--loglevel=info", "--concurrency=4"]
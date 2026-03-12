FROM python:3.11-slim
WORKDIR /app

# 1. Install base system packages (Highly Cached)
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

# 2. Install Language-Specific Security Tools
RUN pip install --no-cache-dir bandit semgrep && \
    npm install -g eslint && \
    gem install brakeman && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest

# 3. Install Nikto
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto


# 4. Install SpotBugs & Checkstyle
RUN wget -q https://github.com/spotbugs/spotbugs/releases/download/4.8.6/spotbugs-4.8.6.zip && \
    unzip spotbugs-4.8.6.zip && \
    mv spotbugs-4.8.6 /opt/spotbugs && \
    rm spotbugs-4.8.6.zip && \
    wget -q https://github.com/checkstyle/checkstyle/releases/download/checkstyle-10.12.5/checkstyle-10.12.5-all.jar -O /opt/checkstyle.jar

# 5. Set Environment Paths (Crucial for AIGIS to find the tools)
ENV PATH="/root/go/bin:/opt/zap:/opt/spotbugs/bin:${PATH}"

# 6. Install Python Requirements
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 7. Copy Code (Last to maximize cache)
COPY backend /app/backend
COPY config /app/config

CMD ["celery", "-A", "backend.workers.celery_app:celery", "worker", "--loglevel=info", "--concurrency=4"]
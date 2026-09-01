FROM python:3.12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    aircrack-ng \
    hashcat \
    reaver \
    hostapd \
    dnsmasq \
    mdk4 \
    macchanger \
    hcxdumptool \
    hcxtools \
    iw \
    wireless-tools \
    net-tools \
    nmap \
    python3-pip \
    python3-venv \
    iwlist \
    rfkill \
    usbutils \
    pciutils \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir -e ".[dev]" || pip install --no-cache-dir .

RUN mkdir -p /root/.wafford/{logs,plugins,wordlists,captures,reports}

COPY docker-compose.yml ./

ENTRYPOINT ["python", "-m", "wafford"]

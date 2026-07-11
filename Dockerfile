# Reconta — containerized so you can run a full recon without installing
# 25+ tools on your host.
#
#   docker build -t reconta .
#   docker run --rm -v "$PWD/loot:/opt/reconta/output" reconta example.com -p normal
#
# Results land in ./loot on your host. Add API keys by mounting tool configs,
# e.g. -v "$HOME/.config/subfinder:/root/.config/subfinder".

FROM golang:1.22-bookworm

LABEL org.opencontainers.image.title="Reconta" \
      org.opencontainers.image.description="Recon + Data — de-noised recon & OSINT with prioritized findings" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/<you>/reconta"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/go/bin:/root/.local/bin:${PATH}"

# System dependencies (nmap/masscan/whois/jq/pipx + libpcap for naabu).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git curl jq whois nmap masscan dnsutils \
      python3 python3-pip pipx libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/reconta
COPY . .

# Install the Go-based tools, then the Python ones.
RUN chmod +x reconta.sh install.sh \
    && ./install.sh --go-only \
    && pipx install uro \
    && pipx install arjun \
    && pipx install theHarvester \
    && pipx install git+https://github.com/devanshbatham/paramspider || true

# Pre-fetch a resolvers list so active stages work out of the box.
RUN mkdir -p /root/.config/reconta \
    && curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
       -o /root/.config/reconta/resolvers.txt || true

VOLUME ["/opt/reconta/output"]
ENTRYPOINT ["/opt/reconta/reconta.sh"]
CMD ["--help"]

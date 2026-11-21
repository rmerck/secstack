# HexStrike API server inside Kali (arm64). Tools live here, not on macOS.
# Base images are pinned to the digests the working reference image was built from (2026-11-19).
# Kali packages still roll (apt-signed); refresh the pins deliberately, then rebuild and re-test.
# gau and waybackurls are not packaged for Kali arm64: build them from source in a throwaway stage
# (Go modules are verified against the Go checksum database).
FROM golang:1-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS gotools
RUN go install github.com/lc/gau/v2/cmd/gau@latest && go install github.com/tomnomnom/waybackurls@latest

FROM kalilinux/kali-rolling@sha256:1ff4a2be3849333687b3ed2b31bb5af0cd1b7c0a11ec7713feb5abe5a6b2795c
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip python3-dev build-essential git curl ca-certificates \
      chromium chromium-driver iputils-ping dnsutils netcat-openbsd wordlists dirb \
 && rm -rf /var/lib/apt/lists/*
# Security tools: installed one at a time so a renamed/missing package doesn't fail the build (it is
# listed as MISSING). Every other step is chained with &&: a failed apt-get update or cleanup fails
# the build, and so does a run where no tool installed at all.
RUN apt-get update \
 && for p in \
      nmap masscan rustscan nuclei subfinder httpx-toolkit ffuf gobuster feroxbuster dirsearch \
      sqlmap nikto wpscan amass katana whatweb wafw00f arjun dalfox gau waybackurls naabu dnsx \
      hydra john hashcat dnsenum fierce theharvester enum4linux smbmap netexec responder evil-winrm \
      sslscan testssl.sh binwalk radare2 gdb checksec libimage-exiftool-perl steghide trivy ; do \
      apt-get install -y --no-install-recommends "$p" >/dev/null 2>&1 && echo "OK $p" >> /opt/tools.txt || echo "MISSING $p" >> /opt/tools.txt; \
    done \
 && ln -sf /usr/bin/httpx-toolkit /usr/local/bin/httpx \
 && rm -rf /var/lib/apt/lists/* \
 && grep -q '^OK ' /opt/tools.txt
WORKDIR /opt/hexstrike
COPY --from=ghcr.io/astral-sh/uv:latest@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d /uv /usr/local/bin/uv
COPY requirements.txt .
# Kali's system Python is 3.14; hexstrike's pinned deps (mitmproxy<11 etc.) need 3.12 wheels.
ENV UV_PYTHON_INSTALL_DIR=/opt/uv-python UV_LINK_MODE=copy
RUN uv venv -p 3.12 /opt/hexstrike-env \
 && grep -vE '^(angr|pwntools)' requirements.txt > req-core.txt \
 && VIRTUAL_ENV=/opt/hexstrike-env uv pip install -r req-core.txt \
 && (VIRTUAL_ENV=/opt/hexstrike-env uv pip install 'pwntools>=4.10.0,<5.0.0' && echo "OK pwntools" >> /opt/tools.txt || echo "MISSING pwntools" >> /opt/tools.txt) \
 && (VIRTUAL_ENV=/opt/hexstrike-env uv pip install 'angr>=9.2.0,<10.0.0' && echo "OK angr" >> /opt/tools.txt || echo "MISSING angr" >> /opt/tools.txt)
COPY hexstrike_server.py .
COPY --from=entry hexstrike_entry.py .
COPY --from=gotools /go/bin/gau /go/bin/waybackurls /usr/local/bin/
RUN printf 'OK gau (go build)\nOK waybackurls (go build)\n' >> /opt/tools.txt
EXPOSE 8888
CMD ["/opt/hexstrike-env/bin/python", "/opt/hexstrike/hexstrike_entry.py"]

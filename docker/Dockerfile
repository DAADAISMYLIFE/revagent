FROM eclipse-temurin:21-jdk-jammy AS jdk

FROM python:3.12-slim-bookworm

ENV LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive HOME=/root PIP_NO_CACHE_DIR=1

# Native reversing toolchain (explicit list; no recommends).
# radare2 is not packaged in Debian bookworm (removed from the archive); installed below from upstream's .deb release.
RUN apt-get update && apt-get install -y --no-install-recommends \
      binutils gdb gcc g++ gcc-multilib libc6-i386 file strace ltrace \
      curl ca-certificates git make xxd qemu-user-static netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# libssl1.1 for older CTF binaries (not in bookworm). Pinned bullseye build; failure fails the build.
ARG LIBSSL11_URL=http://deb.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.1w-0+deb11u1_amd64.deb
RUN curl -fsSL -o /tmp/libssl1.1.deb "$LIBSSL11_URL" \
    && dpkg -i /tmp/libssl1.1.deb \
    && rm -f /tmp/libssl1.1.deb \
    && ldconfig -p | grep -q 'libssl.so.1.1'

# radare2 (not in Debian bookworm's archive). Pinned upstream release .deb; failure fails the build.
ARG RADARE2_URL=https://github.com/radareorg/radare2/releases/download/6.2.2/radare2_6.2.2_amd64.deb
RUN curl -fsSL -o /tmp/radare2.deb "$RADARE2_URL" \
    && dpkg -i /tmp/radare2.deb \
    && rm -f /tmp/radare2.deb \
    && radare2 -v >/dev/null

# JDK 21 from the official Temurin image (avoids the api.adoptium.net download, which is TLS-intercepted on this network).
# Directory name must start with jdk-21: install_ghidra.sh's `ls -d jdk-21*` and revagent/ghidra.py's `glob("jdk-21*")` both key off it.
RUN mkdir -p /root/tools
COPY --from=jdk /opt/java/openjdk /root/tools/jdk-21-temurin

# Ghidra + JDK 21 under /root/tools (same script as the host install; needs revagent/ghidra_scripts for its verify step).
# GHIDRA_URL pins an exact release for reproducible builds (unset would fall back to a "latest" GitHub
# API lookup, like the host install script does).
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip
COPY scripts/install_ghidra.sh /tmp/scripts/install_ghidra.sh
COPY revagent/ghidra_scripts /tmp/revagent/ghidra_scripts
RUN GHIDRA_URL=$GHIDRA_URL bash /tmp/scripts/install_ghidra.sh \
    && rm -rf /tmp/scripts /tmp/revagent /root/tools/*.zip /root/tools/*.tar.gz /tmp/tmp.*

# Pinned reversing-stack Python packages, installed before the app code so this (large, slow) layer
# caches independently of application source changes.
RUN pip install angr==10.0.0 z3-solver==5.1.0.0 unicorn==2.1.2 capstone==5.0.9 pwntools==4.15.0 \
      pefile==2024.8.26 pycryptodome==3.23.0

# ---- Stage 2: Windows PE execution (wine on Xvfb) + OCR + mingw for test PEs ----
RUN apt-get update && apt-get install -y --no-install-recommends \
      wine wine64 xvfb xdotool x11-utils imagemagick tesseract-ocr tesseract-ocr-eng \
      mingw-w64 fonts-dejavu-core procps \
    && rm -rf /var/lib/apt/lists/*
RUN pip install pillow==12.3.0
ENV DISPLAY=:99 WINEDEBUG=-all WINEPREFIX=/root/.wine
RUN (Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >/dev/null 2>&1 &) && sleep 2 \
    && wineboot -u && wineserver -w \
    && (pkill Xvfb || true)

# Agent code. Editable install so `-v <repo>:/app` overrides code at runtime. openai pinned to the
# version pip last resolved for this image (I2): reproducible builds, no silent API drift.
COPY . /app
RUN pip install -e /app "openai==3.16.2"

COPY docker/entrypoint.sh /usr/local/bin/revagent-entrypoint
RUN chmod +x /usr/local/bin/revagent-entrypoint

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/revagent-entrypoint"]
CMD ["--help"]

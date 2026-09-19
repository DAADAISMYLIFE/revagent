FROM eclipse-temurin:21-jdk-jammy AS jdk

FROM python:3.12-slim-bookworm

ENV LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive HOME=/root PIP_NO_CACHE_DIR=1

# Native reversing toolchain (explicit list; no recommends).
# radare2 is not packaged in Debian bookworm (removed from the archive); installed below from upstream's .deb release.
RUN apt-get update && apt-get install -y --no-install-recommends \
      binutils gdb gcc g++ gcc-multilib libc6-i386 file strace ltrace \
      curl ca-certificates git make xxd qemu-user-static \
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
COPY scripts/install_ghidra.sh /tmp/scripts/install_ghidra.sh
COPY revagent/ghidra_scripts /tmp/revagent/ghidra_scripts
RUN bash /tmp/scripts/install_ghidra.sh && rm -rf /tmp/scripts /tmp/revagent /root/tools/*.zip /root/tools/*.tar.gz

# Agent + Python reversing stack. Editable install so `-v <repo>:/app` overrides code at runtime.
COPY . /app
RUN pip install -e /app \
    && pip install angr z3-solver unicorn capstone pwntools pefile pycryptodome

WORKDIR /work
ENTRYPOINT ["revagent"]
CMD ["--help"]

# ---- Stage 2 (PE verification) layer goes here: wine64 xvfb tesseract-ocr imagemagick ----

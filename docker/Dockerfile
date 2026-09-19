FROM python:3.12-slim-bookworm

ENV LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive HOME=/root PIP_NO_CACHE_DIR=1

# Native reversing toolchain (explicit list; no recommends).
RUN apt-get update && apt-get install -y --no-install-recommends \
      binutils gdb gcc g++ gcc-multilib libc6-i386 file strace ltrace \
      curl ca-certificates git make xxd radare2 qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

# libssl1.1 for older CTF binaries (not in bookworm). Pinned bullseye build; failure fails the build.
ARG LIBSSL11_URL=http://deb.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.1w-0+deb11u1_amd64.deb
RUN curl -fsSL -o /tmp/libssl1.1.deb "$LIBSSL11_URL" \
    && dpkg -i /tmp/libssl1.1.deb \
    && rm -f /tmp/libssl1.1.deb \
    && ldconfig -p | grep -q 'libssl.so.1.1'

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

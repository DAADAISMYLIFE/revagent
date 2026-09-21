FROM eclipse-temurin:21-jdk-jammy AS jdk
# Prune here, in the source stage, so the COPY --from layer below never contains these (a later `rm` in the
# final image would only add an overlay whiteout and save nothing). jmods are jlink inputs; man pages.
RUN rm -rf /opt/java/openjdk/jmods /opt/java/openjdk/man

FROM python:3.12-slim-bookworm

ENV LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive HOME=/root PIP_NO_CACHE_DIR=1

# Native reversing toolchain (explicit list; no recommends).
# radare2 is not packaged in Debian bookworm (removed from the archive); installed below from upstream's .deb release.
# 32-bit: lib32gcc-12-dev + libc6-dev-i386 + lib32stdc++-12-dev give `gcc -m32` AND `g++ -m32` (link included)
# without gcc-multilib's unused x32-ABI libraries. The /usr/include/asm symlink is the one thing gcc-multilib
# itself shipped; `-m32` needs it for <asm/*.h> (e.g. <iostream> -> errno.h). git is not needed by the agent
# (nothing in revagent/ or scripts/ invokes it).
RUN apt-get update && apt-get install -y --no-install-recommends \
      binutils gdb gcc g++ lib32gcc-12-dev libc6-dev-i386 lib32stdc++-12-dev file strace ltrace \
      curl ca-certificates make xxd qemu-user-static netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s x86_64-linux-gnu/asm /usr/include/asm

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
# A full JDK is required (DumpFunctions.java is compiled at runtime); only jmods and man pages are dropped (jdk stage above).
RUN mkdir -p /root/tools
COPY --from=jdk /opt/java/openjdk /root/tools/jdk-21-temurin

# Ghidra under /root/tools (same script as the host install, SKIP_VERIFY=1: the headless verify runs as a
# separate late step below so that editing revagent/ghidra_scripts does not invalidate this layer).
# GHIDRA_URL pins an exact release for reproducible builds (unset would fall back to a "latest" GitHub
# API lookup, like the host install script does).
# Pruned after install: HTML/javadoc docs, optional extension zips, the Ghidra multi-user server, the Windows
# dbgeng debugger agent and per-module *-src.zip source archives. FunctionID, typeinfo, Processors, the
# Decompiler, PyGhidra and the Framework are kept intact.
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip
COPY scripts/install_ghidra.sh /tmp/scripts/install_ghidra.sh
RUN SKIP_VERIFY=1 GHIDRA_URL=$GHIDRA_URL bash /tmp/scripts/install_ghidra.sh \
    && GH="$(ls -d /root/tools/ghidra_*_PUBLIC)" \
    && rm -rf "$GH/docs" "$GH"/Extensions/Ghidra/*.zip "$GH/Ghidra/Features/GhidraServer" "$GH/Ghidra/Debug/Debugger-agent-dbgeng" \
    && find "$GH" -name '*-src.zip' -delete \
    && test -d "$GH/Ghidra/Features/FunctionID" && test -d "$GH/Ghidra/Processors" && test -d "$GH/Ghidra/Features/Decompiler" \
    && rm -rf /root/tools/*.zip /root/tools/*.tar.gz

# Pinned reversing-stack Python packages, installed before the app code so this (large, slow) layer
# caches independently of application source changes. openai pinned to the version pip last resolved
# for this image (I2): reproducible builds, no silent API drift. The z3 wheel ships libz3.so twice
# (libz3.so and libz3.so.5.1, byte-identical); the loader tries the versioned name first, so the plain
# name becomes a symlink.
RUN pip install angr==10.0.0 z3-solver==5.1.0.0 unicorn==2.1.2 capstone==5.0.9 pwntools==4.15.0 \
      pefile==2024.8.26 pycryptodome==3.23.0 pillow==12.3.0 "openai==3.16.2" \
    && Z3LIB="$(python3 -c 'import os, z3; print(os.path.join(os.path.dirname(z3.__file__), "lib"))')" \
    && cmp "$Z3LIB/libz3.so" "$Z3LIB/libz3.so.5.1" \
    && ln -sf libz3.so.5.1 "$Z3LIB/libz3.so" \
    && python3 -c "import z3; print('z3', z3.get_version_string())"

# ---- Stage 2: Windows PE execution (wine on Xvfb) + OCR + mingw for test PEs and solve-time stub DLLs ----
# One mingw-w64 toolchain per arch (posix thread model) instead of the `mingw-w64` metapackage, which also
# pulls in the duplicate win32-thread-model compilers.
RUN apt-get update && apt-get install -y --no-install-recommends \
      wine wine64 xvfb xdotool x11-utils imagemagick tesseract-ocr tesseract-ocr-eng \
      gcc-mingw-w64-x86-64-posix g++-mingw-w64-x86-64-posix gcc-mingw-w64-i686-posix g++-mingw-w64-i686-posix \
      fonts-dejavu-core procps \
    && rm -rf /var/lib/apt/lists/* \
    && x86_64-w64-mingw32-gcc --version >/dev/null && i686-w64-mingw32-gcc --version >/dev/null \
    && x86_64-w64-mingw32-g++ --version >/dev/null && i686-w64-mingw32-g++ --version >/dev/null
# The wine prefix (/root/.wine, ~700 MB, mostly copies of the package's builtin DLLs) is baked in on purpose:
# creating it at container start was measured at 17-22 s per run (WSL2/Docker Desktop), too slow for a per-solve
# container. The entrypoint still runs wineboot if the prefix is missing (e.g. an overridden WINEPREFIX).
ENV DISPLAY=:99 WINEDEBUG=fixme-all WINEPREFIX=/root/.wine
RUN (Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >/dev/null 2>&1 &) && sleep 2 \
    && wineboot -u && wineserver -w \
    && (pkill Xvfb || true) && sleep 1 && rm -rf /tmp/.X99-lock /tmp/.X11-unix/X99 /tmp/wine-*

# Cheap late step: headless Ghidra verify with the agent's DumpFunctions.java (the script part that changes).
COPY revagent/ghidra_scripts /tmp/revagent/ghidra_scripts
RUN bash /tmp/scripts/install_ghidra.sh && rm -rf /tmp/scripts /tmp/revagent /tmp/hsperfdata_root /tmp/root-ghidra

# Agent code. Editable install so `-v <repo>:/app` overrides code at runtime. --no-deps: every runtime
# dependency is already pinned in the pip layer above, so code changes never re-resolve/re-download.
COPY . /app
RUN pip install --no-deps -e /app

COPY docker/entrypoint.sh /usr/local/bin/revagent-entrypoint
RUN chmod +x /usr/local/bin/revagent-entrypoint

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/revagent-entrypoint"]
CMD ["--help"]

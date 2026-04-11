# Dockerfile — mla-transfert-server
# Multi-stage : builder Rust → runtime Debian slim
#
# Variables d'environnement disponibles au runtime :
#   PORT               (défaut : 3001)
#   STORAGE_DIR        (défaut : /data/uploads)
#   MAX_FILE_SIZE_BYTES (défaut : 2147483648 = 2 GB)

# ── Stage 1 : Build ────────────────────────────────────────────────────────────
FROM dhi.io/rust:1-debian13-sfw-ent-dev AS builder

WORKDIR /build

# Copier le workspace complet (nécessaire : mla-transfert-server dépend de mla)
COPY Cargo.toml Cargo.lock ./
COPY mla/              mla/
COPY mlar/             mlar/
COPY bindings/         bindings/
COPY mla-wasm/         mla-wasm/
COPY mla-transfert-server/ mla-transfert-server/

# Build release — on ne compile que le serveur
RUN cargo build --release -p mla-transfert-server

# ── Stage 2 : Runtime ──────────────────────────────────────────────────────────
FROM debian:trixie-slim AS runtime

# Utilisateur non-root pour limiter la surface d'attaque
RUN groupadd --gid 10001 mla && \
    useradd --uid 10001 --gid mla --shell /bin/false --create-home mla

# Répertoire de stockage des fichiers chiffrés uploadés
RUN mkdir -p /data/uploads && chown mla:mla /data/uploads

# Binaire compilé
COPY --from=builder \
     /build/target/release/mla-transfert-server \
     /usr/local/bin/mla-transfert-server

USER mla

EXPOSE 3001

# Volume pour la persistance des uploads entre redémarrages
VOLUME ["/data/uploads"]

ENV STORAGE_DIR=/data/uploads

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:${PORT:-3001}/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/mla-transfert-server"]

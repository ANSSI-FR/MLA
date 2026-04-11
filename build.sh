#!/usr/bin/env bash
# build.sh — Build complet de MLA-Transfert (WASM + web + serveur)
#
# Usage:
#   ./build.sh              # build tout
#   ./build.sh --wasm-only  # rebuild WASM uniquement
#   ./build.sh --skip-wasm  # skip le build WASM (utilise pkg/ existant)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SKIP_WASM=false
WASM_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --skip-wasm) SKIP_WASM=true ;;
    --wasm-only) WASM_ONLY=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

# ── 1. Build WASM ──────────────────────────────────────────────────────────────
if [ "$SKIP_WASM" = false ]; then
  echo "▶ Building mla-wasm..."

  if ! command -v wasm-pack &>/dev/null; then
    echo "  wasm-pack not found — installing..."
    cargo install wasm-pack
  fi

  wasm-pack build mla-wasm --target web --out-dir pkg

  echo "  Copying WASM binary to mla-transfert-web/public/..."
  cp mla-wasm/pkg/mla_wasm_bg.wasm mla-transfert-web/public/

  echo "✓ mla-wasm built"
fi

[ "$WASM_ONLY" = true ] && exit 0

# ── 2. Build frontend Astro ────────────────────────────────────────────────────
echo "▶ Building mla-transfert-web..."

if [ ! -d "mla-transfert-web/node_modules" ]; then
  echo "  Installing npm dependencies..."
  (cd mla-transfert-web && npm install)
fi

(cd mla-transfert-web && npm run build)
echo "✓ mla-transfert-web built → mla-transfert-web/dist/"

# ── 3. Build serveur Rust ──────────────────────────────────────────────────────
echo "▶ Building mla-transfert-server..."
cargo build --release -p mla-transfert-server
echo "✓ mla-transfert-server built → target/release/mla-transfert-server"

# ── Résumé ─────────────────────────────────────────────────────────────────────
echo ""
echo "Build complet. Pour lancer localement :"
echo "  ./target/release/mla-transfert-server"
echo "  cd mla-transfert-web && npm run preview"

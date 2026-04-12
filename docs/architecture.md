# MLA-Share — Architecture & Workflow de déploiement

Date : 2026-04-12

---

## Architecture globale

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          NAVIGATEUR (client)                            │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  mla-transfert-web  (Astro + React)                              │   │
│  │                                                                  │   │
│  │  ┌──────────────┐   ┌─────────────────────────────────────────┐  │   │
│  │  │  SendForm    │   │  ReceiveForm                            │  │   │
│  │  │  FileDropZone│   │  PasswordInput / KeyImporter            │  │   │
│  │  │  ModeSelector│   │  TransferProgress                       │  │   │
│  │  └──────┬───────┘   └────────────────┬────────────────────────┘  │   │
│  │         │                            │                           │   │
│  │         ▼                            ▼                           │   │
│  │  ┌──────────────────────────────────────────────────────────┐    │   │
│  │  │  mla-wasm  (Rust → WebAssembly)                          │    │   │
│  │  │                                                          │    │   │
│  │  │  encrypt_with_password / decrypt_with_password (Argon2id)│    │   │
│  │  │  encrypt_with_keys / decrypt_with_keys (X25519+ML-KEM)   │    │   │
│  │  │  generate_keypair()                                      │    │   │
│  │  │                                                          │    │   │
│  │  │  Cryptographie : MLA (ANSSI) — post-quantique hybride    │    │   │
│  │  │  X25519 + ML-KEM 1024 | Ed25519 + ML-DSA 87 | AES-256-GCM    │   │
│  │  └──────────────────────────────────────────────────────────┘    │   │
│  │                                                                  │   │
│  │  ┌──────────────────────────────────────────────────────────┐    │   │
│  │  │  api.ts                          webrtc.ts               │    │   │
│  │  │  POST /api/upload                WebRTC P2P (optionnel)  │    │   │
│  │  │  GET  /api/download/:id          WS /api/signal/:room    │    │   │
│  │  │  GET  /api/info/:id                                      │    │   │
│  │  └──────────────────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │  HTTPS  (données chiffrées uniquement)
                               │
        ┌──────────────────────▼──────────────────────┐
        │  Cloudflare (réseau de distribution)         │
        │                                              │
        │  ┌────────────────────────────────────────┐  │
        │  │  Cloudflare Pages                      │  │
        │  │  mla-transfert-web (frontend SSR/SPA)  │  │
        │  │  https://mla-share.kodetis.cloud       │  │
        │  └────────────────────────────────────────┘  │
        │                                              │
        │  ┌────────────────────────────────────────┐  │
        │  │  Cloudflare Worker (route api/*)        │  │
        │  │  mla-transfert-worker (Rust/WASM)       │  │
        │  │                                         │  │
        │  │  POST  /api/upload   → R2 + KV (TTL)   │  │
        │  │  GET   /api/download → R2               │  │
        │  │  GET   /api/info     → KV               │  │
        │  │  WS    /api/signal   → Durable Object   │  │
        │  │  (SignalRoom WebRTC)                    │  │
        │  └──────────────┬─────────────────────────┘  │
        │                 │                             │
        │  ┌──────────────▼─────────────────────────┐  │
        │  │  R2 Storage          KV Store           │  │
        │  │  fichiers chiffrés   métadonnées + TTL  │  │
        │  │  (binaire opaque,    (id → expiry,      │  │
        │  │   jamais en clair)    taille, type)     │  │
        │  └────────────────────────────────────────┘  │
        └──────────────────────────────────────────────┘
```

---

## Propriété zero-knowledge

```
Expéditeur (navigateur)
  │
  ├─ Sélectionne le(s) fichier(s)
  ├─ Chiffre DANS le navigateur via mla-wasm
  │   Mode mot de passe : Argon2id → clé → AES-256-GCM
  │   Mode clés MLA    : X25519+ML-KEM → clé éphémère → AES-256-GCM
  │
  └─► Envoie le ciphertext opaque au Worker
          (le serveur ne voit JAMAIS le fichier en clair)
          (le mot de passe / les clés ne quittent JAMAIS le navigateur)

Worker / R2 Storage
  └─ Stocke des octets chiffrés + métadonnées non-sensibles
     Suppression automatique à l'expiration (TTL KV)

Destinataire (navigateur)
  ├─ Télécharge le ciphertext
  ├─ Déchiffre DANS le navigateur via mla-wasm
  │   (saisit le mot de passe OU importe sa clé privée .mlapriv)
  └─► Télécharge le(s) fichier(s) en clair localement
```

---

## Workflow de déploiement (GitHub Actions)

```
git push → main
     │
     ▼
┌─────────────────────────────────────────────────────┐
│  GitHub Actions  (.github/workflows/deploy.yml)     │
│                                                     │
│  1. Checkout du repo                                │
│                                                     │
│  2. ── Rust + WASM ─────────────────────────────    │
│     dtolnay/rust-toolchain@stable                   │
│     target: wasm32-unknown-unknown                  │
│     Cache: ~/.cargo + mla-wasm/target               │
│                                                     │
│     cargo install wasm-pack --locked --version 0.13.1   │
│     (pinned — pas de curl|sh)                       │
│                                                     │
│     wasm-pack build --target web --release          │
│     → mla-wasm/pkg/  (jamais commité dans le repo)  │
│                                                     │
│  3. ── Node + Astro ────────────────────────────    │
│     actions/setup-node@v4 (Node 22)                 │
│     Cache npm : mla-transfert-web/package-lock.json │
│                                                     │
│     npm ci                                          │
│     npm run build                                   │
│     PUBLIC_API_URL=https://mla-share.kodetis.cloud  │
│     (baked à la compilation — pas de runtime var)   │
│     → mla-transfert-web/dist/                       │
│                                                     │
│  4. ── Deploy Cloudflare Pages ─────────────────    │
│     CLOUDFLARE_API_TOKEN  ← secret repo GitHub      │
│     CLOUDFLARE_ACCOUNT_ID ← secret repo GitHub      │
│                                                     │
│     npx wrangler pages deploy dist                  │
│       --project-name mla-transfert-web              │
│       --branch main                                 │
│       --commit-message "CI deploy ${GITHUB_SHA::8}" │
│                                                     │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │  Cloudflare Pages            │
        │  projet : mla-transfert-web  │
        │  production branch : main    │
        │                              │
        │  → https://mla-share.kodetis.cloud  │
        └──────────────────────────────┘
```

---

## Sécurité supply chain (WASM)

```
Repo public GitHub
  │
  ├── mla-wasm/src/   ← sources Rust (auditables)
  ├── mla-wasm/Cargo.lock  ← dépendances verrouillées
  │
  └── mla-wasm/pkg/   ← GITIGNORE (jamais commité)
                          binaire WASM reconstruit à chaque CI

Risque mitigé : un attaquant ne peut pas pousser un binaire WASM
malveillant dans le repo — il faudrait compromettre la pipeline CI
et les secrets GitHub.

wasm-pack est installé via cargo install --locked (pas de curl|sh).
```

---

## Secrets & configuration

| Secret | Stockage | Usage |
|--------|----------|-------|
| `CLOUDFLARE_API_TOKEN` | GitHub repo secrets | wrangler pages deploy |
| `CLOUDFLARE_ACCOUNT_ID` | GitHub repo secrets | wrangler pages deploy |
| `ALLOWED_ORIGIN` | Cloudflare Worker env vars (dashboard) | CORS restriction |
| `MAX_FILE_SIZE_BYTES` | Cloudflare Worker env vars (dashboard) | Limite upload |

Aucun secret dans le code source. `wrangler.toml` est gitignore.

---

## Domaines & routes

| URL | Service |
|-----|---------|
| `https://mla-share.kodetis.cloud` | Cloudflare Pages (frontend) |
| `https://mla-share.kodetis.cloud/api/*` | Cloudflare Worker (prioritaire sur Pages) |
| `https://mla-share.kodetis.cloud/receive/:id` | Pages (page de réception) |

---

## Stack technique

| Couche | Technologie |
|--------|-------------|
| Frontend | Astro 5 + React 19 + TailwindCSS |
| Crypto client | Rust → WebAssembly (wasm-pack) |
| Lib crypto | ANSSI MLA (format d'archive post-quantique) |
| Worker | Rust (worker-rs 0.8) → WASM |
| Stockage fichiers | Cloudflare R2 |
| Métadonnées / TTL | Cloudflare KV |
| Signaling WebRTC | Cloudflare Durable Objects |
| CI/CD | GitHub Actions |
| DNS / CDN | Cloudflare (zone kodetis.cloud) |

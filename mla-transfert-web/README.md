# mla-transfert-web

Service de transfert de fichiers chiffrés par MLA, un format d'archive post-quantique certifié ANSSI. Le chiffrement s'effectue intégralement dans le navigateur (zero-knowledge) : le serveur ne voit jamais les données en clair.

## Architecture

Le projet est composé de trois sous-projets dans le workspace Cargo/npm :

| Composant | Technologie | Role |
|---|---|---|
| `mla-wasm` | Rust + wasm-bindgen | Bindings WebAssembly de la lib MLA |
| `mla-transfert-web` | Astro 5 + React 19 + TailwindCSS | Interface utilisateur |
| `mla-transfert-server` | Axum (Rust) | Relais chiffre et signaling WebRTC |

## Prerequis

- Rust stable (`rustup update stable`)
- `wasm-pack` (`cargo install wasm-pack`)
- Node.js 22
- npm

## Lancement local

```bash
# 1. Build WASM et copie dans public/
./build.sh --wasm-only

# 2. Demarrer le serveur (port 3001 par defaut)
./target/release/mla-transfert-server &

# 3. Demarrer le frontend en mode dev (port 4322)
cd mla-transfert-web && npm run dev
```

L'interface est disponible sur `http://localhost:4322`.

## Variables d'environnement

### Frontend (`mla-transfert-web`)

| Variable | Defaut | Description |
|---|---|---|
| `PUBLIC_API_URL` | `http://localhost:3001` | URL du serveur backend |

A definir dans `mla-transfert-web/.env` :

```env
PUBLIC_API_URL=https://transfert.example.com
```

### Serveur (`mla-transfert-server`)

| Variable | Defaut | Description |
|---|---|---|
| `PORT` | `3001` | Port d'ecoute |
| `STORAGE_DIR` | `./data/uploads` | Repertoire de stockage des archives chiffrees |
| `MAX_FILE_SIZE_BYTES` | `2147483648` (2 Go) | Taille maximale d'un fichier uploade |

## Modes de chiffrement

### Mode mot de passe

L'expediteur et le destinataire partagent un mot de passe. Une paire de cles MLA est derivee a partir de ce mot de passe via Argon2id. Aucune cle n'est echangee explicitement.

Cas d'usage : transfert ponctuel sans echange de cles prealable.

### Mode cles MLA

L'expediteur chiffre avec sa cle privee et la cle publique du destinataire. Le destinataire dechiffre avec sa cle privee et verifie la signature via la cle publique de l'expediteur (chiffrement authentifie).

Cas d'usage : correspondants recurrents disposant chacun d'une paire de cles MLA.

## Modes de transport

### Relais serveur

Les donnees chiffrees sont uploadees sur le serveur via `POST /api/upload`. Le serveur genere un lien de telechargement (`GET /api/download/:id`) partage avec le destinataire. Les fichiers sont purges automatiquement a expiration.

### P2P WebRTC

Le serveur sert uniquement de canal de signaling (`GET /api/signal/:room` via WebSocket). Les donnees transitent directement entre les navigateurs, sans passer par le serveur.

## Endpoints serveur

| Methode | Chemin | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/upload` | Upload d'une archive MLA chiffree |
| `GET` | `/api/download/:id` | Telechargement d'une archive par identifiant |
| `GET` | `/api/info/:id` | Metadonnees d'un transfert (taille, expiration) |
| `GET` | `/api/signal/:room` | WebSocket de signaling WebRTC |

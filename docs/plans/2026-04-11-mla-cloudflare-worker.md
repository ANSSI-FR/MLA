# MLA-Transfert Cloudflare Worker — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Porter `mla-transfert-server` (Axum/Tokio) vers un Cloudflare Worker Rust (`worker-rs`) avec stockage R2, métadonnées KV, et signaling WebRTC via Durable Objects.

**Architecture:** Nouveau crate `mla-transfert-worker` compilé en `wasm32-unknown-unknown` via `wrangler`. Les fichiers chiffrés sont stockés dans Cloudflare R2 (S3-compatible). Les métadonnées de transfert sont stockées dans KV Workers avec TTL natif (remplace la purge task). Le signaling WebRTC est géré par un Durable Object `SignalRoom` qui maintient les WebSocket sessions par room.

**Tech Stack:** `worker` crate 0.4, `serde_json`, `uuid` (feature `js`), `wrangler` CLI, Cloudflare R2 + KV + Durable Objects.

**Note frontend:** Ce plan suppose que le frontend (Astro+React ou Vue+Vite) est déployé séparément sur Cloudflare Pages. La variable `PUBLIC_API_URL` pointera vers le Worker déployé.

**Note repo:** Projet sur GitHub (`Kodetis/MLA-Transfert`) → utiliser `gh` (pas `glab`).

---

## Prérequis

Avant de commencer :

```bash
# Installer wrangler
npm install -g wrangler

# S'authentifier à Cloudflare
wrangler login

# Créer le bucket R2 (une seule fois)
wrangler r2 bucket create mla-transfers

# Créer le namespace KV (une seule fois)
wrangler kv:namespace create TRANSFERS_KV
# → noter l'ID retourné, à mettre dans wrangler.toml

# Vérifier la toolchain Rust WASM
rustup target add wasm32-unknown-unknown
```

---

## File Structure

```
mla-transfert-worker/
├── Cargo.toml       # crate-type cdylib, worker-rs deps
├── wrangler.toml    # bindings R2 / KV / Durable Objects
└── src/
    ├── lib.rs       # #[event(fetch)] entry point + router
    ├── cors.rs      # CORS headers helper
    ├── error.rs     # json_err() helper
    ├── upload.rs    # POST /api/upload → R2 + KV
    ├── download.rs  # GET /api/download/:id → R2
    ├── info.rs      # GET /api/info/:id → KV
    └── signal.rs    # Durable Object SignalRoom (WebSocket)
```

**Modifications workspace :**
- Modify: `Cargo.toml` (root) — ajouter `mla-transfert-worker` aux members
- Ne pas supprimer `mla-transfert-server` : garder les deux (server = déploiement VPS, worker = déploiement CF)

---

## Task 1 : Scaffold du crate et wrangler.toml

**Files:**
- Modify: `Cargo.toml` (root workspace)
- Create: `mla-transfert-worker/Cargo.toml`
- Create: `mla-transfert-worker/wrangler.toml`
- Create: `mla-transfert-worker/src/lib.rs`

- [ ] **Step 1 : Ajouter au workspace**

Dans `Cargo.toml` (racine), ajouter `"mla-transfert-worker"` aux members :

```toml
[workspace]
members = [
    "mla",
    "mla-fuzz-afl",
    "mlar",
    "mlar/mlar-upgrader",
    "bindings/C",
    "mla-wasm",
    "mla-transfert-server",
    "mla-transfert-worker",
]
```

- [ ] **Step 2 : Créer `mla-transfert-worker/Cargo.toml`**

```toml
[package]
name = "mla-transfert-worker"
version = "0.1.0"
edition = "2024"
license = "LGPL-3.0-only"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
worker = { version = "0.4", features = ["d1"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "js"] }
getrandom = { version = "0.2", features = ["js"] }

[lints]
workspace = true
```

- [ ] **Step 3 : Créer `mla-transfert-worker/wrangler.toml`**

Remplacer `<KV_NAMESPACE_ID>` par l'ID obtenu via `wrangler kv:namespace create TRANSFERS_KV`.

```toml
name = "mla-transfert-worker"
main = "build/worker/shim.mjs"
compatibility_date = "2025-01-01"

# Limite de taille upload (2 Go = limite CF Enterprise, 100 Mo sur free)
# Sur le plan free, body max = 100 Mo
[limits]
cpu_ms = 50

[[r2_buckets]]
binding = "BUCKET"
bucket_name = "mla-transfers"
preview_bucket_name = "mla-transfers-preview"

[[kv_namespaces]]
binding = "TRANSFERS_KV"
id = "<KV_NAMESPACE_ID>"

[durable_objects]
bindings = [
  { name = "SIGNAL_ROOM", class_name = "SignalRoom" }
]

[[migrations]]
tag = "v1"
new_classes = ["SignalRoom"]

[vars]
MAX_FILE_SIZE_BYTES = "104857600"  # 100 Mo (plan free CF)
```

- [ ] **Step 4 : Créer `mla-transfert-worker/src/lib.rs` (squelette)**

```rust
use worker::*;

mod cors;
mod download;
mod error;
mod info;
mod signal;
mod upload;

pub use signal::SignalRoom;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .get("/api/health", |_, _| Response::ok("ok"))
        .post_async("/api/upload", upload::handle)
        .get_async("/api/download/:id", download::handle)
        .get_async("/api/info/:id", info::handle)
        .get_async("/api/signal/:room", signal::handle)
        .run(req, env)
        .await
}
```

- [ ] **Step 5 : Créer les stubs pour compiler**

Créer `mla-transfert-worker/src/error.rs` :

```rust
use worker::{Response, Result};

pub fn json_err(status: u16, message: &str) -> Result<Response> {
    let body = serde_json::json!({ "error": message }).to_string();
    Response::error(body, status)
}
```

Créer `mla-transfert-worker/src/cors.rs` :

```rust
use worker::{Headers, Response, Result};

/// Ajoute les headers CORS à une réponse existante.
pub fn add_cors(mut res: Response) -> Result<Response> {
    let headers = res.headers_mut();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Content-Type")?;
    Ok(res)
}
```

Créer `mla-transfert-worker/src/upload.rs` (stub) :

```rust
use worker::{Request, Response, Result, RouteContext};

pub async fn handle(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    Response::error("not implemented", 501)
}
```

Créer `mla-transfert-worker/src/download.rs` (stub) :

```rust
use worker::{Request, Response, Result, RouteContext};

pub async fn handle(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let _id = ctx.param("id").unwrap_or_default();
    Response::error("not implemented", 501)
}
```

Créer `mla-transfert-worker/src/info.rs` (stub) :

```rust
use worker::{Request, Response, Result, RouteContext};

pub async fn handle(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let _id = ctx.param("id").unwrap_or_default();
    Response::error("not implemented", 501)
}
```

Créer `mla-transfert-worker/src/signal.rs` (stub Durable Object) :

```rust
use worker::*;

pub async fn handle(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let room = ctx.param("room").unwrap_or("default").to_string();
    let namespace = ctx.durable_object("SIGNAL_ROOM")?;
    let stub = namespace.id_from_name(&room)?.get_stub()?;
    stub.fetch_with_request(req).await
}

#[durable_object]
pub struct SignalRoom {
    state: State,
    _env: Env,
}

#[durable_object]
impl DurableObject for SignalRoom {
    fn new(state: State, env: Env) -> Self {
        Self { state, _env: env }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        self.state.accept_web_socket(&server);
        Response::from_websocket(pair.client)
    }

    async fn websocket_message(
        &mut self,
        _ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let sessions = self.state.get_web_sockets();
        for session in &sessions {
            match &message {
                WebSocketIncomingMessage::String(s) => {
                    let _ = session.send_with_str(s);
                }
                WebSocketIncomingMessage::Binary(b) => {
                    let _ = session.send_with_bytes(b);
                }
            }
        }
        Ok(())
    }

    async fn websocket_close(
        &mut self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&mut self, _ws: WebSocket, _error: worker::Error) -> Result<()> {
        Ok(())
    }
}
```

- [ ] **Step 6 : Vérifier que ça compile en WASM**

```bash
cd mla-transfert-worker
wrangler build
```

Expected : build OK, pas d'erreurs. Warnings acceptables.

- [ ] **Step 7 : Commit**

```bash
git add mla-transfert-worker/ Cargo.toml
git commit -m "feat(worker): scaffold Cloudflare Worker crate with stubs"
```

---

## Task 2 : POST /api/upload → R2 + KV

**Files:**
- Modify: `mla-transfert-worker/src/upload.rs`

Le handler parse le body multipart, stocke le fichier dans R2, et les métadonnées dans KV avec TTL.

- [ ] **Step 1 : Structure de métadonnées**

Au début de `upload.rs` :

```rust
use serde::{Deserialize, Serialize};
use worker::{FormData, FormEntry, Request, Response, Result, RouteContext};

use crate::cors::add_cors;
use crate::error::json_err;

#[derive(Serialize, Deserialize)]
pub struct TransferMeta {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub expires_in_hours: u64,
}
```

- [ ] **Step 2 : Implémenter le handler upload**

```rust
pub async fn handle(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    // Lire la limite depuis les variables d'environnement
    let max_bytes: u64 = ctx
        .env
        .var("MAX_FILE_SIZE_BYTES")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(104_857_600); // 100 Mo par défaut

    let form: FormData = req.form_data().await?;

    // Extraire le champ "file"
    let (filename, file_bytes) = match form.get("file") {
        Some(FormEntry::File(f)) => {
            let name = f.name();
            let bytes = f.bytes().await?;
            (name, bytes)
        }
        _ => return json_err(400, "missing file field"),
    };

    // Extraire "expires_hours" (optionnel, défaut 24h)
    let expires_hours: u64 = match form.get("expires_hours") {
        Some(FormEntry::Field(s)) => match s.as_str() {
            "1" => 1,
            "168" => 168,
            _ => 24,
        },
        _ => 24,
    };

    let size = file_bytes.len() as u64;

    if size > max_bytes {
        return json_err(413, "file exceeds maximum size");
    }

    // Générer un ID unique
    let id = uuid::Uuid::new_v4().to_string();

    // Stocker le fichier dans R2
    let bucket = ctx.env.bucket("BUCKET")?;
    bucket.put(&id, file_bytes).execute().await?;

    // Stocker les métadonnées dans KV avec TTL
    let meta = TransferMeta {
        id: id.clone(),
        filename,
        size,
        expires_in_hours,
    };
    let kv = ctx.env.kv("TRANSFERS_KV")?;
    kv.put(&id, serde_json::to_string(&meta)?)?
        .expiration_ttl(expires_hours * 3600)
        .execute()
        .await?;

    // Réponse JSON
    let body = serde_json::json!({
        "id": id,
        "expires_in_hours": expires_hours,
    });
    let res = Response::from_json(&body)?;
    add_cors(res)
}
```

- [ ] **Step 3 : Build**

```bash
wrangler build
```

Expected : OK

- [ ] **Step 4 : Test local avec wrangler dev**

```bash
wrangler dev
```

Dans un autre terminal :

```bash
# Upload un fichier test
curl -X POST http://localhost:8787/api/upload \
  -F "file=@/tmp/test.txt" \
  -F "expires_hours=1"
```

Expected : `{"id":"<uuid>","expires_in_hours":1}`

- [ ] **Step 5 : Commit**

```bash
git add mla-transfert-worker/src/upload.rs
git commit -m "feat(worker): implement POST /api/upload with R2 + KV storage"
```

---

## Task 3 : GET /api/download/:id → R2

**Files:**
- Modify: `mla-transfert-worker/src/download.rs`

- [ ] **Step 1 : Implémenter le handler download**

```rust
use worker::{Request, Response, Result, RouteContext};

use crate::cors::add_cors;
use crate::error::json_err;

pub async fn handle(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = match ctx.param("id") {
        Some(id) => id.to_string(),
        None => return json_err(400, "missing id"),
    };

    // Vérifier que le transfert existe dans KV (gère l'expiration)
    let kv = ctx.env.kv("TRANSFERS_KV")?;
    if kv.get(&id).text().await?.is_none() {
        return json_err(410, "transfer expired or not found");
    }

    // Récupérer le fichier depuis R2
    let bucket = ctx.env.bucket("BUCKET")?;
    let object = match bucket.get(&id).execute().await? {
        Some(obj) => obj,
        None => return json_err(404, "file not found"),
    };

    let bytes = match object.body() {
        Some(body) => body.bytes().await?,
        None => return json_err(404, "empty file"),
    };

    let mut res = Response::from_bytes(bytes)?;
    res.headers_mut()
        .set("Content-Type", "application/octet-stream")?;
    add_cors(res)
}
```

- [ ] **Step 2 : Test local**

```bash
# Récupérer l'ID de l'upload du Task 2, puis :
curl http://localhost:8787/api/download/<id> --output /tmp/downloaded.bin
file /tmp/downloaded.bin
```

Expected : même type que le fichier uploadé.

- [ ] **Step 3 : Commit**

```bash
git add mla-transfert-worker/src/download.rs
git commit -m "feat(worker): implement GET /api/download/:id from R2"
```

---

## Task 4 : GET /api/info/:id → KV

**Files:**
- Modify: `mla-transfert-worker/src/info.rs`

- [ ] **Step 1 : Implémenter le handler info**

```rust
use worker::{Request, Response, Result, RouteContext};

use crate::cors::add_cors;
use crate::error::json_err;
use crate::upload::TransferMeta;

pub async fn handle(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let id = match ctx.param("id") {
        Some(id) => id.to_string(),
        None => return json_err(400, "missing id"),
    };

    let kv = ctx.env.kv("TRANSFERS_KV")?;
    let raw = match kv.get(&id).text().await? {
        Some(v) => v,
        None => return json_err(410, "transfer expired or not found"),
    };

    let meta: TransferMeta = match serde_json::from_str(&raw) {
        Ok(m) => m,
        Err(_) => return json_err(500, "corrupted metadata"),
    };

    // KV ne donne pas le TTL restant directement.
    // On retourne expires_in_hours * 3600 comme approximation.
    // Pour une valeur précise, stocker created_at dans les métadonnées.
    let body = serde_json::json!({
        "id": meta.id,
        "size": meta.size,
        "expires_in_seconds": meta.expires_in_hours * 3600,
    });

    let res = Response::from_json(&body)?;
    add_cors(res)
}
```

- [ ] **Step 2 : Test local**

```bash
curl http://localhost:8787/api/info/<id>
```

Expected : `{"id":"...","size":N,"expires_in_seconds":3600}`

- [ ] **Step 3 : Commit**

```bash
git add mla-transfert-worker/src/info.rs
git commit -m "feat(worker): implement GET /api/info/:id from KV"
```

---

## Task 5 : CORS preflight OPTIONS

**Files:**
- Modify: `mla-transfert-worker/src/lib.rs`

Le navigateur envoie une requête OPTIONS avant tout POST cross-origin. Sans ça, l'upload échoue.

- [ ] **Step 1 : Ajouter le handler OPTIONS dans le router**

Dans `lib.rs`, mettre à jour le router :

```rust
use worker::*;

mod cors;
mod download;
mod error;
mod info;
mod signal;
mod upload;

pub use signal::SignalRoom;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Gérer le preflight CORS pour toutes les routes
    if req.method() == Method::Options {
        let mut res = Response::empty()?;
        let h = res.headers_mut();
        h.set("Access-Control-Allow-Origin", "*")?;
        h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
        h.set("Access-Control-Allow-Headers", "Content-Type")?;
        h.set("Access-Control-Max-Age", "86400")?;
        return Ok(res);
    }

    Router::new()
        .get("/api/health", |_, _| Response::ok("ok"))
        .post_async("/api/upload", upload::handle)
        .get_async("/api/download/:id", download::handle)
        .get_async("/api/info/:id", info::handle)
        .get_async("/api/signal/:room", signal::handle)
        .run(req, env)
        .await
}
```

- [ ] **Step 2 : Test preflight**

```bash
curl -X OPTIONS http://localhost:8787/api/upload \
  -H "Origin: http://localhost:4322" \
  -H "Access-Control-Request-Method: POST" \
  -v 2>&1 | grep "Access-Control"
```

Expected : les 3 headers `Access-Control-Allow-*` présents dans la réponse.

- [ ] **Step 3 : Commit**

```bash
git add mla-transfert-worker/src/lib.rs
git commit -m "feat(worker): add CORS preflight OPTIONS handler"
```

---

## Task 6 : Durable Object SignalRoom (WebSocket signaling)

**Files:**
- Modify: `mla-transfert-worker/src/signal.rs`

Remplacer le stub par l'implémentation complète. Le DO maintient les sessions WebSocket par room et broadcast les messages.

- [ ] **Step 1 : Implémenter SignalRoom complet**

```rust
use worker::*;

/// Route HTTP → Durable Object
pub async fn handle(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let room = ctx.param("room").unwrap_or("default").to_string();
    let namespace = ctx.env.durable_object("SIGNAL_ROOM")?;
    let stub = namespace.id_from_name(&room)?.get_stub()?;
    stub.fetch_with_request(req).await
}

#[durable_object]
pub struct SignalRoom {
    state: State,
    _env: Env,
}

#[durable_object]
impl DurableObject for SignalRoom {
    fn new(state: State, env: Env) -> Self {
        Self { state, _env: env }
    }

    /// Upgrade HTTP → WebSocket et enregistrer la session
    async fn fetch(&mut self, _req: Request) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        // Hibernating WebSocket : le DO peut être suspendu entre messages
        self.state.accept_web_socket(&server);
        Response::from_websocket(pair.client)
    }

    /// Message reçu → broadcast à toutes les autres sessions de la room
    async fn websocket_message(
        &mut self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let sessions = self.state.get_web_sockets();
        // Identifier la session émettrice pour ne pas lui renvoyer le message
        let sender_id = ws
            .deserialize_attachment::<String>()
            .ok()
            .flatten()
            .unwrap_or_default();

        for session in &sessions {
            let session_id = session
                .deserialize_attachment::<String>()
                .ok()
                .flatten()
                .unwrap_or_default();
            if session_id == sender_id {
                continue;
            }
            match &message {
                WebSocketIncomingMessage::String(s) => {
                    let _ = session.send_with_str(s);
                }
                WebSocketIncomingMessage::Binary(b) => {
                    let _ = session.send_with_bytes(b);
                }
            }
        }
        Ok(())
    }

    async fn websocket_close(
        &mut self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&mut self, _ws: WebSocket, _error: worker::Error) -> Result<()> {
        Ok(())
    }
}
```

- [ ] **Step 2 : Build**

```bash
wrangler build
```

Expected : OK

- [ ] **Step 3 : Test signaling (deux terminaux)**

Terminal 1 :
```bash
wrangler dev
```

Terminal 2 (session A) :
```bash
wscat -c "ws://localhost:8787/api/signal/test-room"
```

Terminal 3 (session B) :
```bash
wscat -c "ws://localhost:8787/api/signal/test-room"
# Taper un message → vérifier qu'il apparaît dans Terminal 2
```

Expected : les messages de B arrivent dans A et vice-versa.

Note : `wscat` s'installe avec `npm install -g wscat`

- [ ] **Step 4 : Commit**

```bash
git add mla-transfert-worker/src/signal.rs
git commit -m "feat(worker): implement SignalRoom Durable Object for WebRTC signaling"
```

---

## Task 7 : Déploiement Cloudflare + CI/CD

**Files:**
- Modify: `.github/workflows/mla-transfert.yml`

- [ ] **Step 1 : Déploiement manuel (vérification)**

```bash
cd mla-transfert-worker
wrangler deploy
```

Expected : URL du worker affichée, ex: `https://mla-transfert-worker.<account>.workers.dev`

Tester :
```bash
curl https://mla-transfert-worker.<account>.workers.dev/api/health
# → ok
```

- [ ] **Step 2 : Ajouter le secret `CLOUDFLARE_API_TOKEN` dans GitHub**

Aller sur https://dash.cloudflare.com/profile/api-tokens → créer un token avec permission `Workers Scripts: Edit`.

Dans les settings GitHub du repo → Secrets → `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`.

- [ ] **Step 3 : Ajouter le job de déploiement dans `.github/workflows/mla-transfert.yml`**

Ajouter après le job `docker` existant :

```yaml
  # ── Deploy Worker (main uniquement) ──────────────────────────────────────────
  deploy-worker:
    name: Deploy Cloudflare Worker
    runs-on: ubuntu-24.04
    needs: [ test-server, lint-transfert ]
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2

      - name: Setup Node.js (for wrangler)
        uses: actions/setup-node@cdca7365b2dadb8aad0a33bc7601856ffabcc48e # v4.3.0
        with:
          node-version: '22'

      - name: Install wrangler
        run: npm install -g wrangler

      - name: Install Rust WASM target
        run: rustup target add wasm32-unknown-unknown

      - name: Deploy Worker
        working-directory: mla-transfert-worker
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
        run: wrangler deploy
```

- [ ] **Step 4 : Commit**

```bash
git add .github/workflows/mla-transfert.yml
git commit -m "ci: add Cloudflare Worker deploy job on main push"
```

---

## Task 8 : Mise à jour du frontend (PUBLIC_API_URL)

**Files:**
- Modify: `mla-transfert-web/astro.config.mjs` (ou `vite.config.ts` si migration Vue+Vite)
- Modify: `.github/workflows/mla-transfert.yml`

Le frontend doit pointer vers le Worker CF en production, et continuer à pointer vers `localhost:8787` en développement.

- [ ] **Step 1 : Variable d'env déjà gérée**

`mla-transfert-web/src/lib/api.ts` contient déjà :
```typescript
const API_BASE = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:8787';
```

Changer le fallback de `3001` à `8787` (port de `wrangler dev`) :

```typescript
// Avant :
const API_BASE = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:3001';
// Après :
const API_BASE = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:8787';
```

- [ ] **Step 2 : Ajouter la variable dans GitHub**

Dans les settings GitHub → Variables (pas Secrets) → `PUBLIC_API_URL` = `https://mla-transfert-worker.<account>.workers.dev`

Le job `build-web` existant utilise déjà `${{ vars.PUBLIC_API_URL }}`.

- [ ] **Step 3 : Commit**

```bash
git add mla-transfert-web/src/lib/api.ts
git commit -m "fix(web): update default API URL to wrangler dev port 8787"
```

---

## Limites Cloudflare à connaître

| Plan | Limite upload | Remarque |
|------|--------------|----------|
| Free | 100 Mo / requête | OK pour fichiers bureautiques |
| Paid (Workers Paid) | 500 Mo / requête | Suffisant pour la plupart des usages |
| Enterprise | Sans limite pratique | |

**R2 :** pas de limite de taille par objet, facturation à l'usage (10 Go/mois gratuits).

**KV TTL :** minimum 60 secondes. L'option "1 heure" du frontend fonctionne.

**Durable Objects :** disponibles sur Workers Paid uniquement (pas sur le plan free).
Si le mode P2P WebRTC n'est pas prioritaire, le DO peut être omis en phase initiale.

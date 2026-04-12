# Audit Sécurité — MLA-Share
**Date :** 2026-04-12 (mis à jour après Sprints 1–3)
**Périmètre :** `mla-transfert-server` (Rust/Axum), `mla-transfert-web` (Astro/React/TS), `mla-wasm` (Rust/WASM), pipeline CI (Dagger/Python)
**Branche :** `feature-ci-security`

---

## Score de posture : 78 / 100

| Catégorie | Avant | Après S1–S3 | Δ |
|---|---|---|---|
| Cryptographie & chiffrement | 90/100 | 88/100 | -2 (M5 incomplet) |
| Headers HTTP de sécurité | 20/100 | 38/100 | +18 (referrer+fonts; CSP manquant) |
| Contrôle d'accès & rate limiting | 15/100 | 70/100 | +55 (tower_governor + CORS fixé) |
| Upload & validation des entrées | 55/100 | 82/100 | +27 (streaming + sanitize filename) |
| Signaling WebRTC | 45/100 | 60/100 | +15 (room cap + TTL; JSON validation manquante) |
| Gestion des erreurs | 70/100 | 72/100 | +2 (error.rs générique; direct JsValue encore) |
| Dépendances & CI | 75/100 | 72/100 | -3 (curl\|sh non fixé, pas de cargo deny) |

---

## Findings résolus (Sprints 1–3)

### ✅ [HIGH] H1 — Rate limiting absent
**Fix :** `tower_governor` (20 req/s, burst 40) via `SmartIpKeyExtractor`. `axum::serve` migré en `into_make_service_with_connect_info`.
**Commit :** Sprint 2

### ✅ [HIGH] H2 — CORS permissif (`CorsLayer::permissive()`)
**Fix :** `ALLOWED_ORIGIN` env var → `AllowOrigin::exact()`, méthodes restreintes à GET/POST.
**Fichier :** `mla-transfert-server/src/main.rs`
**Commit :** Sprint 1

### ✅ [HIGH] H3 — Fuite Referer via Google Fonts (partiel)
**Fix partiel :** `<meta name="referrer" content="no-referrer">` + suppression Google Fonts → system-ui.
**Restant :** CSP, HSTS, X-Frame-Options, X-Content-Type-Options non implémentés.
**Fichier :** `mla-transfert-web/src/layouts/Layout.astro`, `global.css`
**Commit :** Sprint 1 + Sprint 3

### ✅ [MEDIUM] M2 — Filename multipart non sanitisé
**Fix :** `sanitize_filename()` — basename uniquement, chars alphanumériques+`./-_`, max 255 bytes.
**Fichier :** `mla-transfert-server/src/relay.rs`
**Commit :** Sprint 2

### ✅ [MEDIUM] M3 — Upload chargé entièrement en RAM
**Fix :** Streaming `.chunk()` avec vérification incrémentale `max_file_size`.
**Fichier :** `mla-transfert-server/src/relay.rs`
**Commit :** Sprint 2

### ✅ [MEDIUM] M4 — Biais de modulo dans le générateur de mots de passe
**Fix :** `randBelow(max)` avec rejection sampling — `threshold = 0x100000000 % max`, boucle jusqu'à `buf[0] >= threshold`.
**Fichier :** `mla-transfert-web/src/components/PasswordInput.tsx`
**Commit :** Sprint 3

### ✅ [MEDIUM] M5 — Erreurs WASM en clair (partiel)
**Fix partiel :** `error.rs` — tous les `From<mla::errors::*>` et `From<std::io::Error>` retournent `"Decryption failed"`.
**Restant :** Voir finding **M5b** ci-dessous — des appels directs `JsValue::from_str()` dans `password.rs` et `keys.rs` contournent `WasmMlaError`.
**Commit :** Sprint 3

### ✅ [LOW] L1 — Lien depuis `window.location.origin`
**Fix :** `import.meta.env.PUBLIC_BASE_URL ?? window.location.origin`.
**Fichier :** `mla-transfert-web/src/components/SendForm.tsx`

### ✅ [LOW] L2 — `autoComplete="current-password"`
**Fix :** `autoComplete="new-password"` dans `PasswordInput.tsx:81`.

### ✅ [LOW] L3 — Google Fonts sans SRI
**Fix :** Suppression des 3 `<link>` Google Fonts → `system-ui, -apple-system, 'Segoe UI', sans-serif`.

### ✅ [LOW] L4 — Rooms WebSocket sans limite ni TTL
**Fix :** `MAX_ROOM_PARTICIPANTS = 2`, `ROOM_TTL = 3600s`, `RoomEntry = (Sender, SystemTime)`.
**Fichier :** `mla-transfert-server/src/signaling.rs`, `state.rs`

---

## Findings ouverts

### [HIGH] H3b — Headers HTTP de sécurité manquants
- **CWE :** CWE-693
- **OWASP :** A05:2021 Security Misconfiguration
- **Location :** `astro.config.mjs`, `mla-transfert-server/src/main.rs`
- **Description :** Pas de CSP, HSTS, X-Frame-Options ni X-Content-Type-Options. Un attaquant peut clickjacker le formulaire d'envoi, injecter du script via XSS reflected, ou déclencher du MIME sniffing.
- **Attack Vector :**
  ```
  # Clickjacking — iframe-able sans X-Frame-Options
  <iframe src="https://mla-share.example.com"></iframe>

  # MIME sniffing — contenu non typé interprété comme JS
  GET /api/download/<id> → Content-Type manquant → interprétation navigateur
  ```
- **Fix :**
  ```typescript
  // astro.config.mjs — middleware Astro ou reverse proxy Caddy/Nginx
  headers: {
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'no-referrer',
  }
  // Ou via Caddy :
  // header Content-Security-Policy "default-src 'self'; ..."
  ```
- **Vérification :** `curl -I https://mla-share.example.com | grep -E "CSP|X-Frame|HSTS"`

---

### [MEDIUM] M5b — Fuites internes dans `password.rs` / `keys.rs` (JsValue directs)
- **CWE :** CWE-209
- **OWASP :** A09:2021 Security Logging and Monitoring Failures
- **Location :** `mla-wasm/src/password.rs:117,151,72` · `mla-wasm/src/keys.rs:45,122`
- **Description :** Plusieurs chemins d'erreur construisent directement un `JsValue::from_str(format!(...))` sans passer par `WasmMlaError`, contournant la généralisation des messages. Un attaquant peut distinguer "données trop courtes" de "mauvais mot de passe" de "entrée introuvable".
- **PoC :**
  ```javascript
  // Données de 4 octets (< 16 octets salt) → message "trop courtes"
  const tiny = new Uint8Array([1, 2, 3, 4]);
  decrypt_with_password(tiny, "password").catch(e => console.log(e));
  // → "Données invalides : trop courtes pour contenir un salt"  ← fuite
  ```
- **Fix :** Remplacer tous les `JsValue::from_str(&format!(...))` dans les fonctions de chiffrement/déchiffrement par le message générique :
  ```rust
  // password.rs:117 — au lieu de "Données invalides..."
  return Err(JsValue::from_str("Decryption failed"));

  // password.rs:72 et keys.rs:45 — au lieu de "Invalid entry name..."
  .map_err(|_| JsValue::from_str("Decryption failed"))?;

  // password.rs:151 et keys.rs:122 — au lieu de "Entry not found..."
  .ok_or_else(|| JsValue::from_str("Decryption failed"))?;
  ```
  Conserver les messages techniques sur les erreurs qui ne sont PAS des oracles (programming errors, serialization post-déchiffrement).
- **Vérification :** `wasm-pack test --headless --firefox -- --test oracle`

---

### [MEDIUM] N1 — Rate limit contournable via `X-Forwarded-For` spoofé
- **CWE :** CWE-348
- **OWASP :** A07:2021 Identification and Authentication Failures
- **Location :** `mla-transfert-server/src/main.rs` — `SmartIpKeyExtractor`
- **Description :** `SmartIpKeyExtractor` préfère l'en-tête `X-Forwarded-For` sur l'adresse socket. Si le serveur n'est pas derrière un proxy de confiance, n'importe quel client peut fabriquer `X-Forwarded-For: 1.2.3.4` et contourner le quota par IP.
- **Attack Vector :**
  ```bash
  for i in $(seq 1 1000); do
    curl -X POST https://mla-share.example.com/api/upload \
      -H "X-Forwarded-For: 10.0.0.$((i % 254))" \
      -F "file=@payload.bin"
  done
  ```
- **Fix Option A — Derrière un proxy de confiance :** Configurer le proxy (Caddy, Nginx) pour réécrire proprement `X-Forwarded-For` et noter l'IP réelle. Ajouter `TRUSTED_PROXY` env var et valider que l'IP source est le proxy.
- **Fix Option B — Direct internet (pas de proxy) :** Remplacer `SmartIpKeyExtractor` par `PeerIpKeyExtractor` dans `main.rs` — utilise uniquement l'adresse socket, non spoofable.
  ```rust
  // main.rs
  use tower_governor::key_extractor::PeerIpKeyExtractor;
  // Remplacer SmartIpKeyExtractor par PeerIpKeyExtractor dans GovernorConfigBuilder
  .key_extractor(PeerIpKeyExtractor)
  ```
- **Vérification :** `curl -H "X-Forwarded-For: 999.999.999.999" http://localhost:3001/api/health` → doit retourner 200 sans bypass quota.

---

### [MEDIUM] M1 — Signaling WebRTC non validé (JSON + structure SDP)
- **CWE :** CWE-20
- **OWASP :** A03:2021 Injection
- **Location :** `mla-transfert-web/src/lib/webrtc.ts:56,117`
- **Description :** `JSON.parse(event.data)` sans try/catch, puis cast direct vers `RTCSessionDescriptionInit` sans validation de structure. Un pair malveillant peut crasher le handler ou injecter un SDP malformé.
- **Attack Vector :**
  ```javascript
  // Pair malveillant envoie un message non-JSON
  ws.send("not json at all");
  // → SyntaxError non capturé → Promise rejetée silencieuse

  // Ou SDP avec type invalide
  ws.send(JSON.stringify({ type: 'offer', data: { type: 'INVALID', sdp: 'x' } }));
  ```
- **Fix :**
  ```typescript
  ws.onmessage = async (event) => {
    let msg: PeerMessage;
    try { msg = JSON.parse(event.data as string); } catch { return; }
    if (!msg?.type || !msg?.data) return;
    if (msg.type === 'answer' && typeof (msg.data as RTCSessionDescriptionInit).type === 'string') {
      await pc.setRemoteDescription(msg.data as RTCSessionDescriptionInit);
    } else if (msg.type === 'candidate') {
      await pc.addIceCandidate(new RTCIceCandidate(msg.data as RTCIceCandidateInit));
    }
  };
  ```
- **Vérification :** Envoyer `"garbage"` via WebSocket en mode développeur → aucune exception dans la console.

---

### [LOW] L5 — STUN Google leak IP réelle
- **CWE :** CWE-200
- **OWASP :** A02:2021 Cryptographic Failures (metadata)
- **Location :** `mla-transfert-web/src/lib/webrtc.ts:21,83`
- **Description :** `stun:stun.l.google.com:19302` contacte Google pour résoudre les candidats ICE, révélant l'adresse IP réelle des deux pairs.
- **Fix :** Héberger un serveur STUN/TURN auto-géré (coturn) ou référencer un serveur neutre (stun.nextcloud.com). Configurable via `PUBLIC_STUN_URL`.
  ```typescript
  const iceServers = [{ urls: import.meta.env.PUBLIC_STUN_URL ?? 'stun:stun.nextcloud.com:443' }];
  ```

---

### [LOW] CI1 — `curl | sh` pour installer wasm-pack
- **CWE :** CWE-494 (Download of Code Without Integrity Check)
- **Location :** `ci/src/mla/main.py:72-75`
- **Description :** `curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh` exécute un script distant non vérifié. Compromission du CDN = compromission de la pipeline.
- **Fix :**
  ```python
  .with_exec(["cargo", "install", "wasm-pack", "--locked", "--version", "0.13.1"])
  ```
  Fixer la version et utiliser `--locked` pour vérifier le Cargo.lock.

---

### [LOW] CI2 — Pas de `cargo deny` (licenses + supply chain)
- **Location :** `ci/src/mla/main.py`
- **Description :** Aucune vérification des licences ou des crates bannis. Un advisory non encore dans RustSec passerait en CI.
- **Fix :** Ajouter un step `cargo_deny()` dans la pipeline Dagger :
  ```python
  @function
  async def cargo_deny(self, src: dagger.Directory) -> str:
      return await (
          rust_base(src)
          .with_exec(["cargo", "install", "cargo-deny", "--locked"])
          .with_exec(["cargo", "deny", "check"])
          .stdout()
      )
  ```

---

## Points positifs — inchangés

- **Argon2id** correctement paramétré (m=64 MiB, t=3, p=4) — ANSSI/OWASP conforme
- **CSPRNG exclusif** — `crypto.getRandomValues()` avec rejection sampling depuis Sprint 3
- **Zero-knowledge by design** — mot de passe et clés ne transitent jamais côté serveur
- **Stockage par UUID** — path traversal impossible sur disque
- **Signatures MLA** activées (`with_encryption_with_signature`)
- **Streaming upload** avec vérification incrémentale depuis Sprint 2
- **Sanitisation filename** rigoureuse depuis Sprint 2
- **Room cap 2 + TTL 1h** sur le signaling WebRTC depuis Sprint 2
- **Rate limiting 20 req/s burst 40** par IP depuis Sprint 2
- **Purge auto** toutes les 60s des fichiers expirés

---

## Plan de remédiation — Sprint 4

**Priorité 1 (critique pour la prod)**
- [ ] **H3b** — Implémenter CSP + HSTS + X-Frame-Options + X-Content-Type-Options via middleware Astro ou config Caddy/Nginx
- [ ] **M5b** — Remplacer les `JsValue::from_str(format!(...))` par `"Decryption failed"` dans `password.rs:117,151,72` et `keys.rs:45,122`
- [ ] **N1** — Passer à `PeerIpKeyExtractor` si pas de proxy, ou documenter la config proxy de confiance

**Priorité 2 (robustesse)**
- [ ] **M1** — Ajouter try/catch sur `JSON.parse` et validation de structure SDP dans `webrtc.ts`
- [ ] **CI1** — Remplacer `curl|sh` wasm-pack par `cargo install wasm-pack --locked --version X.Y.Z`
- [ ] **CI2** — Ajouter step `cargo deny` dans la pipeline Dagger

**Priorité 3 (hardening)**
- [ ] **L5** — STUN configurable (`PUBLIC_STUN_URL`) + option self-hosted coturn

---

## Suivi CVE upstream

| Advisory | Crate | Statut |
|---|---|---|
| RUSTSEC-2025-0144 | `ml-dsa 0.0.4` (via `mla 2.0.0`) | Ignoré (`audit.toml`) — upstream ANSSI non patché |

Surveiller : https://github.com/ANSSI-FR/MLA/issues — notamment issue #234 (OID ML-KEM provisoire).

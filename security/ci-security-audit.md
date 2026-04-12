# Audit Sécurité CI — MLA-Share

**Date :** 2026-04-12
**Branch :** feature-ci-security
**Auditeur :** Kodetis Security Hunter + DevOps Infra Architect
**Pipeline :** `ci/src/mla/main.py` (Dagger v0.20.5, Python SDK)
**Workflow GitHub Actions :** `.github/workflows/mla-transfert.yml`

---

## Score de complétude CI sécurité : 42 / 100

| Domaine | Score | Max |
|---------|-------|-----|
| Rust/WASM — Quality gates | 18 | 25 |
| Node/Frontend — Security gates | 8 | 20 |
| Docker/Infrastructure | 5 | 20 |
| Supply chain & secrets | 3 | 20 |
| Couverture findings applicatifs | 8 | 15 |

---

## Résumé

Le pipeline CI Dagger couvre les contrôles de qualité Rust de base (fmt, clippy, test, cargo-audit) et le build de la chaîne WASM → frontend. Les vérifications de sécurité profondes sont absentes : pas de scan de secrets, pas de SAST, pas de scan d'image Docker, pas de cargo deny, pas de vérification des headers HTTP ni de tests d'intégration couvrant les findings critiques H1/H2/H3. Le workflow GitHub Actions (`.github/workflows/mla-transfert.yml`) est correctement durci (actions pinées par SHA, container pinée par digest) mais ne lance pas le pipeline Dagger — les deux pipelines coexistent sans se compléter. L'exposition des risques identifiés dans l'audit applicatif du 2026-04-12 n'est pas réduite par le CI actuel.

---

## Steps présents et opérationnels

### Pipeline Dagger (`ci/src/mla/main.py`)

| Step | Commande | Statut | Notes |
|------|----------|--------|-------|
| `rust_fmt` | `cargo fmt --all -- --check` | Opérationnel | Couvre tout le workspace |
| `rust_clippy` | `cargo clippy --workspace -D warnings` | Opérationnel | Exclut `mla-fuzz-afl` correctement |
| `rust_test` | `cargo test -p mla-wasm -p mla-transfert-server` | Opérationnel | Uniquement native target |
| `rust_audit` | `cargo audit --file audit.toml` | Opérationnel | 1 CVE ignoré documenté (RUSTSEC-2025-0144) |
| `wasm_build` | `wasm-pack build --target web --release` | Opérationnel | Image hardening absent (installe curl + pipe-to-sh) |
| `web_build` | `npm ci && npm run build` | Opérationnel | Lockfile strict |
| `npm_audit` | `npm audit --audit-level=high` | Opérationnel | High+Critical uniquement |

### Workflow GitHub Actions (`.github/workflows/mla-transfert.yml`)

| Job | Statut | Notes de sécurité |
|-----|--------|-------------------|
| `build-wasm` | Opérationnel | Container Rust pinée par digest SHA256 |
| `test-server` | Opérationnel | `RUSTFLAGS=-D warnings`, release mode |
| `lint-transfert` | Opérationnel | clippy + rustfmt |
| `build-web` | Opérationnel | `npm ci`, actions pinées SHA |
| `docker` | Opérationnel (main only) | Multi-stage, `dhi.io/rust:1-debian13-sfw-ent-dev` |

**Points positifs :**
- Toutes les actions GitHub sont pinées par SHA de commit (supply chain hardening niveau Gold)
- `permissions: {}` au niveau workflow (least privilege)
- Container Rust pinée par digest SHA256 (`rust@sha256:ecbe59a...`)
- Dockerfile multi-stage avec utilisateur non-root (uid 10001) et HEALTHCHECK
- `audit.toml` avec justification documentée pour le seul CVE ignoré

---

## Gaps identifiés

### Critique (bloque déploiement)

**CI-CRIT-1 : Scan de secrets absent**
Aucun outil (gitleaks, trufflehog, git-secrets) ne scanne le dépôt pour détecter des clés MLA, tokens, ou secrets commités. Compte tenu de la présence de fichiers `*.mlapriv` / `*.mlapub` générés lors des tests E2E (mentionnés dans `todo.md`), ce risque est concret.

**CI-CRIT-2 : Installation curl-pipe-to-sh non reproducible dans le pipeline Dagger**
`_wasm_pkg()` et le job GitHub Actions `build-wasm` installent wasm-pack via `curl ... | sh` sans vérification de checksum ni d'intégrité. Vecteur d'attaque supply chain si le CDN est compromis.

**CI-CRIT-3 : Scan d'image Docker absent**
Le job `docker` build et push l'image vers GHCR sans scan Grype + Syft. Des vulnérabilités dans `debian:trixie-slim` ou les dépendances système transitent en production sans détection.

### High (à corriger dans le sprint)

**CI-HIGH-1 : `cargo deny` absent**
`cargo audit` ne couvre pas les conflits de licences ni les crates dupliquées. `cargo deny` offre une gestion plus fine (policy `deny.toml`) et peut bloquer les advisories RUSTSEC plus tôt. Absence de vérification des checksums Cargo.lock (`cargo deny check sources`).

**CI-HIGH-2 : SAST Rust absent**
Aucune analyse statique de type semgrep (règles Rust) ou `cargo-geiger` (unsafe code audit) n'est exécutée. Le code `relay.rs` et `signaling.rs` contiennent des surfaces d'attaque non couvertes.

**CI-HIGH-3 : SAST TypeScript absent**
`eslint-plugin-security` ou semgrep (règles TypeScript) ne sont pas configurés. Le finding M4 (biais de modulo dans `PasswordInput.tsx`) et M2 (filename non sanitisé) auraient pu être détectés automatiquement.

**CI-HIGH-4 : Vérification headers HTTP absente**
Le CI ne vérifie pas que les headers de sécurité (CSP, X-Frame-Options, HSTS, Referrer-Policy) sont présents dans le build Astro final. Le finding H3 n'est pas testé.

### Medium (amélioration continue)

**CI-MED-1 : Tests d'intégration CORS absents**
Le finding H2 (`CorsLayer::permissive()`) n'est pas couvert par un test automatisé vérifiant que les origines non autorisées reçoivent une réponse CORS rejetée.

**CI-MED-2 : Test de rate limiting absent**
Le finding H1 (absence de rate limiting) n'est pas détecté en CI. Un test de smoke simple avec `k6` ou `hey` qui échoue si > N requêtes/s sont acceptées sans throttling manque.

**CI-MED-3 : SBOM non généré**
Aucun Software Bill of Materials (CycloneDX ou SPDX) n'est généré ni attaché comme artefact. Requis NIS2 pour les composants logiciels à risque élevé.

**CI-MED-4 : Pipeline Dagger et workflow GitHub Actions déconnectés**
Le CI Dagger est un outil standalone, mais le workflow GitHub Actions ne l'appelle pas. Les steps Dagger (`ci/src/mla/main.py`) doublonnent partiellement les jobs GitHub Actions sans partage de résultats ni gates partagés.

**CI-MED-5 : Hadolint absent**
Le Dockerfile n'est pas linté par `hadolint`. Des règles comme l'absence de `--no-install-recommends` (stage runtime), la version non pinée de `debian:trixie-slim` et la présence de `wget` dans l'image runtime pourraient être détectées.

**CI-MED-6 : `npm audit --audit-level=moderate` trop permissif**
Le seuil actuel `high` laisse passer des CVE modérées. Pour un projet de sécurité, le seuil devrait être `moderate` voire `low`.

### Low (nice to have)

**CI-LOW-1 : SRI sur assets externes non vérifié**
Le finding L3 (Google Fonts sans SRI) n'est pas testé. Un grep sur le build output pour `fonts.googleapis.com` sans attribut `integrity` serait suffisant.

**CI-LOW-2 : Test de régression M4 (biais modulo) absent**
Aucun test statistique automatisé ne valide l'uniformité de distribution de `generatePassword()`.

**CI-LOW-3 : Vérification `autoComplete` absente**
Un grep CI sur `autoComplete="current-password"` dans les composants React éviterait la régression du finding L2.

---

## Mapping avec findings de l'audit applicatif (todo.md)

| Finding | Couvert en CI ? | Step CI concerné | Gap |
|---------|----------------|-----------------|-----|
| H1 — No rate limiting | Non | Aucun | Ajouter test de charge smoke (k6/hey) |
| H2 — CORS permissif | Non | Aucun | Test d'intégration CORS avec `curl -H Origin:` |
| H3 — Headers HTTP manquants | Non | Aucun | Scan headers sur build Astro (vérification `astro.config.mjs`) |
| M1 — WebRTC signaling non validé | Non | Aucun | Test WebSocket injectant un payload malformé |
| M2 — Filename non sanitisé | Non | Aucun | SAST (semgrep) détecte l'absence de sanitisation |
| M3 — Upload chargé en RAM | Non | Aucun | Test de charge avec fichier > `MAX_FILE_SIZE_BYTES` |
| M4 — Biais modulo password gen | Partiellement | `rust_clippy` (ne couvre pas TS) | Test statistique sur `generatePassword()` + SAST TS |
| M5 — Erreurs WASM oracle | Non | Aucun | Test que les erreurs WASM sont opaques |
| L1 — Base URL proxy | Non | Aucun | Vérification `PUBLIC_BASE_URL` dans build |
| L2 — autoComplete | Non | Aucun | Grep CI sur le source TS |
| L3 — Google Fonts sans SRI | Non | Aucun | Grep sur build output dist/ |
| L4 — WebSocket rooms sans TTL | Non | Aucun | Test de montée en charge WebSocket |
| RUSTSEC-2025-0144 | Oui (ignoré documenté) | `rust_audit` | Surveillance upstream ANSSI — acceptable |

---

## Recommandations — Steps CI à ajouter

### 1. Scan de secrets (gitleaks) — CRITIQUE

```python
@function
async def secrets_scan(self, src: dagger.Directory) -> str:
    """Scan the repository for leaked secrets (API keys, MLA private keys, tokens)."""
    return await (
        dag.container()
        .from_("zricethezav/gitleaks:v8.24.3")
        .with_mounted_directory("/repo", src)
        .with_exec([
            "gitleaks", "detect",
            "--source", "/repo",
            "--no-git",
            "--redact",
            "--exit-code", "1",
            "--config", "/repo/.gitleaks.toml",  # si présent
        ])
        .stdout()
    )
```

Créer également `/Users/tipunch/Gitlab/Tools/MLA/.gitleaks.toml` :

```toml
title = "MLA-Share gitleaks config"

[extend]
useDefault = true

[[rules]]
id = "mla-private-key"
description = "MLA private key file"
regex = '''(?i)(mlapriv|\.mla_key|mla_secret)'''
tags = ["mla", "key", "secret"]
```

### 2. cargo deny — HIGH

```python
@function
async def rust_deny(self, src: dagger.Directory) -> str:
    """Check Rust dependencies: licenses, bans, advisories, sources integrity."""
    return await (
        rust_base(src)
        .with_exec(["cargo", "install", "cargo-deny", "--locked"])
        .with_exec(["cargo", "deny", "check"])
        .stdout()
    )
```

Créer `/Users/tipunch/Gitlab/Tools/MLA/deny.toml` :

```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"
notice = "warn"
ignore = [
    "RUSTSEC-2025-0144",  # ml-dsa timing side-channel — waiting on ANSSI upstream
]

[licenses]
unlicensed = "deny"
copyleft = "warn"
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
]

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

### 3. Scan image Docker (Grype + Syft) — CRITIQUE

```python
@function
async def docker_scan(self, src: dagger.Directory) -> str:
    """Build server Docker image, generate SBOM with Syft, scan CVEs with Grype."""
    # Build the server image
    server_image = dag.container().build(
        context=src,
        dockerfile="mla-transfert-server/Dockerfile",
    )
    # Export as OCI tar for Syft
    image_tar = server_image.as_tarball()

    # Step 1: Syft → SBOM
    sbom_file = (
        dag.container()
        .from_("anchore/syft:latest")
        .with_mounted_file("/image.tar", image_tar)
        .with_exec([
            "syft", "oci-archive:/image.tar",
            "--output", "spdx-json=/tmp/sbom.spdx.json",
            "--quiet",
        ])
        .file("/tmp/sbom.spdx.json")
    )
    # Step 2: Grype → CVE scan on SBOM (fail on High+Critical)
    return await (
        dag.container()
        .from_("anchore/grype:latest")
        .with_mounted_file("/sbom.spdx.json", sbom_file)
        .with_exec([
            "grype", "sbom:/sbom.spdx.json",
            "--fail-on", "high",
            "--output", "table",
        ])
        .stdout()
    )
```

### 4. SAST Rust — cargo-geiger (unsafe audit) — HIGH

```python
@function
async def rust_unsafe_audit(self, src: dagger.Directory) -> str:
    """Count unsafe Rust code blocks across the workspace (cargo-geiger)."""
    return await (
        rust_base(src)
        .with_exec(["apt-get", "install", "-y", "--no-install-recommends", "libssl-dev"])
        .with_exec(["cargo", "install", "cargo-geiger", "--locked"])
        .with_exec([
            "cargo", "geiger",
            "--workspace",
            "--exclude", "mla-fuzz-afl",
            "--output-format", "GitHubActions",
        ])
        .stdout()
    )
```

### 5. Vérification headers HTTP (SAST statique) — HIGH

```python
@function
async def web_security_headers_check(self, src: dagger.Directory) -> str:
    """
    Verify security headers are configured in astro.config.mjs.
    Fails if CSP, X-Frame-Options, HSTS or Referrer-Policy are missing.
    """
    script = """
set -e
CONFIG="mla-transfert-web/astro.config.mjs"

check_header() {
    local header="$1"
    if ! grep -q "$header" "$CONFIG"; then
        echo "MISSING HEADER: $header not found in $CONFIG" >&2
        exit 1
    fi
    echo "OK: $header"
}

check_header "Content-Security-Policy"
check_header "X-Frame-Options"
check_header "Referrer-Policy"
check_header "X-Content-Type-Options"

# Vérifier que CorsLayer::permissive() n'est plus utilisé
if grep -r "CorsLayer::permissive" mla-transfert-server/src/; then
    echo "SECURITY ISSUE: CorsLayer::permissive() still in use (finding H2)" >&2
    exit 1
fi
echo "CORS check: OK"
"""
    return await (
        dag.container()
        .from_("alpine:3.21")
        .with_exec(["apk", "add", "--no-cache", "bash", "grep"])
        .with_mounted_directory("/src", src)
        .with_workdir("/src")
        .with_exec(["sh", "-c", script])
        .stdout()
    )
```

### 6. Scan de secrets dans le code (gitleaks inline) — CRITIQUE

Ajouter dans le job GitHub Actions `lint-transfert` :

```yaml
      - name: Scan secrets (gitleaks)
        uses: gitleaks/gitleaks-action@44c470a69d0e567c8c76fac55dc37c6fe4e0ea5b  # v2.3.9
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_ENABLE_COMMENTS: false
```

### 7. Hadolint — Dockerfile lint — MEDIUM

```python
@function
async def dockerfile_lint(self, src: dagger.Directory) -> str:
    """Lint the server Dockerfile with hadolint."""
    return await (
        dag.container()
        .from_("hadolint/hadolint:v2.12.0-alpine")
        .with_mounted_directory("/src", src)
        .with_exec([
            "hadolint",
            "--failure-threshold", "warning",
            "--ignore", "DL3008",   # apt-get pin versions (hardened base image)
            "/src/mla-transfert-server/Dockerfile",
        ])
        .stdout()
    )
```

### 8. Wasm-pack installation reproducible — CRITIQUE

Remplacer `curl | sh` par installation via cargo dans `_wasm_pkg()` :

```python
def _wasm_pkg(self, src: dagger.Directory) -> dagger.Directory:
    """Build mla-wasm with wasm-pack (installed via cargo --locked for reproducibility)."""
    return (
        dag.container()
        .from_(WASM_IMAGE)
        .with_exec(["apt-get", "update", "-qq"])
        .with_exec([
            "apt-get", "install", "-y", "--no-install-recommends",
            "pkg-config", "libssl-dev",
        ])
        # Installation reproducible via cargo (pas de curl|sh)
        .with_exec(["cargo", "install", "wasm-pack", "--version", "0.13.1", "--locked"])
        .with_exec(["rustup", "target", "add", "wasm32-unknown-unknown"])
        .with_mounted_cache("/root/.cargo/registry", dag.cache_volume("cargo-registry"))
        .with_mounted_cache("/root/.cargo/git", dag.cache_volume("cargo-git"))
        .with_mounted_directory("/src", src)
        .with_workdir("/src/mla-wasm")
        .with_exec(["wasm-pack", "build", "--target", "web", "--release"])
        .directory("/src/mla-wasm/pkg")
    )
```

### 9. npm audit avec seuil abaissé à moderate — MEDIUM

```python
@function
async def npm_audit(self, src: dagger.Directory) -> str:
    """Scan Node dependencies — fail on moderate+ CVEs (security project standard)."""
    wasm_pkg = self._wasm_pkg(src)
    return await (
        dag.container()
        .from_(NODE_IMAGE)
        .with_mounted_cache("/root/.npm", dag.cache_volume("npm-cache"))
        .with_mounted_directory("/src", src)
        .with_mounted_directory("/src/mla-wasm/pkg", wasm_pkg)
        .with_workdir("/src/mla-transfert-web")
        .with_exec(["npm", "ci"])
        # Abaissé de high à moderate (projet de sécurité)
        .with_exec(["npm", "audit", "--audit-level=moderate"])
        .stdout()
    )
```

### 10. SBOM — CycloneDX — MEDIUM

```python
@function
async def generate_sbom(self, src: dagger.Directory) -> dagger.File:
    """Generate a CycloneDX SBOM for the Rust workspace."""
    return (
        rust_base(src)
        .with_exec(["cargo", "install", "cargo-cyclonedx", "--locked"])
        .with_exec([
            "cargo", "cyclonedx",
            "--workspace",
            "--format", "json",
            "--output-file", "/tmp/sbom.json",
        ])
        .file("/tmp/sbom.json")
    )
```

### 11. Test de régression finding L2 (autoComplete) — LOW

```python
@function
async def web_regression_checks(self, src: dagger.Directory) -> str:
    """Grep-based regression tests for known security findings."""
    script = r"""
set -e
ERRORS=0

# L2 : autoComplete="current-password" sur champ de transfert
if grep -r 'autoComplete="current-password"' /src/mla-transfert-web/src/components/; then
    echo "REGRESSION L2: autoComplete=current-password found" >&2
    ERRORS=$((ERRORS+1))
fi

# L3 : Google Fonts sans SRI dans les sources
if grep -r 'fonts.googleapis.com' /src/mla-transfert-web/src/ | grep -v 'integrity='; then
    echo "REGRESSION L3: Google Fonts without SRI" >&2
    ERRORS=$((ERRORS+1))
fi

# H2 : CORS permissif
if grep -r 'CorsLayer::permissive' /src/mla-transfert-server/src/; then
    echo "REGRESSION H2: CorsLayer::permissive() still in use" >&2
    ERRORS=$((ERRORS+1))
fi

if [ "$ERRORS" -gt 0 ]; then
    echo "--- $ERRORS regression(s) found ---" >&2
    exit 1
fi
echo "All regression checks passed."
"""
    return await (
        dag.container()
        .from_("alpine:3.21")
        .with_exec(["apk", "add", "--no-cache", "grep", "bash"])
        .with_mounted_directory("/src", src)
        .with_exec(["sh", "-c", script])
        .stdout()
    )
```

### 12. Pipeline CI complet mis à jour

Remplacer la méthode `ci()` dans `main.py` :

```python
@function
async def ci(self, src: dagger.Directory) -> str:
    """Run the full CI pipeline (security-hardened)."""
    results: list[str] = []

    steps = [
        # --- Qualité Rust ---
        ("fmt",              self.rust_fmt(src)),
        ("clippy",           self.rust_clippy(src)),
        ("test",             self.rust_test(src)),
        ("rust-audit",       self.rust_audit(src)),
        ("rust-deny",        self.rust_deny(src)),          # NEW
        ("rust-unsafe",      self.rust_unsafe_audit(src)),  # NEW
        # --- Build ---
        ("wasm-build",       self.wasm_build(src)),
        ("web-build",        self.web_build(src)),
        # --- Sécurité Node ---
        ("npm-audit",        self.npm_audit(src)),          # seuil moderate
        ("web-sec-headers",  self.web_security_headers_check(src)),  # NEW
        ("web-regressions",  self.web_regression_checks(src)),       # NEW
        # --- Supply chain & secrets ---
        ("secrets-scan",     self.secrets_scan(src)),       # NEW
        ("dockerfile-lint",  self.dockerfile_lint(src)),    # NEW
        ("docker-scan",      self.docker_scan(src)),        # NEW
    ]

    for name, coro in steps:
        try:
            out = await coro
            results.append(f"[PASS] {name}\n{out}")
        except Exception as exc:  # noqa: BLE001
            results.append(f"[FAIL] {name}\n{exc}")
            break

    return "\n\n".join(results)
```

---

## Secrets & Supply Chain

### État actuel

| Contrôle | État | Détail |
|----------|------|--------|
| Actions GitHub pinées par SHA | Conforme | Toutes les actions dans `mla-transfert.yml` |
| Container Rust pinée par digest | Conforme | `rust@sha256:ecbe59a...` |
| wasm-pack via `curl \| sh` | Non conforme | Vecteur supply chain — aucune vérification d'intégrité |
| Scan de secrets | Absent | Risque clés MLA privées commitées |
| Clés MLA de test en dépôt | Non vérifié | `todo.md` mentionne `kodetis.mlapriv` / `partenaire.mlapriv` |
| SBOM | Absent | Non généré, non attaché comme artefact |
| Checksums Cargo.lock | Partiellement | `cargo audit` vérifie les advisories mais pas l'intégrité source via `cargo deny check sources` |
| `.gitignore` pour `*.mlapriv` | À vérifier | Ajouter `*.mlapriv`, `*.mlapub`, `nxo-mlar.mla` |

### Fichier suspect détecté

Le fichier `nxo-mlar.mla` est présent en status `??` (untracked) à la racine du projet. S'il s'agit d'une archive MLA de test contenant des données sensibles, il ne doit pas être commité. Ajouter au `.gitignore` :

```
# Fichiers MLA générés / archives de test
*.mlapriv
*.mlapub
*.mla
nxo-mlar.mla
data/
```

### Recommandations supply chain prioritaires

1. **Pinner wasm-pack par version cargo** (`--version 0.13.1 --locked`) dans Dagger ET dans le workflow GitHub Actions
2. **Ajouter gitleaks** dans le pipeline Dagger ET dans le pre-commit hook local
3. **Générer un SBOM CycloneDX** et l'attacher comme artefact GitHub Actions
4. **Activer `cargo deny check sources`** pour bloquer les crates depuis des registries non officiels

---

## Plan de remédiation priorisé

**Sprint 1 (< 2h) — Quick wins sans refactoring :**
- [ ] Ajouter `*.mlapriv`, `*.mlapub`, `*.mla`, `data/` au `.gitignore`
- [ ] Remplacer `curl | sh` wasm-pack par `cargo install wasm-pack --version 0.13.1 --locked` dans `main.py` ET `mla-transfert.yml`
- [ ] Ajouter `web_regression_checks` step dans `main.py` (grep H2/L2/L3 — code fourni ci-dessus)
- [ ] Abaisser `npm audit` de `--audit-level=high` à `--audit-level=moderate`
- [ ] Créer `.gitleaks.toml` avec règle `mla-private-key`
- [ ] Ajouter `gitleaks-action` dans le job `lint-transfert` du workflow GitHub Actions

**Sprint 2 (1-2 jours) — Hardening security gates :**
- [ ] Implémenter `rust_deny()` + créer `deny.toml` (code fourni ci-dessus)
- [ ] Implémenter `secrets_scan()` dans le pipeline Dagger
- [ ] Implémenter `web_security_headers_check()` — force la correction du finding H2 (CORS) et H3 (headers)
- [ ] Implémenter `dockerfile_lint()` avec hadolint
- [ ] Implémenter `docker_scan()` avec Grype après le build Docker
- [ ] Ajouter step SBOM CycloneDX et upload comme artefact GitHub Actions

**Sprint 3 (amélioration continue) :**
- [ ] Implémenter `rust_unsafe_audit()` avec cargo-geiger
- [ ] Configurer semgrep avec règles Rust + TypeScript (`.semgrep/` à la racine)
- [ ] Ajouter test d'intégration CORS automatisé (script `curl` dans un step Dagger)
- [ ] Intégrer le pipeline Dagger dans le workflow GitHub Actions (`dagger call ci --src .`)
- [ ] Générer et publier les résultats de scan sous format SARIF dans GitHub Security tab
- [ ] Test statistique de `generatePassword()` pour valider l'absence de biais (finding M4)

---

## Annexe — Images et versions recommandées

| Outil | Image / Version recommandée | Note |
|-------|---------------------------|------|
| gitleaks | `zricethezav/gitleaks:v8.24.3` | Pinner par SHA en prod |
| Grype | `anchore/grype:latest` | |
| hadolint | `hadolint/hadolint:v2.12.0-alpine` | |
| cargo-deny | `0.16.x` via `cargo install --locked` | |
| cargo-cyclonedx | `0.5.x` via `cargo install --locked` | |
| semgrep | `semgrep/semgrep:1.90.0` | |
| wasm-pack | `0.13.1` via `cargo install --locked` | Remplace curl\|sh |

---

*Rapport généré le 2026-04-12 — Kodetis Security Hunter / DevOps Infra Architect*
*Pipeline Dagger : `ci/src/mla/main.py` — Workflow GHA : `.github/workflows/mla-transfert.yml`*

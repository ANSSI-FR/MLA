"""MLA-Share CI pipeline — security-first.

Steps:
  1. rust_fmt      — cargo fmt --check
  2. rust_clippy   — cargo clippy -D warnings
  3. rust_test     — cargo test (mla-wasm + mla-transfert-server)
  4. rust_audit    — cargo audit (CVE scan Rust deps)
  5. wasm_build    — wasm-pack build mla-wasm
  6. web_build     — npm ci + astro build (wasm pkg injected)
  7. npm_audit     — npm audit --audit-level=high

Run everything:  dagger call ci --src .
Run one step:    dagger call rust-fmt --src .
"""

import dagger
from dagger import dag, function, object_type

RUST_IMAGE = "rust:1-slim-bookworm"
WASM_IMAGE = "rust:1-slim-bookworm"
NODE_IMAGE = "node:22-slim"
# Anchore tools — Syft (SBOM) + Grype (CVE scan)
ANCHORE_IMAGE = "anchore/syft:latest"
GRYPE_IMAGE = "anchore/grype:latest"


def rust_base(src: dagger.Directory) -> dagger.Container:
    """Shared Rust container: source mounted, Cargo cache warm."""
    return (
        dag.container()
        .from_(RUST_IMAGE)
        .with_exec(["apt-get", "update", "-qq"])
        .with_exec(
            [
                "apt-get", "install", "-y", "--no-install-recommends",
                "pkg-config", "libssl-dev",
            ]
        )
        .with_mounted_cache("/root/.cargo/registry", dag.cache_volume("cargo-registry"))
        .with_mounted_cache("/root/.cargo/git", dag.cache_volume("cargo-git"))
        .with_mounted_cache("/root/target", dag.cache_volume("cargo-target"))
        .with_mounted_directory("/src", src)
        .with_workdir("/src")
        .with_env_variable("CARGO_TARGET_DIR", "/root/target")
    )


@object_type
class Mla:

    # ------------------------------------------------------------------ #
    # Internal helper — returns the built pkg/ dir (lazy, not async)      #
    # ------------------------------------------------------------------ #
    def _wasm_pkg(self, src: dagger.Directory) -> dagger.Directory:
        """Build mla-wasm with wasm-pack and return the pkg/ output directory.

        This is a lazy Dagger pipeline — no build happens until the Directory
        is actually consumed (e.g. mounted into a Node container for npm ci).
        """
        return (
            dag.container()
            .from_(WASM_IMAGE)
            .with_exec(["apt-get", "update", "-qq"])
            .with_exec(
                [
                    "apt-get", "install", "-y", "--no-install-recommends",
                    "curl", "pkg-config", "libssl-dev",
                ]
            )
            .with_exec(
                [
                    "sh", "-c",
                    "curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh",
                ]
            )
            .with_exec(["rustup", "target", "add", "wasm32-unknown-unknown"])
            .with_mounted_cache("/root/.cargo/registry", dag.cache_volume("cargo-registry"))
            .with_mounted_cache("/root/.cargo/git", dag.cache_volume("cargo-git"))
            .with_mounted_directory("/src", src)
            .with_workdir("/src/mla-wasm")
            .with_exec(["wasm-pack", "build", "--target", "web", "--release"])
            .directory("/src/mla-wasm/pkg")
        )

    # ------------------------------------------------------------------ #
    # Step 1 — cargo fmt                                                   #
    # ------------------------------------------------------------------ #
    @function
    async def rust_fmt(self, src: dagger.Directory) -> str:
        """Check Rust formatting with cargo fmt --check."""
        return await (
            rust_base(src)
            .with_exec(["rustup", "component", "add", "rustfmt"])
            .with_exec(["cargo", "fmt", "--all", "--", "--check"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 2 — cargo clippy                                                #
    # ------------------------------------------------------------------ #
    @function
    async def rust_clippy(self, src: dagger.Directory) -> str:
        """Run cargo clippy — deny warnings."""
        return await (
            rust_base(src)
            .with_exec(["rustup", "component", "add", "clippy"])
            .with_exec(
                [
                    "cargo", "clippy",
                    "--workspace",
                    "--exclude", "mla-fuzz-afl",
                    "--",
                    "-D", "warnings",
                ]
            )
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 3 — cargo test                                                  #
    # ------------------------------------------------------------------ #
    @function
    async def rust_test(self, src: dagger.Directory) -> str:
        """Run cargo test on mla-wasm (native) and mla-transfert-server."""
        return await (
            rust_base(src)
            .with_exec(
                [
                    "cargo", "test",
                    "-p", "mla-wasm",
                    "-p", "mla-transfert-server",
                ]
            )
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 4 — cargo audit                                                 #
    # ------------------------------------------------------------------ #
    @function
    async def rust_audit(self, src: dagger.Directory) -> str:
        """Scan Rust dependencies for known CVEs with cargo-audit."""
        return await (
            rust_base(src)
            .with_exec(["cargo", "install", "cargo-audit"])
            .with_exec(["cargo", "audit", "--file", "audit.toml"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 5 — wasm-pack build (public step, returns log output)          #
    # ------------------------------------------------------------------ #
    @function
    async def wasm_build(self, src: dagger.Directory) -> str:
        """Compile mla-wasm to WebAssembly with wasm-pack."""
        entries = await self._wasm_pkg(src).entries()
        return "pkg/ built successfully: " + ", ".join(entries)

    # ------------------------------------------------------------------ #
    # Step 6 — npm ci + astro build                                        #
    # ------------------------------------------------------------------ #
    @function
    async def web_build(self, src: dagger.Directory) -> str:
        """Build the Astro frontend (wasm compiled first, then npm ci + astro build)."""
        wasm_pkg = self._wasm_pkg(src)
        return await (
            dag.container()
            .from_(NODE_IMAGE)
            .with_mounted_cache("/root/.npm", dag.cache_volume("npm-cache"))
            .with_mounted_directory("/src", src)
            .with_mounted_directory("/src/mla-wasm/pkg", wasm_pkg)
            .with_workdir("/src/mla-transfert-web")
            .with_exec(["npm", "ci"])
            .with_exec(["npm", "run", "build"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 7 — npm audit                                                   #
    # ------------------------------------------------------------------ #
    @function
    async def npm_audit(self, src: dagger.Directory) -> str:
        """Scan Node dependencies for known CVEs (high+critical only)."""
        wasm_pkg = self._wasm_pkg(src)
        return await (
            dag.container()
            .from_(NODE_IMAGE)
            .with_mounted_cache("/root/.npm", dag.cache_volume("npm-cache"))
            .with_mounted_directory("/src", src)
            .with_mounted_directory("/src/mla-wasm/pkg", wasm_pkg)
            .with_workdir("/src/mla-transfert-web")
            .with_exec(["npm", "ci"])
            .with_exec(["npm", "audit", "--audit-level=high"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 8 — Syft SBOM generation                                        #
    # ------------------------------------------------------------------ #
    @function
    async def sbom(self, src: dagger.Directory) -> str:
        """Generate a Software Bill of Materials (SBOM) with Syft in SPDX JSON format."""
        return await (
            dag.container()
            .from_(ANCHORE_IMAGE)
            .with_mounted_directory("/src", src)
            .with_workdir("/src")
            .with_exec(
                [
                    "syft", "dir:/src",
                    "--output", "spdx-json=/tmp/sbom.spdx.json",
                    "--output", "table",
                    "--exclude", "**/target/**",
                    "--exclude", "**/node_modules/**",
                    "--exclude", "**/.git/**",
                ]
            )
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 9 — Grype CVE scan on SBOM                                      #
    # ------------------------------------------------------------------ #
    @function
    async def grype_scan(self, src: dagger.Directory) -> str:
        """Scan the project with Grype for known CVEs (fail on High+Critical)."""
        # Generate SBOM first, then feed to Grype — avoids re-scanning filesystem
        sbom_file = (
            dag.container()
            .from_(ANCHORE_IMAGE)
            .with_mounted_directory("/src", src)
            .with_workdir("/src")
            .with_exec(
                [
                    "syft", "dir:/src",
                    "--output", "spdx-json=/tmp/sbom.spdx.json",
                    "--exclude", "**/target/**",
                    "--exclude", "**/node_modules/**",
                    "--exclude", "**/.git/**",
                    "--quiet",
                ]
            )
            .file("/tmp/sbom.spdx.json")
        )
        return await (
            dag.container()
            .from_(GRYPE_IMAGE)
            .with_mounted_file("/sbom.spdx.json", sbom_file)
            .with_exec(
                [
                    "grype", "sbom:/sbom.spdx.json",
                    "--fail-on", "high",
                    "--output", "table",
                ]
            )
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Full pipeline                                                         #
    # ------------------------------------------------------------------ #
    @function
    async def ci(self, src: dagger.Directory) -> str:
        """Run the full CI pipeline: fmt → clippy → test → audit → wasm → web → npm audit → sbom → grype."""
        results: list[str] = []

        steps = [
            ("fmt",        self.rust_fmt(src)),
            ("clippy",     self.rust_clippy(src)),
            ("test",       self.rust_test(src)),
            ("rust-audit", self.rust_audit(src)),
            ("wasm-build", self.wasm_build(src)),
            ("web-build",  self.web_build(src)),
            ("npm-audit",  self.npm_audit(src)),
            ("sbom",       self.sbom(src)),
            ("grype",      self.grype_scan(src)),
        ]

        for name, coro in steps:
            try:
                out = await coro
                results.append(f"[PASS] {name}\n{out}")
            except Exception as exc:  # noqa: BLE001
                results.append(f"[FAIL] {name}\n{exc}")
                break

        return "\n\n".join(results)

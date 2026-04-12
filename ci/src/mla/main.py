"""MLA-Share CI pipeline — security-first.

Steps:
  1. rust_fmt      — cargo fmt --check
  2. rust_clippy   — cargo clippy -D warnings
  3. rust_test     — cargo test (mla-wasm + mla-transfert-server)
  4. rust_audit    — cargo audit (CVE scan Rust deps)
  5. wasm_build    — wasm-pack build mla-wasm
  6. web_install   — npm ci (mla-transfert-web)
  7. web_build     — astro build
  8. npm_audit     — npm audit (CVE scan Node deps)

Run everything:  dagger call ci --src .
Run one step:    dagger call rust-fmt --src .
"""

import dagger
from dagger import dag, function, object_type

# Rust toolchain image — matches hardened Kodetis CI image convention
RUST_IMAGE = "rust:1-slim-bookworm"
# wasm-pack needs a slightly fuller environment
WASM_IMAGE = "rust:1-slim-bookworm"
# Node for the Astro frontend
NODE_IMAGE = "node:22-slim"


def rust_base(src: dagger.Directory) -> dagger.Container:
    """Shared Rust container: source mounted, cargo cache warm."""
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
    # Step 5 — wasm-pack build                                             #
    # ------------------------------------------------------------------ #
    @function
    async def wasm_build(self, src: dagger.Directory) -> str:
        """Compile mla-wasm to WebAssembly with wasm-pack."""
        return await (
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
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 6 — npm ci                                                      #
    # ------------------------------------------------------------------ #
    @function
    async def web_install(self, src: dagger.Directory) -> str:
        """Install frontend dependencies with npm ci."""
        return await (
            dag.container()
            .from_(NODE_IMAGE)
            .with_mounted_cache("/root/.npm", dag.cache_volume("npm-cache"))
            .with_mounted_directory("/src", src)
            .with_workdir("/src/mla-transfert-web")
            .with_exec(["npm", "ci"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 7 — astro build                                                 #
    # ------------------------------------------------------------------ #
    @function
    async def web_build(self, src: dagger.Directory) -> str:
        """Build the Astro frontend."""
        return await (
            dag.container()
            .from_(NODE_IMAGE)
            .with_mounted_cache("/root/.npm", dag.cache_volume("npm-cache"))
            .with_mounted_directory("/src", src)
            .with_workdir("/src/mla-transfert-web")
            .with_exec(["npm", "ci"])
            .with_exec(["npm", "run", "build"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 8 — npm audit                                                   #
    # ------------------------------------------------------------------ #
    @function
    async def npm_audit(self, src: dagger.Directory) -> str:
        """Scan Node dependencies for known CVEs with npm audit."""
        return await (
            dag.container()
            .from_(NODE_IMAGE)
            .with_mounted_cache("/root/.npm", dag.cache_volume("npm-cache"))
            .with_mounted_directory("/src", src)
            .with_workdir("/src/mla-transfert-web")
            .with_exec(["npm", "ci"])
            .with_exec(["npm", "audit", "--audit-level=high"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Full pipeline                                                         #
    # ------------------------------------------------------------------ #
    @function
    async def ci(self, src: dagger.Directory) -> str:
        """Run the full CI pipeline: fmt → clippy → test → audit → wasm → web → npm audit."""
        results: list[str] = []

        steps = [
            ("fmt",        self.rust_fmt(src)),
            ("clippy",     self.rust_clippy(src)),
            ("test",       self.rust_test(src)),
            ("rust-audit", self.rust_audit(src)),
            ("wasm-build", self.wasm_build(src)),
            ("web-build",  self.web_build(src)),
            ("npm-audit",  self.npm_audit(src)),
        ]

        for name, coro in steps:
            try:
                out = await coro
                results.append(f"[PASS] {name}\n{out}")
            except Exception as exc:  # noqa: BLE001
                results.append(f"[FAIL] {name}\n{exc}")
                # Stop on first failure for fast feedback
                break

        return "\n\n".join(results)

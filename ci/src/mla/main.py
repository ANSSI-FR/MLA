"""Dagger pipeline for MLA.

Provides a reproducible entry point for running the project's
security and quality checks locally or in CI. Complementary to the
existing GitHub Actions workflows.

Steps:
    1. rust_fmt     - cargo fmt --check
    2. rust_clippy  - cargo clippy -D warnings
    3. rust_test    - cargo test --workspace
    4. rust_audit   - cargo audit (CVE scan on Rust dependencies)
    5. cargo_deny   - cargo deny check (licenses + supply chain)
    6. sbom         - Syft SBOM in SPDX JSON
    7. grype_scan   - Grype CVE scan on SBOM

Usage:
    dagger call ci --src .                 # run the full pipeline
    dagger call rust-fmt --src .           # run a single step
"""

import dagger
from dagger import dag, function, object_type

RUST_IMAGE = "rust:1.94.1-slim-bookworm"
ANCHORE_IMAGE = "anchore/syft:v1.42.4"
GRYPE_IMAGE = "anchore/grype:v0.111.0"


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
    # Step 1 - cargo fmt                                                  #
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
    # Step 2 - cargo clippy                                               #
    # ------------------------------------------------------------------ #
    @function
    async def rust_clippy(self, src: dagger.Directory) -> str:
        """Run cargo clippy - deny warnings."""
        return await (
            rust_base(src)
            .with_exec(["rustup", "component", "add", "clippy"])
            .with_exec(
                [
                    "cargo", "clippy",
                    "--workspace",
                    "--all-targets",
                    "--",
                    "-D", "warnings",
                ]
            )
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 3 - cargo test                                                 #
    # ------------------------------------------------------------------ #
    @function
    async def rust_test(self, src: dagger.Directory) -> str:
        """Run cargo test on the full workspace."""
        return await (
            rust_base(src)
            .with_exec(["cargo", "test", "--workspace"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 4 - cargo audit                                                #
    # ------------------------------------------------------------------ #
    @function
    async def rust_audit(self, src: dagger.Directory) -> str:
        """Scan Rust dependencies for known CVEs with cargo-audit."""
        return await (
            rust_base(src)
            .with_exec(["cargo", "install", "cargo-audit", "--locked"])
            .with_exec(["cargo", "audit"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 5 - cargo deny (licenses + supply chain)                       #
    # ------------------------------------------------------------------ #
    @function
    async def cargo_deny(self, src: dagger.Directory) -> str:
        """Check Rust dependencies for banned licenses and supply-chain advisories."""
        return await (
            rust_base(src)
            .with_exec(["cargo", "install", "cargo-deny", "--locked"])
            .with_exec(["cargo", "deny", "check"])
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 6 - Syft SBOM generation                                       #
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
                    "/syft", "dir:/src",
                    "--output", "spdx-json=/tmp/sbom.spdx.json",
                    "--output", "table",
                    "--exclude", "**/target/**",
                    "--exclude", "**/.git/**",
                ]
            )
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Step 7 - Grype CVE scan on SBOM                                     #
    # ------------------------------------------------------------------ #
    @function
    async def grype_scan(self, src: dagger.Directory) -> str:
        """Scan the project with Grype for known CVEs (fail on High+Critical)."""
        # Generate SBOM first, then feed to Grype - avoids re-scanning filesystem
        sbom_file = (
            dag.container()
            .from_(ANCHORE_IMAGE)
            .with_mounted_directory("/src", src)
            .with_workdir("/src")
            .with_exec(
                [
                    "/syft", "dir:/src",
                    "--output", "spdx-json=/tmp/sbom.spdx.json",
                    "--exclude", "**/target/**",
                    "--exclude", "**/.git/**",
                    "--quiet",
                ]
            )
            .file("/tmp/sbom.spdx.json")
        )

        # Cache the Grype vulnerability DB between runs to avoid re-downloading.
        grype_db_cache = dag.cache_volume("grype-db")

        return await (
            dag.container()
            .from_(GRYPE_IMAGE)
            .with_mounted_cache("/grype-db", grype_db_cache)
            .with_env_variable("GRYPE_DB_CACHE_DIR", "/grype-db")
            # Force IPv4 - some container runtimes lack IPv6 routing
            .with_env_variable("GODEBUG", "netdns=go")
            .with_mounted_file("/sbom.spdx.json", sbom_file)
            .with_exec(
                [
                    "/grype", "sbom:/sbom.spdx.json",
                    "--fail-on", "high",
                    "--output", "table",
                ]
            )
            .stdout()
        )

    # ------------------------------------------------------------------ #
    # Full pipeline                                                       #
    # ------------------------------------------------------------------ #
    @function
    async def ci(self, src: dagger.Directory) -> str:
        """Run the full CI pipeline: fmt, clippy, test, audit, deny, sbom, grype."""
        results: list[str] = []

        steps = [
            ("fmt",         self.rust_fmt(src)),
            ("clippy",      self.rust_clippy(src)),
            ("test",        self.rust_test(src)),
            ("rust-audit",  self.rust_audit(src)),
            ("cargo-deny",  self.cargo_deny(src)),
            ("sbom",        self.sbom(src)),
            ("grype",       self.grype_scan(src)),
        ]

        for name, coro in steps:
            try:
                out = await coro
                results.append(f"[PASS] {name}\n{out}")
            except Exception as exc:  # noqa: BLE001
                results.append(f"[FAIL] {name}\n{exc}")
                break

        return "\n\n".join(results)

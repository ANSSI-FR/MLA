# Dagger Pipeline

A [Dagger](https://dagger.io) Python module providing a unified entry point
for MLA's quality and security checks. The pipeline runs identically on a
developer machine and in CI, with no dependency on the GitHub Actions
runtime.

It is complementary to the existing GitHub Actions workflows; nothing
existing is removed or modified.

## Steps

| # | Step        | Image                 | Command                                                | Purpose                    |
|---|-------------|-----------------------|--------------------------------------------------------|----------------------------|
| 1 | rust_fmt    | rust:1-slim-bookworm  | `cargo fmt --check --all`                              | Formatting                 |
| 2 | rust_clippy | rust:1-slim-bookworm  | `cargo clippy --workspace --all-targets -- -D warnings`| Lints                      |
| 3 | rust_test   | rust:1-slim-bookworm  | `cargo test --workspace`                               | Tests                      |
| 4 | rust_audit  | rust:1-slim-bookworm  | `cargo audit`                                          | CVE scan on Rust deps      |
| 5 | cargo_deny  | rust:1-slim-bookworm  | `cargo deny check`                                     | Licenses + supply chain    |
| 6 | sbom        | anchore/syft          | `syft dir:/src -o spdx-json`                           | SBOM generation            |
| 7 | grype_scan  | anchore/grype         | `grype sbom:... --fail-on High`                        | CVE scan on the SBOM       |

## Usage

Run the full pipeline:

```bash
dagger call ci --src .
```

Run a single step:

```bash
dagger call rust-fmt --src .
dagger call grype-scan --src .
```

## Requirements

- Dagger engine v0.20+ (installed automatically via the `dagger` CLI)
- Python 3.13+ (managed via `uv` inside the Dagger runtime)

## Local setup

```bash
curl -L https://dl.dagger.io/dagger/install.sh | sh
dagger call ci --src .
```

The first run downloads the container images and the Grype vulnerability
database; subsequent runs reuse Dagger cache volumes for Cargo registries,
build targets, and the Grype DB.

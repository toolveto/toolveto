# Security Policy

## Supported Versions

ToolVeto actively supports security fixes for the latest published minor release of:
- `@toolveto/core`
- `@toolveto/shield`
- `toolveto-gateway`
- `toolveto` (CLI)

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report vulnerabilities privately through one of these channels:
1. **GitHub Private Vulnerability Reporting:** Use the **Report a vulnerability** button under the repository's **Security** tab.
2. **Email:** Send details (reproduction steps, affected package/version, and impact) to **`security@toolveto.ai`**.

## Response & Remediation SLAs

| Severity (CVSS) | Initial Acknowledgment | Target Remediation |
|---|---|---|
| **Critical (9.0–10.0)** | <= 24 hours | <= 72 hours |
| **High (7.0–8.9)** | <= 2 business days | <= 7 calendar days |
| **Medium (4.0–6.9)** | <= 5 business days | <= 30 calendar days |
| **Low (0.1–3.9)** | <= 10 business days | <= 90 calendar days |

## Supply-Chain Verification

Every official release published via `.github/workflows/release.yml` includes:
- **npm Provenance** (`pnpm publish --provenance`)
- **CycloneDX SBOM** (`toolveto-sbom.cdx.json`) attached to the GitHub Release
- **SLSA Build Provenance Attestations** (`actions/attest-build-provenance`) for release tarballs, SBOM, and `ghcr.io/toolveto/gateway` container images
- **SHA-256 Checksums** (`SHA256SUMS.txt`)

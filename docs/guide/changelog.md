# Changelog

This page provides a summary of all Phoenix versions and the changes in each release.

---

## v1.0.1 — Shadowsocks AEAD & TLS Fingerprint Spoofing 🚀

In this version, numerous security improvements have been introduced to fight against Deep Packet Inspection (DPI) and fully support third-party local proxying.

- **[New]** Added **Browser Fingerprint Spoofing** (`fingerprint`) (Chrome, Firefox, Safari, Random) using `utls` to deceive DPI systems.
- **[New]** Introduced a standalone **Insecure TLS** mode (`tls_mode = "insecure"`) designed for direct connections to servers using Self-signed certs without needing a CDN.
- **[New]** Flawless native Shadowsocks implementation. Phoenix can now act as a local Shadowsocks proxy on your client using secure AEAD ciphers (`aes-256-gcm`, `aes-128-gcm`, `chacha20-ietf-poly1305`).
- **[New]** Added the `-get-ss` utility flag to instantly grab a complete `ss://` connection link directly from the client.
- **[Improvement]** Added ECDSA P256 key support on the server to mitigate Chrome's lack of support for Ed25519 in TLS certificates.
- **[Improvement]** Complete revamp of startup security logs for clarity regarding token status, core protocol, and Fingerprint modes.
- **[Docs]** Website landing page modernized using Glassmorphism design alongside massive updates to troubleshooting scenarios and logs explanation.

---

## v1.0.1dev2 — TLS Fingerprint Spoofing & Insecure TLS

- **[New]** Added **Browser Fingerprint Spoofing** (`fingerprint`) using the `utls` library — to bypass DPI systems blocking non-browser traffic
- **[New]** **Insecure TLS** mode (`tls_mode = "insecure"`) — for direct connections to a server using a self-signed certificate without needing a CDN
- **[Improvement]** Security logs at startup now display TLS, token, and fingerprint status completely
- **[Improvement]** Support for ECDSA P256 key on the server for compatibility with Chrome fingerprint

## v1.0.1dev1 — True Shadowsocks Support

- **[New]** Complete implementation of Shadowsocks with AEAD (Authenticated Encryption with Associated Data)
- **[Improvement]** Supported ciphers: `aes-256-gcm`, `aes-128-gcm`, `chacha20-ietf-poly1305`
- **[New]** Added `-get-ss` flag to generate the `ss://` connection link for mobile clients

---

## v1.0.0 — First Stable Release 🎉

- **[New]** Support for deeper architectures: `armv7`, `arm32`, `mips`, `mipsle`, `mips64`, `mips64le`, `riscv64`
- Builds are now available for **12 different platforms**:
  - Linux: amd64, arm64, armv7, arm32, mips, mipsle, mips64, mips64le, riscv64
  - macOS: amd64, arm64
  - Windows: amd64

---

## v1.0.0dev21

- Added CI builds for ARM and MIPS architectures (v1.0.0 preview)

## v1.0.0dev20

- **[Bug Fix]** Removed overly strict `PingTimeout` and implemented intelligent `background flusher`
- Performance improvement: Fixed buffer bloat and packet amplification issues

## v1.0.0dev17

- **[Docs]** Complete rewrite of documentation containing details on mTLS, One-Way TLS, and Circuit Breaker

## v1.0.0dev16

- **[Bug Fix]** Fixed race condition in release by separating build and release jobs

## v1.0.0dev15

- **[New]** Setup multi-platform build workflow (Linux/macOS/Windows)

## v1.0.0dev14

- **[Improvement]** Implemented Debounce for Hard Reset to prevent Reset Storms

## v1.0.0dev13

- **[Improvement]** Re-designed Client Transport to support Hard Reset upon error

## v1.0.0dev12

- **[New]** Implemented **Circuit Breaker** to recover Zombie connections

## v1.0.0dev11

- **[New]** Added `-gen-keys` flag for the client

## v1.0.0dev10

- **[New]** Implemented **One-Way TLS** (Server-Side Encryption)

## v1.0.0dev9

- **[Docs]** Updated example configuration files with mTLS keys instructions

## v1.0.0dev8

- **[Improvement]** Updated Integration Tests for the new security architecture and speed tests

## v1.0.0dev7

- **[New]** Added `-get-ss` flag and set default Shadowsocks cipher to `chacha20-ietf-poly1305`

## v1.0.0dev6

- **[Improvement]** UDP performance optimization: buffer increase, H2 transport adjustment, timeout disabled

## v1.0.0dev5

- **[Bug Fix]** Fixed UDP connection drop issue while sending keep-alive data

## v1.0.0dev4

- **[Bug Fix]** Fixed routing and flushing issue in UDP Associate, added integration test

## v1.0.0dev3

- **[New]** Full support for **SOCKS5 UDP Associate** (Command 0x03)

## v1.0.0dev2

- **[Bug Fix]** Fixed nil pointer dereference in client Dial management

## v1.0.0dev1

- **[New]** Complete initial implementation of the Phoenix System (Server/Client/Transport/Adapters)

---

::: tip Contributing to the Project
To see all changes with deep technical details, visit the [Releases page on GitHub](https://github.com/Fox-Fig/phoenix/releases).
:::

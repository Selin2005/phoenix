# Complete Configuration Reference

This guide provides a detailed reference for configuring Phoenix Client and Server, including TOML configuration files and Command Line Interface (CLI) flags.

## Command Line Flags (CLI)

Both the client and server binaries support specific command-line arguments.

### Server Flags
Usage: `./phoenix-server [flags]`

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-config <path>` | Path to the server configuration file. | `server.toml` |
| `-gen-keys` | Generate a new Ed25519 keypair (Public/Private) for mTLS. Prints the Public Key and saves the Private Key to `private.key`. | `false` |

### Client Flags
Usage: `./phoenix-client [flags]`

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-config <path>` | Path to the client configuration file. | `client.toml` |
| `-gen-keys` | Generate a new Ed25519 keypair. Prints the Public Key (to give to the server admin) and saves the Private Key. | `false` |
| `-get-ss` | specific flag to generate and print a compliant Shadowsocks URI (`ss://...`) based on your configuration. | `false` |

---

## Server Configuration (`server.toml`)

The server configuration file controls network binding, allowed protocols, and cryptographic identity.

### Global Settings

| Key | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `listen_addr` | string | The TCP address and port the server will bind to. Examples: `:8080` (h2c), `:8443` (mTLS). | `:8080` |

### Security & Protocols `[security]`
This block controls which tunneling protocols are permitted and handles authentication keys.

| Key | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `enable_socks5` | bool | Allow clients to tunnel SOCKS5 traffic. | `true` |
| `enable_udp` | bool | Allow SOCKS5 UDP Associate (required for voice/video calls). | `true` |
| `enable_shadowsocks` | bool | Allow clients to tunnel Shadowsocks traffic. | `false` |
| `enable_ssh` | bool | Allow clients to tunnel SSH traffic. | `false` |
| `private_key` | string | **Path** to the server's private key file (e.g., `server.private.key`). Generated via `-gen-keys`. Required for secure modes. | `""` |
| `authorized_clients`| array | A list of **Client Public Keys** (Base64 strings) authorized to connect. If empty/commented, the server runs in **One-Way TLS** mode (anyone with the server's public key can connect). If populated, it enforces **mTLS** (Mutual TLS). | `[]` |

---

## Client Configuration (`client.toml`)

The client configuration defines the connection to the server and local entry points.

### Global Settings

| Key | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `remote_addr` | string | The address of the Phoenix server (IP:Port). | `"127.0.0.1:8080"` |
| `server_public_key`| string | The **Server's Public Key** (Base64). **REQUIRED** for any secure connection (One-Way TLS or mTLS) to prevent MITM attacks. | `"SERVER_PUB_KEY..."` |
| `private_key` | string | **Path** to the client's private key file. Required ONLY if you want to use **mTLS** (Client Authentication). | `"client.private.key"` |

### Inbounds `[[inbounds]]`
Defines local listeners. You can define multiple inbounds by repeating the `[[inbounds]]` block.

| Key | Type | Description |
| :--- | :--- | :--- |
| `protocol` | string | The protocol to listen for. Options: `"socks5"`, `"shadowsocks"`, `"ssh"`. |
| `local_addr` | string | The local IP and Port to bind (e.g., `"127.0.0.1:1080"`). |
| `enable_udp` | bool | Enable UDP support (Only for `socks5`). |
| `auth` | string | Authentication details. <br>• For `shadowsocks`: `"method:password"` (e.g., `chacha20-ietf-poly1305:my-pass`).<br>• For `ssh`: Path to private key (e.g., `/home/user/.ssh/id_rsa`). |

#### Example: Mixed Inbounds
```toml
remote_addr = "example.com:8080"
server_public_key = "..."

# Standard SOCKS5 Proxy
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1080"
enable_udp = true

# Shadowsocks Listener (for legacy apps)
[[inbounds]]
protocol = "shadowsocks"
local_addr = "127.0.0.1:8388"
auth = "chacha20-ietf-poly1305:secure-password"
```

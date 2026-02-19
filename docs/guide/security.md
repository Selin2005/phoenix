# Security & Encryption Modes

Phoenix distinguishes itself by offering a spectrum of security modes, from raw performance to military-grade mutual authentication, all running over HTTP/2 Cleartext (h2c) to withstand DPI.

## 1. Cleartext h2c (No Encryption)
**Best for:** Setup behind a Trusted CDN (Cloudflare/Gcore) that handles TLS.

In this mode, traffic is encapsulated in HTTP/2 frames but sent over plain TCP. The "Security" comes from the fact that it looks like standard HTTP/2 traffic to a web server.

### Configuration
*   **Server:** Do NOT set `private_key`.
*   **Client:** Do NOT set `server_public_key` or `private_key`.

---

## 2. One-Way TLS (Anonymous Client)
**Best for:** Standard private proxy usage. Prevents MITM (Man-in-the-Middle) attacks.

Similar to standard HTTPS. The Client encrypts traffic using the Server's Public Key. The Server is authenticated, but the Client is anonymous.

### Setup
1.  **Server:** Generate keys: `./phoenix-server -gen-keys`. Save the private key (e.g., `server.key`).
2.  **Server Config:** point `private_key` to the generated file.
3.  **Client Config:** Copy the printed **Public Key** from the server generation step and paste it into `server_public_key`.

**(No Client Private Key is required in this mode.)**

### Config Snippets

**Server (`server.toml`):**
```toml
[security]
private_key = "server.key"
# authorized_clients is empty/commented
```

**Client (`client.toml`):**
```toml
remote_addr = "x.x.x.x:8080"
server_public_key = "INSERT_SERVER_PUBLIC_KEY_HERE"
# private_key is commented out
```

---

## 3. Mutual TLS (mTLS - High Security)
**Best for:** High-censorship environments. Prevents active probing.

In mTLS, **both** the client and server must prove their identity. If a censor tries to connect to your server (Active Probing) without a valid Client Key, the connection is instantly rejected.

### Setup
1.  **Server:** Generate keys (`./phoenix-server -gen-keys`) -> Get `Server PubKey`.
2.  **Client:** Generate keys (`./phoenix-client -gen-keys`) -> Get `Client PubKey`.
3.  **Exchange:**
    *   Put `Server PubKey` into **Client's** `server_public_key`.
    *   Put `Client PubKey` into **Server's** `authorized_clients` list.

### Config Snippets

**Server (`server.toml`):**
```toml
[security]
private_key = "server.key"
authorized_clients = [
    "CLIENT_PUBLIC_KEY_BASE64_HERE"
]
```

**Client (`client.toml`):**
```toml
remote_addr = "x.x.x.x:8080"
private_key = "client.key"
server_public_key = "SERVER_PUBLIC_KEY_BASE64_HERE"
```

> **Note:** Keys are Ed25519, providing high security with small key sizes and fast performance.

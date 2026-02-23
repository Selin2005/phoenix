# Advanced Configuration

Welcome to the advanced configuration section!
Given the extensive features of Phoenix, this page is long and contains multiple sections. **But don't worry!** You do not need to read this entire page. Based on your needs, just select one or two sections and configure them.

::: info Quick Study Guide for this Page

- **If you want maximum security (Recommended):** Only read sections **1** and **2** (related to mTLS).
- **If your server is not behind a CDN:** Read section **3** (Insecure TLS mode).
- **If your ISP is sensitive to unusual protocols:** In addition to the above steps, read section **4** (Fingerprint spoofing).
  :::

---

## 1. One-Way TLS Configuration (Like HTTPS)

In this mode, the server holds the private key, and the client uses the server's public key to ensure secure connectivity.

### Step 1: Generate Server Keys

On the server (VPS), run the following command:

```bash
./phoenix-server -gen-keys
```

The output of this command will include two items:

1. A file named `private.key` will be created in the current directory.
2. A **Public Key** will be printed to the terminal. **Copy and save it.**

Then, rename the private key to match the default configuration file:

```bash
mv private.key server.private.key
```

### Step 2: Server Configuration (`server.toml`)

Open `server.toml` and uncomment the line relating to `private_key` (remove the `#`):

```toml
[security]
# ...
private_key = "server.private.key"
```

### Step 3: Client Configuration (`client.toml`)

On your computer, open `client.toml`. Find the `server_public_key` variable, uncomment it, and set its value to the **server's public key** (the one you saved in step 1):

```toml
server_public_key = "YOUR_SERVER_PUBLIC_KEY..."
```

**Congratulations!** One-Way TLS is now activated and you can start using the application.

---

## 2. mTLS Configuration (Mutual Authentication - Recommended)

For maximum security (Anti-Probing), after completing the above steps (One-Way TLS), perform the following steps as well.

### Step 4: Generate Client Keys

On your computer (Client side), run the following command:

```bash
./phoenix-client -gen-keys
# Or on Windows:
# .\phoenix-client.exe -gen-keys
```

The output is similar to before:

1. A `private.key` file is created.
2. A **Public Key** is displayed. **Copy and save it.**

Rename the private key file:

```bash
mv private.key client.private.key
# Or on Windows (PowerShell):
# Rename-Item private.key client.private.key
```

_(Note: The command output usually names it `private.key`, or you can just rename whatever the generated file is.)_

### Step 5: Client Configuration (`client.toml`)

Open `client.toml` and uncomment the `private_key` line:

```toml
# The path to the client private key you just created
private_key = "client.private.key"
```

### Step 6: Server Configuration (`server.toml`)

Go back to the server and open `server.toml`.
Uncomment the `authorized_clients` variable (the list of allowed clients) and insert the client's public key (from Step 4) into it:

```toml
[security]
# ...
authorized_clients = [
  "CLIENT_PUBLIC_KEY..."
]
```

**Done!** Now just run the server and client. In this mode, only your specific client is allowed to connect to the server.

::: tip Important Note Regarding File Names
In all the steps above, we used the `mv` command to rename the generated `private.key` files to `server.private.key` and `client.private.key` to match the default config files (`server.toml` and `client.toml`).
If you do not wish to rename them, you must adjust the `private_key` variable in the configuration files to point to your key files' exact names/paths.
:::

::: tip Running the Application
Now that you have enabled at least one security mode, you can go back to the previous page (**Installation**) and read the **Running the Application** section to run your service with peace of mind.
:::

---

## 3. Insecure TLS Mode (Direct Connection with Self-Signed Cert)

This mode is suitable when your server is **not behind a CDN** and you want TLS but cannot easily obtain a valid certificate (like Let's Encrypt).

::: warning Security Warning
In this mode, the client **does not** verify the server's certificate. This implies vulnerability to Man-in-the-Middle (MITM) attacks. For heightened security, use the **One-Way TLS** or **mTLS** modes instead.
:::

### Step 1: Server Configuration

The server must possess a private key. If you haven't generated keys yet, use the following:

```bash
./phoenix-server -gen-keys
mv private.key server.private.key
```

Then in `server.toml`:

```toml
[security]
private_key = "server.private.key"
enable_socks5 = true
enable_udp = true
```

### Step 2: Client Configuration

In `client.toml`, set the `tls_mode` to `"insecure"`:

```toml
remote_addr = "your-server-ip:443"

# TLS mode without certificate verification
tls_mode = "insecure"

[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1080"
enable_udp = true
```

---

## 4. Browser TLS Fingerprint Spoofing — Bypassing ISP DPI

### What is the issue?

Advanced ISP DPI (Deep Packet Inspection) systems can determine from the **TLS ClientHello** message that your traffic originates from a Go application (not a regular browser). This is because the Go standard library leaves a unique "fingerprint".

::: info Symptoms of this issue

- The request makes it from the client to the server (you see it in server logs).
- But the server's response never reaches the client (timeout on the client).
- This issue is very common with certain ISPs (such as in Iran).
  :::

### The Solution: Chrome Fingerprint Spoofing

Phoenix utilizes the `utls` library to forge the TLS ClientHello to perfectly mimic real web browsers.

In `client.toml` (alongside `tls_mode`):

```toml
remote_addr = "your-server-ip:443"

# TLS Activation (Required for fingerprint functionality)
tls_mode = "insecure"

# Browser Fingerprint Spoofing
fingerprint = "chrome"

[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1080"
```

### Allowed `fingerprint` Values

| Value           | Description                                              |
| :-------------- | :------------------------------------------------------- |
| `"chrome"`      | Mimics Chrome 120 — **Recommended** (Best Compatibility) |
| `"firefox"`     | Mimics Firefox 120                                       |
| `"safari"`      | Mimics Safari                                            |
| `"random"`      | Randomized browser on each connection                    |
| Empty (default) | Standard Go TLS (No spoofing)                            |

::: warning Important Limitation
The `fingerprint` feature is ONLY effective when TLS is active:

- `tls_mode = "insecure"` or `tls_mode = "system"`
- Or `server_public_key` / `private_key` have been configured.

In h2c mode (no TLS), this setting has no effect.
:::

---

## 5. Token Authentication (Token Auth)

To add an extra layer of security, you can use an authentication token. This feature is combinable with all TLS modes.

### Step 1: Generate a Token

```bash
# On server or client
./phoenix-server -gen-token
```

The output will be a 64-character random string. Save it.

### Step 2: Server Configuration

```toml
[security]
auth_token = "paste-your-generated-token-here"
enable_socks5 = true
```

### Step 3: Client Configuration

```toml
auth_token = "paste-your-generated-token-here"
```

::: tip Combination with other modes
Token Auth can be combined with all TLS modes (h2c, Insecure, One-Way TLS, mTLS). For absolute maximum security: **mTLS + Token Auth**.
:::

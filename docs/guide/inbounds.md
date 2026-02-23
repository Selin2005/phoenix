# Client Outputs (Inbounds)

When the Phoenix client connects to the server, it creates a secure "tunnel" between your system and the server. In order for your system applications (like Telegram, web browsers, or other tools) to route their data through this tunnel, the Phoenix client opens specific local ports on your system.

These local ports are called **Inbounds**.

The Phoenix system supports several different protocols, and depending on your needs, you can activate one or multiple `inbounds` simultaneously.

---

## General Structure of Client Inbounds

Inside the `client.toml` file, there is a section called `[[inbounds]]`. You can repeat this section to open multiple different ports.
**Crucial Note:** Keep in mind that any `inbound` on the client side only functions if the corresponding feature is enabled in `server.toml`.

```toml
# Example of a SOCKS5 Inbound
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1080"
enable_udp = true
```

---

## 1. SOCKS5 Output (Standard Proxy)

The most common and widely used output is the standard **SOCKS5**. Almost all modern applications (Telegram, browsers via extensions, tools like Proxifier or V2rayNG on Windows/Mobile) support SOCKS5 proxies.

### Client Settings:

```toml
[[inbounds]]
protocol = "socks5"
local_addr = "127.0.0.1:1080"
enable_udp = true   # Recommended to be true
```

### Server Settings (`server.toml`):

For this output to function, the following variables must be enabled on the server:

```toml
[security]
enable_socks5 = true
enable_udp = true
```

::: tip Why is UDP important?
Traffic for many modern services (like Telegram voice calls, YouTube videos using QUIC, online games) relies on the UDP protocol. Keeping `enable_udp` on allows the client to pass this type of traffic through the tunnel as well.
:::

---

## 2. Shadowsocks Output (Local Proxy)

By activating this `inbound`, the Phoenix client essentially becomes a local **Shadowsocks** server on your system.

### What is its use case?

Integrating this feature into Phoenix does not necessarily mean you _should_ use it on your mobile phone directly.
Some users have specific router applications or clients that only support Shadowsocks clients (and not SOCKS5), or they prefer to broadcast their internet access on their home local area network (LAN). By activating this, Phoenix transforms into a Shadowsocks hub or access point.

### Client Settings:

Add a new section with the `shadowsocks` protocol to `client.toml`:

```toml
[[inbounds]]
protocol = "shadowsocks"
# The port you want to open on your system
local_addr = "127.0.0.1:8388"
# Authentication with the structure: "cipher:password"
auth = "aes-256-gcm:my-secret-password"
```

### Server Settings (`server.toml`):

Enable Shadowsocks support on the server:

```toml
[security]
enable_shadowsocks = true
```

### Supported Ciphers

For the `auth` section in the client config, you can use the following ciphers:

- `aes-256-gcm` (Widely used, excellent compatibility)
- `aes-128-gcm` (Faster)
- `chacha20-ietf-poly1305` (Better performance on mobile processors and routers - highly optimized)

### Extracting the Connection Link (`ss://`)

If you want to configure a Shadowsocks app or client, you can ask Phoenix to generate the specific link for you.
After configuring `client.toml`, run this command on your system:

```bash
./phoenix-client -conf client.toml -get-ss
```

The output will look similar to this:

```text
ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp5b3VyLXBhc3N3b3Jk@127.0.0.1:8388
```

You can enter this link into client applications (like Outline, v2rayNG, Shadowrocket, etc.) to connect the application to your local Phoenix output!

---

## 3. SSH Output (SSH Tunnel)

Another advanced feature of Inbounds in Phoenix is the ability to securely tunnel SSH traffic over Phoenix (hiding it inside HTTP/2 web traffic). This output is primarily used by sysadmins who need secure, DPI-invisible administration access.

### Client Settings:

```toml
[[inbounds]]
protocol = "ssh"
local_addr = "127.0.0.1:2022"
# Path to the private key used for SSH authentication
auth = "/home/user/.ssh/id_rsa"
```

### Server Settings (`server.toml`):

```toml
[security]
enable_ssh = true
```

By doing this, you'll have an SSH output listening on your local port 2022. You can simply run `ssh root@127.0.0.1 -p 2022`, and Phoenix will route the traffic transparently through its tunnel directly to the main server.

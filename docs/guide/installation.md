# Installation

This guide provides a practical, step-by-step explanation of how to install the Phoenix server and client.

## 1. Download and Install Server (Server Side)

First, you need to download the **Server** version on your Virtual Private Server (VPS).
Please select the relevant tab based on your server's operating system and run the commands.

::: code-group

```bash [Linux AMD64]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-server-linux-amd64.zip
unzip phoenix-server-linux-amd64.zip -d phoenix
cd phoenix
cp example_server.toml server.toml
chmod +x phoenix-server
```

```bash [Linux ARM64]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-server-linux-arm64.zip
unzip phoenix-server-linux-arm64.zip -d phoenix
cd phoenix
cp example_server.toml server.toml
chmod +x phoenix-server
```

```powershell [Windows AMD64 (PowerShell)]
Invoke-WebRequest -Uri "https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-server-windows-amd64.zip" -OutFile "phoenix-server.zip"
Expand-Archive -Path "phoenix-server.zip" -DestinationPath "phoenix"
cd phoenix
Copy-Item "example_server.toml" -Destination "server.toml"
```

:::

::: tip Important Note
The `server.toml` file has been created, which must be configured in the next step (Configuration). Do not run the application just yet.
:::

### Initial Server Configuration

::: tip Linux File Editor
To edit `server.toml` in the Linux terminal environment, you can use the `nano` command:

```bash
nano server.toml
```

To save your changes, press `Ctrl+O` and then `Enter`. To exit, press `Ctrl+X`.
:::

::: warning Important Attention
You **must** configure all variables in the table below (except optional crypto-related ones).
:::

::: info Note
In TOML files, the `#` sign at the beginning of a line means it is a Comment, and that line will not be executed.
:::

| Variable             | Type    | Status       | Description                                                                                                                               |
| :------------------- | :------ | :----------- | :---------------------------------------------------------------------------------------------------------------------------------------- |
| `listen_addr`        | String  | **Required** | The address and port the server listens on (e.g., `":443"`).                                                                              |
| `[security]`         | Section | **Required** | Starts the section for security settings and protocols.                                                                                   |
| `auth_token`         | String  | Optional     | Shared authentication token. Only clients possessing this exact token are allowed to connect.                                             |
| `enable_socks5`      | Boolean | **Required** | Are clients allowed to use the SOCKS5 protocol? (`true` or `false`).                                                                      |
| `enable_udp`         | Boolean | **Required** | UDP support. Most modern services (YouTube, Instagram) require this. Only set to `false` for specific use cases like Telegram (TLS-only). |
| `enable_shadowsocks` | Boolean | **Required** | Enable support for the Shadowsocks protocol.                                                                                              |
| `enable_ssh`         | Boolean | **Required** | Enable support for SSH tunneling.                                                                                                         |
| `private_key`        | String  | Optional     | Path to the server's private key file (only for secure TLS modes).                                                                        |
| `authorized_clients` | Array   | Optional     | A list of public keys belonging to authorized clients (only for mTLS).                                                                    |

---

## 2. Download and Install Client (Client Side)

Now, download the **Client** version for your personal device (Windows, Linux, or macOS).

::: code-group

```powershell [Windows AMD64 (PowerShell)]
Invoke-WebRequest -Uri "https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-windows-amd64.zip" -OutFile "phoenix-client.zip"
Expand-Archive -Path "phoenix-client.zip" -DestinationPath "phoenix"
cd phoenix
Copy-Item "example_client.toml" -Destination "client.toml"
```

```bash [Linux AMD64]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-linux-amd64.zip
unzip phoenix-client-linux-amd64.zip -d phoenix
cd phoenix
cp example_client.toml client.toml
chmod +x phoenix-client
```

```bash [macOS Intel]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-darwin-amd64.zip
unzip phoenix-client-darwin-amd64.zip -d phoenix
cd phoenix
cp example_client.toml client.toml
chmod +x phoenix-client
```

```bash [macOS Silicon]
wget https://github.com/Fox-Fig/phoenix/releases/latest/download/phoenix-client-darwin-arm64.zip
unzip phoenix-client-darwin-arm64.zip -d phoenix
cd phoenix
cp example_client.toml client.toml
chmod +x phoenix-client
```

:::

::: warning Attention
Do not run the `client.toml` file yet! You need to configure it first.
:::

### Initial Client Configuration

::: tip Note
The `client.toml` file has been created. You can open it with Notepad or any other text editor.
:::

#### 1. Global Settings

| Variable            | Type   | Status       | Description                                                                                             |
| :------------------ | :----- | :----------- | :------------------------------------------------------------------------------------------------------ |
| `remote_addr`       | String | **Required** | The Phoenix server address (IP or domain) and port. Example: `"203.0.113.10:443"`.                      |
| `server_public_key` | String | Optional     | The server's public key (for One-way TLS and mTLS matching).                                            |
| `private_key`       | String | Optional     | Path to the client's private key file (only for mTLS).                                                  |
| `auth_token`        | String | Optional     | The shared authentication token between server and client (generated using `-gen-token`).               |
| `tls_mode`          | String | Optional     | TLS mode: `"system"` (for CDN/Cloudflare) or `"insecure"` (direct server with self-signed certificate). |
| `fingerprint`       | String | Optional     | Browser fingerprint spoofing: `"chrome"`, `"firefox"`, `"safari"`, `"random"`                           |

#### 2. Inbound Settings (`[[inbounds]]`)

This section specifies which ports the client will listen on locally on your computer. You can have multiple inbounds.

::: tip Comprehensive Guide to Creating and Managing Inbounds
Phoenix supports various inbound types such as SOCKS5, Shadowsocks, and SSH tunneling. If you need more details and want to understand how each inbounds works (as well as its cryptography), be sure to read the **[Managing Inbounds (Inbounds)](inbounds.md)** page!
:::

::: tip Disabling an Inbound
If you want to disable an inbound, simply put a `#` at the beginning of its lines to comment them out.
:::

::: warning Important Note on Server Support
Keep in mind that defined inbounds will only function if the server supports the given feature (e.g., `enable_shadowsocks = true` in the server config).
:::

| Variable     | Type    | Status       | Description                                                                                                     |
| :----------- | :------ | :----------- | :-------------------------------------------------------------------------------------------------------------- |
| `protocol`   | String  | **Required** | The protocol type of the inbound. Allowed values: `"socks5"`, `"shadowsocks"`, `"ssh"`.                         |
| `local_addr` | String  | **Required** | The local address and port opened on your system. Example: `"127.0.0.1:1080"`.                                  |
| `enable_udp` | Boolean | Optional     | Enable UDP Associate (for SOCKS5 only). Usually recommended as `true` for modern services (YouTube, Instagram). |
| `auth`       | String  | Optional     | Authentication info (e.g., Shadowsocks password or path to SSH Key).                                            |

---

## Running the Application

::: danger Security Warning
If you have only filled out the required fields in the config files up to this point, the application will work and you can run it; **BUT it has no security and is completely Cleartext!**

Therefore, if you intend to enable security modes (mTLS/One-Way TLS), go to the **Advanced Configuration** page **before running**, complete the relevant settings, and then run your application.
:::

To run the application on the server, use the following command:

```bash
./phoenix-server -config server.toml
```

And to run the client:

```bash
./phoenix-client -config client.toml
```

### Flags Guide

To familiarize yourself with different application flags, you can review the following table:

| Flag         | App    | Description                                                                                                 |
| :----------- | :----- | :---------------------------------------------------------------------------------------------------------- |
| `-config`    | Both   | Specifies the path to the configuration file (Default: `server.toml` or `client.toml`).                     |
| `-gen-keys`  | Both   | Generates a new pair of Ed25519 private and public keys (used for mTLS/One-Way TLS).                        |
| `-gen-token` | Both   | Generates a secure random token for use in `auth_token`.                                                    |
| `-get-ss`    | Client | If you have a Shadowsocks inbound configured, it generates and prints the connection link (`ss://`) for it. |

---

On the next page, you will learn how to **Configure** three different security modes.

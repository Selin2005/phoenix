# Troubleshooting & Logs

::: info Purpose of this page
This page contains a comprehensive list of all errors and messages you might see on the **Server** or **Client** side. If the application is not working, check the logs first and search for the corresponding message in the list below.
:::

## Guide to Reading Logs

When you run the application (on Linux, Windows, or Mac), messages are printed in the terminal.

- **INFO:** Normal messages indicating correct operation.
- **WARNING:** Alerts that do not stop the application but should be reviewed (e.g., low security).
- **FATAL / ERROR:** Critical errors that cause the program to close or the connection to drop.

---

## 1. Client Side Errors

This section covers the messages you see on your computer or phone's terminal.

### A. Startup Errors

| Log Message                                    | Possible Cause                                                                                          | Solution                                                                                               |
| :--------------------------------------------- | :------------------------------------------------------------------------------------------------------ | :----------------------------------------------------------------------------------------------------- |
| `Failed to load config: ...`                   | `client.toml` file does not exist or its format is incorrect.                                           | Make sure the config file is next to the executable and you entered the command correctly (`-config`). |
| `Failed to generate keys: ...`                 | (When using `-gen-keys`) The application lacks write permission on the disk.                            | Run the application with Administrator/Root privileges or test in a different folder.                  |
| `Creating SECURE transport (TLS)`              | **Not an error.** Indicates that a secure mode (mTLS/TLS) is activated.                                 | -                                                                                                      |
| `Creating INSECURE transport (h2c)`            | **Not an error.** Indicates that Insecure mode (Cleartext) is active.                                   | If you intended to be secure, check the config file to ensure the keys are populated.                  |
| `WARNING: server_public_key NOT SET...`        | You have a `private_key` but left `server_public_key` empty.                                            | To prevent MITM attacks, make sure to enter the server's public key in `client.toml`.                  |
| `Failed to load private key: ...`              | The private key file (e.g., `client.private.key`) was not found.                                        | Check the file path in `client.toml`. Does the file exist?                                             |
| `[Transport] TLS Fingerprint Spoofing: chrome` | **Not an error.** Indicates the client is successfully mimicking a browser fingerprint.                 | Normal status.                                                                                         |
| `[Transport] Security Mode: INSECURE TLS`      | **Not an error.** Indicates you are using Insecure TLS mode and the server certificate is not verified. | Recommended if your server lacks a CDN. For more security, see One-Way TLS.                            |
| `[Token] Security Mode: Token Auth ENABLED`    | **Not an error.** Indicates the client has loaded the `auth_token`.                                     | -                                                                                                      |

### B. Connection & Network Errors (Runtime)

| Log Message                                                               | Possible Cause                                                                    | Solution                                                                                                            |
| :------------------------------------------------------------------------ | :-------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------ |
| `Failed to dial server: connection refused`                               | Server is off or wrong port is entered.                                           | Check the server to ensure it is running (`./phoenix-server`). Check the `remote_addr` port on the client.          |
| `Failed to dial server: i/o timeout`                                      | Server firewall or the region's network has blocked the port.                     | Change the server port. Check the server's firewall (ufw).                                                          |
| `server key verification failed. Expected X, Got Y`                       | **Critical:** Your server is fake or the key in config is wrong.                  | Check the server's `public key` in `client.toml`. If the key is correct, you are likely under a MITM attack!        |
| `Failed to listen on 127.0.0.1:1080...`                                   | Port 1080 is occupied by another application (e.g., another VPN).                 | In `client.toml`, change the `local_addr` value to another port (e.g., `1085`).                                     |
| `SOCKS5 Handler Error: ...`                                               | The browser or Telegram dropped the connection or threw an error.                 | If this error repeats frequently, it means your internet connection is unstable.                                    |
| `Error: Shadowsocks inbound found but 'auth' is empty`                    | (When running `-get-ss`) Shadowsocks password in config is empty.                 | For a Shadowsocks inbound, fill the `auth` field using the format `method:password`.                                |
| `tls: peer doesn't support any of the certificate's signature algorithms` | Incompatibility of `utls` (e.g., Chrome) with the server's certificate (Ed25519). | When `fingerprint` is on, the server cannot use an Ed25519 key for TLS cert (See Architecture section 6).           |
| `stream error: stream ID 1; HTTP_1_1_REQUIRED`                            | The client expects HTTP/2 but the server/filtering responds with HTTP/1.1.        | Usually, a filtering system or an intermediary proxy (like a misconfigured CDN) is downgrading traffic to HTTP/1.1. |
| `Token mismatch`                                                          | The token set on the client does not match the server's token.                    | Check the `auth_token` on both sides (server and client).                                                           |

---

## 2. Server Side Errors

These messages are observed in your VPS terminal.

### A. General Errors

| Log Message                                                    | Possible Cause                                                  | Solution                                                              |
| :------------------------------------------------------------- | :-------------------------------------------------------------- | :-------------------------------------------------------------------- |
| `Failed to load config: ...`                                   | `server.toml` file not found or corrupted.                      | Check the configuration file.                                         |
| `Starting Phoenix Server on :443`                              | **Not an error.** The server started successfully on port 443.  | -                                                                     |
| `Server failed: listen tcp :443: bind: access denied`          | The server does not have permission to access ports below 1024. | Run the server with `sudo` or set the port above 1024 (e.g., `8443`). |
| `Server failed: listen tcp :443: bind: address already in use` | Another program (like Nginx or Apache) is active on this port.  | Stop that application or change the Phoenix port.                     |

### B. Security Errors

| Log Message                                        | Possible Cause                                                                 | Solution                                                                                      |
| :------------------------------------------------- | :----------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------- |
| `Client authentication failed`                     | (In mTLS mode) Client lacks a valid private key.                               | Add the client's public key to the server's `authorized_clients`.                             |
| `Handshake error: remote error: bad certificate`   | Client sent an invalid certificate, or keys do not match.                      | Make sure the client and server key pairs are matched (Ed25519).                              |
| `http2: server: error reading preface from client` | A client connects via a non-HTTP/2 protocol (e.g., normal browser or scanner). | This usually indicates Probing by a censor, and the server rightfully dropped the connection. |
| `request rejected: invalid auth token`             | Client token is incorrect or empty.                                            | Ensure the client's `auth_token` matches exactly. The offending client was blocked.           |

---

## 3. Common Scenarios & Solutions

### Scenario 1: App connects, but sites like YouTube won't open

- **Cause:** `enable_udp` is likely off on the server while the client tries to send UDP, or there is a DNS issue.
- **Solution:** Check your browser. Can it open standard HTTP sites? If only Telegram opens, verify `enable_udp`.

### Scenario 2: Zero speed or frequent disconnects

- **Cause:** Severe packet loss on your network or TCP port blocking.
- **Solution:** Change the server port. Use mTLS mode to avoid active probing identification.

### Scenario 3: I receive a `bad certificate` error

- **Cause:** The client and server keys do not match.
- **Solution:** Generate new keys via `-gen-keys` and copy-paste them precisely according to the guide. Ensure the server's public key is in the client config and vice-versa (for mTLS).

### Scenario 4: I get `tls: peer doesn't support signature algorithms` with Chrome Fingerprint

- **Cause:** You enabled `fingerprint = "chrome"` but the server uses an Ed25519 certificate (Chrome does not support Ed25519 for server TLS certificates).
- **Solution:**
  - Either turn off `fingerprint`.
  - Or generate an ECDSA key on the server (Phoenix supports it via source, but to generate one manually you need OpenSSL). A simpler suggestion is using `safari` or `firefox`, or disabling fingerprinting entirely.

### Scenario 5: My traffic drops completely after a few seconds

- **Cause:** Your ISP's DPI system recognizes the traffic anomaly (Go's standard library TLS fingerprint) and drops the packets.
- **Solution:** Ensure `fingerprint = "chrome"` makes active and `tls_mode` is set to `insecure` (if you have no CDN). This makes your traffic appear exactly like a genuine web browser.

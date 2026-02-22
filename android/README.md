<div align="center">
  <img src="https://fox-fig.github.io/phoenix/logo.png" alt="Phoenix Logo" width="160" height="160">
  <h1>Phoenix — Android Client</h1>
  <p>
    <img src="https://img.shields.io/badge/Android-8.0%2B-3DDC84?logo=android&logoColor=white" alt="Android 8.0+">
    <img src="https://img.shields.io/badge/Arch-ARM64-informational" alt="ARM64">
    <img src="https://img.shields.io/badge/Kotlin-Jetpack%20Compose-7F52FF?logo=kotlin&logoColor=white" alt="Kotlin">
    <img src="https://img.shields.io/badge/License-GPLv2-blue.svg" alt="License">
  </p>
  <p>
    Native Android client for <a href="https://github.com/Fox-Fig/phoenix"><strong>Phoenix</strong></a> — a DPI-resistant censorship circumvention tool.<br>
    Route your device traffic through a Phoenix server without root.
  </p>
</div>

---

## What is Phoenix?

[Phoenix](https://github.com/Fox-Fig/phoenix) is a high-performance tunneling tool that bypasses Deep Packet Inspection (DPI) and severe network censorship by wrapping your traffic inside **HTTP/2** connections. It supports SOCKS5, Shadowsocks, and SSH proxying with mutual Ed25519 authentication and TLS.

This Android client connects your phone to an existing Phoenix server and proxies your traffic through it — **no root required**.

---

## Features

- **SOCKS5 Proxy mode** — starts a local proxy on `127.0.0.1:10080`; configure individual apps to use it
- **VPN mode** — routes *all* device traffic transparently through the tunnel using Android's `VpnService` API; no per-app configuration needed
- **mTLS authentication** — Ed25519 mutual authentication; generate client keys directly on-device
- **One-way TLS** — verify the server's identity without client certificates
- **h2c mode** — cleartext HTTP/2 for deployments behind a CDN that provides TLS termination
- **Live connection logs** — swipe from the left edge or tap the debug icon to inspect the tunnel log in real time
- **Runs in the background** — Android Foreground Service survives Doze mode and app minimization
- **No root required** — both SOCKS5 and VPN modes work on standard unrooted devices

---

## Requirements

| Requirement | Minimum |
|---|---|
| Android version | 8.0 (API 26) |
| CPU architecture | ARM64 (arm64-v8a) |
| Phoenix server | Any version with SOCKS5 or mTLS support |
| Root | Not required |

---

## Installation

### Option A — Download APK (recommended)

1. Go to the [Releases page](https://github.com/Fox-Fig/phoenix/releases)
2. Download `phoenix-android-<version>.apk`
3. On your Android device: **Settings → Security → Install unknown apps** and allow your browser or file manager to install APKs
4. Open the downloaded file and tap **Install**

> **Note:** Your device may show a warning about installing apps from unknown sources. This is normal for sideloaded APKs not distributed through the Play Store.

### Option B — Build from source

See [Build from source](#build-from-source) below.

---

## Quick Start

### Step 1 — Set up a Phoenix server

You need a running Phoenix server before using this app. Follow the [server setup guide](https://Fox-Fig.github.io/phoenix/guide/getting-started) to install and configure one on your VPS.

### Step 2 — Configure the Android client

Open the app and tap **Config** in the bottom navigation bar.

#### Server address
Enter your server's address in `host:port` format, for example:
```
203.0.113.42:8443
```

#### TLS / Authentication mode

| Field | When to fill |
|---|---|
| **Server public key** | Fill this to enable mTLS or one-way TLS. Leave blank for h2c (cleartext). |
| **mTLS toggle** | Enable to send your client certificate. Requires key generation (see below). |

To find your server's public key, run on the server:
```bash
./phoenix-server -gen-keys     # generates server.pub and server.key
cat server.pub                  # copy this value into the app
```

### Step 3 — Generate client keys (mTLS only)

If your server requires mutual authentication (`authorized_clients` is set in `server.toml`):

1. In the **Config** screen, enable the **mTLS** toggle
2. Tap **Generate Keys** — the app creates an Ed25519 keypair stored securely on-device
3. A dialog shows your **client public key** — copy it
4. On your server, add it to `server.toml`:
   ```toml
   authorized_clients = [
     "your-client-public-key-here"
   ]
   ```
5. Restart the Phoenix server

You can view your public key again at any time by tapping the eye icon next to the key field.

### Step 4 — Choose a connection mode

Tap **Settings** in the bottom navigation bar and choose:

| Mode | How it works | Use when |
|---|---|---|
| **SOCKS5 Proxy** | Local proxy on `127.0.0.1:10080`; you configure each app manually | You only need specific apps tunneled |
| **VPN mode** | All device traffic is routed through the tunnel automatically | You want full-device protection |

### Step 5 — Connect

Go back to the **Home** tab and tap **Connect**.

- The status card turns **green** when the tunnel is active
- Connection mode, uptime, and local proxy address are shown in the Connection Info card below

---

## Using SOCKS5 Proxy Mode

When in SOCKS5 mode, the app does **not** automatically intercept all traffic. You need to configure each app or browser to use the local proxy.

**Proxy settings to use:**
```
Host:  127.0.0.1
Port:  10080
Type:  SOCKS5
```

### Browser (Firefox for Android)
1. Settings → General → Network Settings → Manual proxy configuration
2. SOCKS Host: `127.0.0.1`, Port: `10080`, select **SOCKS v5**
3. Check **Proxy DNS when using SOCKS v5**

### System-wide (via third-party apps)
Apps like **SocksDroid** or **Shadowsocks** can forward all system traffic through a SOCKS5 proxy.

Alternatively, switch to **VPN mode** (see Settings) — it does this automatically.

---

## Using VPN Mode

VPN mode routes **all device traffic** through the Phoenix tunnel with no per-app configuration. When you tap Connect in VPN mode:

1. Android shows a one-time VPN permission dialog — tap **OK**
2. A VPN key icon appears in your status bar confirming the tunnel is active
3. The Phoenix app itself is excluded from the VPN to prevent routing loops

To stop tunneling, open the app and tap **Disconnect**, or pull down the notification and tap Stop.

---

## Debug Logs

To see the raw tunnel output:
- **Swipe right** from the left edge of the Home screen, or
- Tap the **bug icon** (top-left of the Home screen)

The log panel shows color-coded output:
- 🟢 Green — normal tunnel messages
- 🟡 Yellow — commands sent to the Go process
- 🔴 Red — errors

Tap **Copy** to share logs when reporting issues.

---

## Build from Source

### Prerequisites

- [Go 1.24+](https://go.dev/dl/)
- [Android Studio](https://developer.android.com/studio) (Ladybug or newer) with SDK 35
- JDK 17

### 1. Clone the repository

```bash
git clone https://github.com/Fox-Fig/phoenix.git
cd phoenix
```

### 2. Build the Go binary for Android ARM64

```bash
make android-client
```

This cross-compiles `cmd/android-client/main.go` for `linux/arm64` and places the output at:
```
android/app/src/main/jniLibs/arm64-v8a/libphoenixclient.so
```

### 3. Build the APK

```bash
cd android
./gradlew assembleDebug
```

The debug APK is at:
```
android/app/build/outputs/apk/debug/app-debug.apk
```

Install on a connected device:
```bash
adb install android/app/build/outputs/apk/debug/app-debug.apk
```

---

## Architecture

```
Android UI (Kotlin / Jetpack Compose)
  └── HomeScreen / ConfigScreen / SettingsScreen
       └── HomeViewModel / ConfigViewModel
            └── PhoenixService (SOCKS5 mode)
            └── PhoenixVpnService (VPN mode)
                 └── libphoenixclient.so  ← Go binary (cmd/android-client/)
                      ├── SOCKS5 listener  (pkg/adapter/socks5)
                      ├── HTTP/2 transport (pkg/transport/client.go)
                      └── tun2socks engine (VPN mode only)
```

**Key design decisions:**

- The Go binary ships as `libphoenixclient.so` inside `jniLibs/arm64-v8a/` so Android places it in the app's `nativeLibraryDir`, which is always executable (bypasses the W^X policy that blocks executing files extracted from assets)
- VPN mode uses [tun2socks](https://github.com/xjasonlyu/tun2socks) to forward TUN device traffic into the local SOCKS5 listener
- The TUN file descriptor is passed from Kotlin to the Go process via the `-tun-fd` flag using `SCM_RIGHTS` fd passing
- Service events (connected, disconnected, error, log lines) are delivered via an in-process `SharedFlow` bus (`ServiceEvents.kt`) — more reliable than Android broadcasts on Samsung devices

---

## Limitations

| Limitation | Notes |
|---|---|
| ARM64 only | The bundled Go binary targets `linux/arm64`. arm32 support requires a separate build. |
| Shadowsocks mode | Not yet available in the Android client. SOCKS5 and mTLS/h2c work. |
| CDN / system TLS mode | Not yet exposed in the Android UI. |
| h2c to external hosts | Android 9+ blocks cleartext HTTP to external hosts by default. h2c mode works only with a CDN that terminates TLS in front of your server. |

---

## Troubleshooting

**"client didn't provide a certificate"**
→ mTLS is enabled on the server but your client keys are not set up. Go to Config → enable mTLS → Generate Keys → add your public key to `authorized_clients` on the server.

**"Connection timed out after 20 s"**
→ The server address is wrong, the server is not running, or a firewall is blocking the port. Check the debug logs for details.

**VPN permission dialog does not appear**
→ The app may already have VPN permission from a previous session. If you uninstalled and reinstalled the app, Android may have revoked it — go to Settings → Apps → Phoenix → Permissions and check.

**App crashes on launch**
→ Ensure your device is ARM64. The binary will not run on x86 emulators or arm32 devices.

---

## License

This project is licensed under the [GPLv2 License](../LICENSE).

---

<div align="center">
  Part of the <a href="https://github.com/Fox-Fig/phoenix">Phoenix project</a> — made with ❤️ by <a href="https://t.me/FoxFig">FoxFig Team</a><br>
  Dedicated to all people of Iran 🇮🇷
</div>

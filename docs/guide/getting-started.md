# Getting Started with Phoenix

Welcome to the Phoenix documentation. This guide will help you install, configure, and run your own Phoenix server and client.

## Installation

### Prerequisites

- A remote server (VPS) with Linux.
- Go 1.21+ installed on your build machine (or download releases).

### Quick Install

```bash
git clone https://github.com/Selin2005/phoenix.git
cd phoenix
make build
```

## Running the Server

1. **Copy the binary** to your VPS.
2. **Create a config file** `server.toml` (see `example_server.toml`).
3. **Run**:
   ```bash
   ./phoenix-server -c server.toml
   ```

## Running the Client

1. **Create a config file** `client.toml` (see `example_client.toml`).
2. **Run**:
   ```bash
   ./phoenix-client -c client.toml
   ```
3. **Connect** your browser or applications to the SOCKS5 proxy (default port 1080).

## Advanced Usage

For more advanced configurations, including CDN setup and mTLS, please refer to the dedicated sections.

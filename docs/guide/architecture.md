# Architecture of Phoenix

Phoenix is designed around the concept of simple, stateless, and high-performance tunneling.

## Core Components

### 1. h2c Multiplexing
HTTP/2 Cleartext (h2c) allows us to send multiple streams of data over a single TCP connection. This reduces handshake overhead and makes the traffic look like standard HTTP/2 requests.

### 2. Client
The client listens on local interfaces (SOCKS5, HTTP, SSH) and multiplexes the incoming connections into h2c streams to the server.

### 3. Server
The server accepts h2c connections, demultiplexes the streams, and forwards the traffic to the final destination.

## CDN Compatibility
Because Phoenix uses standard HTTP/2 frames, it can be proxied through Content Delivery Networks (CDNs) like Cloudflare. The CDN sees valid HTTP traffic and forwards it to the Phoenix server.

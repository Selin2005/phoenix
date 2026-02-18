package protocol

// ProtocolType defines the type of protocol being tunneled or requested.
type ProtocolType string

const (
	// ProtocolSOCKS5 represents the SOCKS5 proxy protocol (TCP).
	ProtocolSOCKS5 ProtocolType = "socks5"
	// ProtocolSOCKS5UDP represents the SOCKS5 proxy protocol (UDP Tunnel).
	ProtocolSOCKS5UDP ProtocolType = "socks5-udp"
	// ProtocolShadowsocks represents the Shadowsocks proxy protocol.
	ProtocolShadowsocks ProtocolType = "shadowsocks"
	// ProtocolSSH represents SSH tunneling.
	ProtocolSSH ProtocolType = "ssh"
	// ProtocolHTTP represents HTTP proxying (for future use).
	ProtocolHTTP ProtocolType = "http"
)

// Inbound defines a single listener on the client side.
type Inbound struct {
	// Protocol is the type of protocol to listen for (e.g., "socks5", "ssh").
	Protocol ProtocolType `toml:"protocol"`
	// ListenAddr is the local address to bind to (e.g., "127.0.0.1:1080").
	ListenAddr string `toml:"listen_addr"`
	// TargetAddr is the remote destination address (optional, used for port forwarding).
	TargetAddr string `toml:"target_addr,omitempty"`
}

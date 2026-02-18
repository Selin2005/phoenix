package transport

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"time"

	"golang.org/x/net/http2"
)

// Client handles outgoing connections to the Server.
type Client struct {
	Config *config.ClientConfig
	Client *http.Client
	Scheme string
}

// NewClient creates a new Phoenix client instance.
func NewClient(cfg *config.ClientConfig) *Client {
	var tr *http2.Transport
	scheme := "http"

	// Check if Secure Mode is requested (mTLS or One-Way TLS)
	// Requires either PrivateKey (mTLS) OR ServerPublicKey (One-Way)
	if cfg.PrivateKeyPath != "" || cfg.ServerPublicKey != "" {
		log.Println("Initializing Client in SECURE mode (TLS)")
		scheme = "https"

		var certs []tls.Certificate
		if cfg.PrivateKeyPath != "" {
			priv, err := crypto.LoadPrivateKey(cfg.PrivateKeyPath)
			if err != nil {
				log.Fatalf("Failed to load private key: %v", err)
			}
			cert, err := crypto.GenerateTLSCertificate(priv)
			if err != nil {
				log.Fatalf("Failed to generate TLS cert: %v", err)
			}
			certs = []tls.Certificate{cert}
		} else {
			log.Println("No private_key provided. Using One-Way TLS (Anonymous Client).")
		}

		tlsConfig := &tls.Config{
			Certificates:       certs,
			InsecureSkipVerify: true, // We use custom verification
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if cfg.ServerPublicKey == "" {
					// Pinning disabled. Insecure against MITM.
					// Allow it? For "easy setup"? User requested "security multiplied".
					// But we will allow it with warning if user explicitly omits key.
					log.Println("WARNING: server_public_key NOT SET. Connection vulnerable to MITM.")
					return nil
				}

				if len(rawCerts) == 0 {
					return errors.New("no server certificate presented")
				}
				leaf, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return fmt.Errorf("failed to parse server cert: %v", err)
				}

				pub := leaf.PublicKey
				pubBytes, ok := pub.(ed25519.PublicKey)
				if !ok {
					return errors.New("server key is not Ed25519")
				}

				pubStr := base64.StdEncoding.EncodeToString(pubBytes)
				if pubStr != cfg.ServerPublicKey {
					return fmt.Errorf("server key verification failed. Expected %s, Got %s", cfg.ServerPublicKey, pubStr)
				}
				return nil
			},
		}

		tr = &http2.Transport{
			TLSClientConfig:            tlsConfig,
			StrictMaxConcurrentStreams: true,
			ReadIdleTimeout:            0,
			PingTimeout:                5 * time.Second,
		}

	} else {
		// INSECURE MODE (h2c)
		log.Println("Initializing Client in INSECURE mode (h2c)")
		tr = &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
			StrictMaxConcurrentStreams: true,
			ReadIdleTimeout:            0,
			PingTimeout:                5 * time.Second,
		}
	}

	return &Client{
		Config: cfg,
		Client: &http.Client{Transport: tr},
		Scheme: scheme,
	}
}

// Dial initiates a tunnel for a specific protocol.
// It connects to the server and returns the stream to be used by the local listener.
func (c *Client) Dial(proto protocol.ProtocolType, target string) (io.ReadWriteCloser, error) {
	// We use io.Pipe to bridge the local connection to the request body.
	pr, pw := io.Pipe()

	req, err := http.NewRequest("POST", c.Scheme+"://"+c.Config.RemoteAddr, pr)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("X-Nerve-Protocol", string(proto))
	if target != "" {
		req.Header.Set("X-Nerve-Target", target)
	}
	// req.Header.Set("Upgrade", "h2c") // Not strictly needed with AllowHTTP=true client transport

	// Execute request asynchronously because the body (pr) will block until written to.
	// We return a ReadWriteCloser that writes to pw and reads from resp.Body.

	respChan := make(chan *http.Response, 1)
	errChan := make(chan error, 1)

	go func() {
		resp, err := c.Client.Do(req)
		if err != nil {
			errChan <- err
			return
		}
		respChan <- resp
	}()

	// Wait for response headers (indicating connection established) or error.
	// Note: since we're piping the request body, the server might not reply until we send data if it buffers.
	// However, standard http client sends headers first.
	// But `Do` blocks until response headers are received. If the server waits for body before ANY response, deadlock!
	// H2C should support full duplex streaming.
	// BUT, http.Client.Do generally waits for response headers.
	// If the server doesn't send headers immediately, we're stuck.
	// Server MUST write headers immediately on `ServeHTTP`. (w.WriteHeader + Flush)

	select {
	case resp := <-respChan:
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("server rejected connection with status: %d", resp.StatusCode)
		}
		return &Stream{
			Writer: pw,
			Reader: resp.Body,
			Closer: resp.Body,
		}, nil
	case err := <-errChan:
		return nil, err
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("connection to server timed out")
	}
}

// Stream wraps the pipe endpoint to implement io.ReadWriteCloser.
type Stream struct {
	io.Writer
	io.Reader
	io.Closer
}

func (s *Stream) Close() error {
	s.Closer.Close()
	if w, ok := s.Writer.(io.Closer); ok {
		w.Close()
	}
	return nil
}

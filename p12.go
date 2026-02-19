package cybersource_soap_dm

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// loadP12Certificate loads a P12/PFX certificate file and returns a TLS certificate
// containing the leaf certificate, CA chain, and private key.
func loadP12Certificate(p12Path, password string) (tls.Certificate, error) {
	p12Path = expandHome(p12Path)
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read P12 file %s: %w", p12Path, err)
	}

	privateKey, leaf, caCerts, err := pkcs12.DecodeChain(p12Data, password)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to decode P12 certificate: %w", err)
	}

	chain := make([][]byte, 0, 1+len(caCerts))
	chain = append(chain, leaf.Raw)
	for _, c := range caCerts {
		chain = append(chain, c.Raw)
	}

	return tls.Certificate{
		Certificate: chain,
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, nil
}

// expandHome replaces a leading "~/" with the user's home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

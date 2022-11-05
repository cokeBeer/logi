package certs

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"os"
	"path"
	"strings"

	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
)

// Manager implements a certificate signing authority for TLS Mitm.
type Manager struct {
	cert  *tls.Certificate
	cache *lru.Cache
}

// Options contains the configuration options for certificate signing client.
type Options struct {
	CacheSize int
	Directory string
}

const (
	caKeyName  = "cakey.pem"
	caCertName = "cacert.pem"
)

// New creates a new certificate manager signing client instance
func New(options *Options) (*Manager, error) {
	manager := &Manager{}

	certFile := path.Join(options.Directory, caCertName)
	keyFile := path.Join(options.Directory, caKeyName)

	_, certFileErr := os.Stat(certFile)
	_, keyFileErr := os.Stat(keyFile)
	if os.IsNotExist(certFileErr) || os.IsNotExist(keyFileErr) {
		if err := manager.createAuthority(certFile, keyFile); err != nil {
			return nil, errors.Wrap(err, "could not create certificate authority")
		}
	}
retryRead:
	cert, err := manager.readCertificateDisk(certFile, keyFile)
	if err != nil {
		// Check if we have an expired cert and regenerate
		if err == errExpiredCert {
			if err := manager.createAuthority(certFile, keyFile); err != nil {
				return nil, errors.Wrap(err, "could not create certificate authority")
			}
			goto retryRead
		}
		return nil, errors.Wrap(err, "could not read certificate authority")
	}

	cache, err := lru.New(options.CacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "could not create lru cache")
	}
	return &Manager{cert: cert, cache: cache}, nil
}

// GetCA returns the CA certificate in PEM Encoded format.
func (m *Manager) GetCA() (tls.Certificate, []byte) {
	buffer := &bytes.Buffer{}

	_ = pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Certificate[0]})
	return *m.cert, buffer.Bytes()
}

// Get returns a certificate for the current host.
func (m *Manager) Get(host string) (*tls.Certificate, error) {
	if value, ok := m.cache.Get(host); ok {
		return value.(*tls.Certificate), nil
	}
	cert, err := m.signCertificate(host)
	if err != nil {
		return nil, err
	}
	m.cache.Add(host, cert)
	return cert, nil
}

func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}

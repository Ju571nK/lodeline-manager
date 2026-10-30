package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Ju571nK/sigil-manager/internal/config"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func issue(t *testing.T, tmpl *x509.Certificate, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCert{cert: cert, key: key, der: der}
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600))
}

// mtlsServer starts a sigil-server stand-in that, like sigil-server with
// client_ca_path set, refuses any connection without a client certificate
// from its CA. It returns the server and the paths a manager would be given.
func mtlsServer(t *testing.T) (srv *httptest.Server, caPath, certPath, keyPath string) {
	t.Helper()
	ca := issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "test-ca"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, nil)
	server := issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "sigil-server"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca)
	client := issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "sigil-manager"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca)

	dir := t.TempDir()
	caPath, certPath, keyPath = filepath.Join(dir, "ca.crt"), filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	writePEM(t, caPath, "CERTIFICATE", ca.der)
	writePEM(t, certPath, "CERTIFICATE", client.der)
	keyDER, err := x509.MarshalECPrivateKey(client.key)
	require.NoError(t, err)
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","ts":"2026-10-30T00:00:00Z"}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{server.der}, PrivateKey: server.key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, caPath, certPath, keyPath
}

func managerEnv(t *testing.T, baseURL string, extra map[string]string) {
	t.Helper()
	env := map[string]string{
		"SIGIL_SERVER_BASE_URL":         baseURL,
		"SIGIL_SERVER_READ_TOKEN":       "token",
		"ADMIN_USERNAME":                "admin",
		"ADMIN_PASSWORD_BCRYPT":         "$2a$04$abcdefghijklmnopqrstuuFooBarBazQuuxCorgePloghTes12tHashXY",
		"JWT_SECRET":                    "abcdefghijklmnopqrstuvwxyzABCDEF",
		"FLEET_CACHE_DISABLED":          "1",
		"MOCK_FLEET":                    "",
		"SIGIL_SERVER_CA_PATH":          "",
		"SIGIL_SERVER_CLIENT_CERT_PATH": "",
		"SIGIL_SERVER_CLIENT_KEY_PATH":  "",
	}
	for k, v := range extra {
		env[k] = v
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func TestNewFromConfig_ReachesMTLSServerWithClientCert(t *testing.T) {
	srv, caPath, certPath, keyPath := mtlsServer(t)
	managerEnv(t, srv.URL, map[string]string{
		"SIGIL_SERVER_CA_PATH":          caPath,
		"SIGIL_SERVER_CLIENT_CERT_PATH": certPath,
		"SIGIL_SERVER_CLIENT_KEY_PATH":  keyPath,
	})
	cfg, err := config.Load()
	require.NoError(t, err)

	h, err := NewFromConfig(cfg).Healthz(context.Background())
	require.NoError(t, err)
	require.Equal(t, "ok", h.Status)
}

func TestNewFromConfig_MTLSServerRejectsManagerWithoutClientCert(t *testing.T) {
	srv, caPath, _, _ := mtlsServer(t)
	managerEnv(t, srv.URL, map[string]string{"SIGIL_SERVER_CA_PATH": caPath})
	cfg, err := config.Load()
	require.NoError(t, err)

	_, err = NewFromConfig(cfg).Healthz(context.Background())
	require.Error(t, err)
}

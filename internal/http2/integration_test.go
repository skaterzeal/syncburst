package http2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/skaterzeal/syncburst/internal/request"
)

// startVulnerableServer starts an in-process HTTPS (h2-capable) server with a
// TOCTOU race on a single-use code, and returns its authority.
func startVulnerableServer(t *testing.T) string {
	t.Helper()
	cert := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	used := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/redeem", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		already := used["X"]
		mu.Unlock()
		if already {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"status":"already_redeemed"}`)
			return
		}
		time.Sleep(15 * time.Millisecond) // race window
		mu.Lock()
		used["X"] = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"redeemed"}`)
	})
	srv := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, // stdlib auto-enables h2
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"127.0.0.1"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestSinglePacketRace(t *testing.T) {
	authority := startVulnerableServer(t)
	req := request.Request{
		Method: "POST", Scheme: "https", Authority: authority, Path: "/redeem",
		Body: []byte(`{"code":"X"}`),
	}
	e := New()
	e.Insecure = true
	resps, err := e.Fire(request.Repeat(req, 20))
	if err != nil {
		t.Fatalf("Fire: %v", err)
	}

	success := 0
	for _, r := range resps {
		if r.Err != nil {
			t.Errorf("stream %d error: %v", r.Index, r.Err)
			continue
		}
		if r.Status != 200 && r.Status != 409 {
			t.Errorf("stream %d unexpected status %d", r.Index, r.Status)
		}
		if r.BodyLen == 0 {
			t.Errorf("stream %d empty body", r.Index)
		}
		if len(r.Body) != r.BodyLen {
			t.Errorf("stream %d body capture=%d full-length=%d", r.Index, len(r.Body), r.BodyLen)
		}
		if r.Status == 200 {
			success++
		}
	}
	// A correct single-use limit permits exactly one success; more than one
	// proves the race window was exploited.
	if success < 2 {
		t.Errorf("expected the race to yield >1 success, got %d", success)
	}
	t.Logf("single-packet race: %d/20 succeeded (limit bypassed)", success)
}

package http1

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

func startVulnerableServer(t *testing.T) string {
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
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	used := false
	mux := http.NewServeMux()
	mux.HandleFunc("/redeem", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		already := used
		mu.Unlock()
		if already {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"status":"already"}`)
			return
		}
		time.Sleep(15 * time.Millisecond)
		mu.Lock()
		used = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"redeemed"}`)
	})
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestLastByteSyncRace(t *testing.T) {
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
			t.Errorf("req %d error: %v", r.Index, r.Err)
			continue
		}
		if r.Status == 200 {
			success++
		}
	}
	if success < 2 {
		t.Errorf("expected the race to yield >1 success, got %d", success)
	}
	t.Logf("last-byte-sync race: %d/20 succeeded (limit bypassed)", success)
}

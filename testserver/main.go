// Command testserver is a deliberately vulnerable target for exercising
// syncburst. POST /redeem performs a non-atomic check-then-act on a single-use
// code, with an artificial window, so concurrent requests can each pass the
// "already used?" check before any of them records the redemption — a textbook
// TOCTOU race. It serves TLS, so Go negotiates HTTP/2 (h2) or HTTP/1.1 via ALPN.
//
// FOR LOCAL TESTING ONLY. Do not expose this to a network.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	delay := flag.Duration("delay", 15*time.Millisecond, "artificial race window width")
	flag.Parse()

	srv := &target{used: map[string]bool{}, window: *delay}
	mux := http.NewServeMux()
	mux.HandleFunc("/redeem", srv.redeem)
	mux.HandleFunc("/reset", srv.reset)

	cert, err := selfSignedCert()
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	httpSrv := &http.Server{
		Addr:      *addr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
	}
	log.Printf("vulnerable testserver on https://%s  (race window %s)", *addr, *delay)
	log.Printf("  POST /redeem {\"code\":\"X\"}   POST /reset")
	log.Fatal(httpSrv.ListenAndServeTLS("", ""))
}

type target struct {
	mu     sync.Mutex // guards used only for read/write of the map itself
	used   map[string]bool
	window time.Duration
}

type redeemReq struct {
	Code string `json:"code"`
}

func (t *target) redeem(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req redeemReq
	_ = json.Unmarshal(body, &req)
	if req.Code == "" {
		req.Code = "GIFT100"
	}

	// --- Vulnerable check-then-act ---
	// Read current state.
	t.mu.Lock()
	already := t.used[req.Code]
	t.mu.Unlock()

	if already {
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, `{"status":"already_redeemed","code":%q}`, req.Code)
		return
	}

	// Artificial window between check and act; concurrent requests interleave
	// here and all see already == false.
	time.Sleep(t.window)

	t.mu.Lock()
	t.used[req.Code] = true
	t.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"redeemed","code":%q,"reward":"$100"}`, req.Code)
}

func (t *target) reset(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	t.used = map[string]bool{}
	t.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, `{"status":"reset"}`)
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "syncburst-testserver"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

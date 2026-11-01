// Command mockupstream serves internal/mock (a DSH look-alike) for the end to
// end harness: mockupstream 127.0.0.1:3190 [TLSADDR CAFILE]
//
// With TLSADDR it also serves the same handler over TLS (a stand-in for "a
// site on the internet" in the sealed egress tests) with a fresh self-signed
// certificate for 127.0.0.1, written to CAFILE for dsh-seal's egress_ca_file.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"dsh-seal/internal/mock"
)

func main() {
	addr := "127.0.0.1:3190"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	if len(os.Args) > 3 {
		go serveTLS(os.Args[2], os.Args[3])
	}
	log.Fatal(http.ListenAndServe(addr, mock.Handler()))
}

func serveTLS(addr, caFile string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "mock remote"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"remote.example.net"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: addr, Handler: mock.Handler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

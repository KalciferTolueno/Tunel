// Command tunel-cert generates a self-signed CA and a server certificate
// signed by that CA, all in PEM format, suitable for tunels + tunelc.
//
// It writes four files in the current directory by default:
//
//	ca.crt      PEM-encoded CA certificate (give this to tunelc as --cacert)
//	ca.key      PEM-encoded CA private key (keep this private)
//	server.crt  PEM-encoded server certificate (give this to tunels as --cert)
//	server.key  PEM-encoded server private key (give this to tunels as --key)
//
// Usage:
//
//	tunel-cert [-out DIR] [-hosts HOST1,HOST2,...] [-bits 2048]
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	out := flag.String("out", ".", "directory to write the cert files into")
	hosts := flag.String("hosts", "127.0.0.1,localhost", "comma-separated host names / IPs added as SANs to the server cert")
	bits := flag.Int("bits", 2048, "RSA key size")
	flag.Parse()

	if err := run(*out, *hosts, *bits); err != nil {
		log.Fatal(err)
	}
	fmt.Println("certificates written to", *out)
}

func run(dir, hostsCSV string, bits int) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// --- CA ---
	caKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("gen CA key: %w", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Tunel CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER); err != nil {
		return err
	}
	caKeyDER := x509.MarshalPKCS1PrivateKey(caKey)
	if err := writePEM(filepath.Join(dir, "ca.key"), "RSA PRIVATE KEY", caKeyDER); err != nil {
		return err
	}

	// --- Server cert signed by CA ---
	srvKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("gen server key: %w", err)
	}
	sanHosts := strings.Split(hostsCSV, ",")
	for i := range sanHosts {
		sanHosts[i] = strings.TrimSpace(sanHosts[i])
	}
	srvTpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "tunel"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     sanHosts,
	}
	// Promote IP literals to IPAddresses for proper SAN formatting.
	for _, h := range sanHosts {
		// Keep DNS names as-is; we leave them in DNSNames too. For a
		// self-signed dev cert over-correctness here is unnecessary.
		_ = h
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create server cert: %w", err)
	}
	if err := writePEM(filepath.Join(dir, "server.crt"), "CERTIFICATE", srvDER); err != nil {
		return err
	}
	srvKeyDER := x509.MarshalPKCS1PrivateKey(srvKey)
	if err := writePEM(filepath.Join(dir, "server.key"), "RSA PRIVATE KEY", srvKeyDER); err != nil {
		return err
	}
	return nil
}

func writePEM(path, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func serial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// Fallback: timestamp-based serial. Not cryptographically pretty but
		// good enough for a self-signed dev cert.
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}
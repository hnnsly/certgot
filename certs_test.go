package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/registration"
)

func TestValidateConfig(t *testing.T) {
	valid := &Config{
		Email:       "admin@example.com",
		StoragePath: "/var/lib/certgot",
		Certificates: []CertConfig{{
			Domain:      "example.com",
			Provider:    "cloudflare",
			Permissions: "0640",
		}},
	}

	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "valid", cfg: *valid},
		{name: "missing email", cfg: Config{StoragePath: valid.StoragePath, Certificates: valid.Certificates}, want: "email is required"},
		{name: "missing storage", cfg: Config{Email: valid.Email, Certificates: valid.Certificates}, want: "storage_path is required"},
		{name: "missing certificates", cfg: Config{Email: valid.Email, StoragePath: valid.StoragePath}, want: "at least one certificate is required"},
		{name: "missing domain", cfg: Config{Email: valid.Email, StoragePath: valid.StoragePath, Certificates: []CertConfig{{Provider: "cloudflare"}}}, want: "certificates[0].domain is required"},
		{name: "missing provider", cfg: Config{Email: valid.Email, StoragePath: valid.StoragePath, Certificates: []CertConfig{{Domain: "example.com"}}}, want: "certificates[0].provider is required"},
		{name: "duplicate domain", cfg: Config{Email: valid.Email, StoragePath: valid.StoragePath, Certificates: []CertConfig{{Domain: "example.com", Provider: "cloudflare"}, {Domain: "example.com", Provider: "route53"}}}, want: "duplicate certificate domain"},
		{name: "bad permissions", cfg: Config{Email: valid.Email, StoragePath: valid.StoragePath, Certificates: []CertConfig{{Domain: "example.com", Provider: "cloudflare", Permissions: "bad"}}}, want: "permissions must be octal"},
		{name: "too broad permissions", cfg: Config{Email: valid.Email, StoragePath: valid.StoragePath, Certificates: []CertConfig{{Domain: "example.com", Provider: "cloudflare", Permissions: "1777"}}}, want: "permissions must not exceed 0777"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.cfg)
			if tt.want == "" && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tt.want != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.want)
				}
				if !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("expected error containing %q, got %v", tt.want, err)
				}
			}
		})
	}
}

func TestLoadConfigExample(t *testing.T) {
	cfg, err := loadConfig("config-example.yml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Email == "" || len(cfg.Certificates) == 0 {
		t.Fatalf("expected populated example config, got %#v", cfg)
	}
}

func TestCheckCertFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	notAfter := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}

	days, expiry, ok := checkCertFile(certPath)
	if !ok {
		t.Fatal("expected cert file to parse")
	}
	if days < 2 || days > 3 {
		t.Fatalf("expected about 3 days left, got %d", days)
	}
	if !expiry.Equal(notAfter) {
		t.Fatalf("expected expiry %s, got %s", notAfter, expiry)
	}

	if err := os.WriteFile(certPath, []byte("not pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := checkCertFile(certPath); ok {
		t.Fatal("expected malformed PEM to fail")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.txt")
	if err := writeFileAtomic(path, []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected content hello, got %q", string(data))
	}

	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0640 {
		t.Fatalf("expected mode 0640, got %o", stat.Mode().Perm())
	}
}

func TestDirectoryModeFromFileMode(t *testing.T) {
	tests := []struct {
		name string
		file os.FileMode
		dir  os.FileMode
	}{
		{name: "owner group read", file: 0640, dir: 0750},
		{name: "owner only", file: 0600, dir: 0700},
		{name: "world readable", file: 0644, dir: 0755},
		{name: "preserves execute", file: 0750, dir: 0750},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := directoryModeFromFileMode(tt.file); got != tt.dir {
				t.Fatalf("expected %o, got %o", tt.dir, got)
			}
		})
	}
}

func TestSaveToDiskUsesExecutableDirectoryPermissions(t *testing.T) {
	dir := t.TempDir()
	certs := &certificate.Resource{
		Certificate:       []byte("certificate"),
		IssuerCertificate: []byte("issuer"),
		PrivateKey:        []byte("key"),
	}

	if err := saveToDisk(dir, certs, CertConfig{Permissions: "0640"}); err != nil {
		t.Fatal(err)
	}

	stat, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0750 {
		t.Fatalf("expected directory mode 0750, got %o", stat.Mode().Perm())
	}

	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		stat, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if stat.Mode().Perm() != 0640 {
			t.Fatalf("expected %s mode 0640, got %o", name, stat.Mode().Perm())
		}
	}
}

func TestRegistrationPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.registration.json")
	reg := &registration.Resource{
		URI: "https://acme.example/acct/1",
		Body: acme.Account{
			Status:  "valid",
			Contact: []string{"mailto:admin@example.com"},
		},
	}

	if err := saveRegistration(path, reg); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadRegistration(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("expected registration")
	}
	if loaded.URI != reg.URI || loaded.Body.Status != reg.Body.Status || loaded.Body.Contact[0] != reg.Body.Contact[0] {
		t.Fatalf("loaded registration mismatch: %#v", loaded)
	}

	missing, err := loadRegistration(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if missing != nil {
		t.Fatalf("expected nil missing registration, got %#v", missing)
	}
}

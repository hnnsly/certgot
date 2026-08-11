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
		{name: "invalid group", cfg: Config{Email: valid.Email, StoragePath: valid.StoragePath, Certificates: []CertConfig{{Domain: "example.com", Provider: "cloudflare", Group: "www data"}}}, want: "group is invalid"},
		{name: "invalid reload unit", cfg: Config{Email: valid.Email, StoragePath: valid.StoragePath, Certificates: []CertConfig{{Domain: "example.com", Provider: "cloudflare", ReloadUnits: []string{"../nginx.service"}}}}, want: "reload_units"},
		{name: "duplicate reload unit", cfg: Config{Email: valid.Email, StoragePath: valid.StoragePath, Certificates: []CertConfig{{Domain: "example.com", Provider: "cloudflare", ReloadUnits: []string{"nginx.service", " nginx.service "}}}}, want: "duplicate unit"},
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

func TestValidateConfigNormalizesGroupAndReloadUnits(t *testing.T) {
	cfg := Config{
		Email:       "admin@example.com",
		StoragePath: t.TempDir(),
		Certificates: []CertConfig{{
			Domain: "example.com", Provider: "cloudflare", Group: " www-data ", ReloadUnits: []string{" nginx.service "},
		}},
	}
	if err := validateConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Certificates[0].Group != "www-data" || cfg.Certificates[0].ReloadUnits[0] != "nginx.service" {
		t.Fatalf("config was not normalized: %#v", cfg.Certificates[0])
	}
}

func TestValidateConfigNormalizesAndRejectsDomains(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		want      string
		wantError bool
	}{
		{name: "lowercase", raw: "example.com", want: "example.com"},
		{name: "case and fqdn dot", raw: " EXAMPLE.COM. ", want: "example.com"},
		{name: "parent traversal", raw: "../../etc", wantError: true},
		{name: "absolute path", raw: "/etc", wantError: true},
		{name: "slash", raw: "example.com/foo", wantError: true},
		{name: "wildcard", raw: "*.example.com", wantError: true},
		{name: "empty label", raw: "a..example.com", wantError: true},
		{name: "long label", raw: strings.Repeat("a", 64) + ".example.com", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Email:        "admin@example.com",
				StoragePath:  t.TempDir(),
				Certificates: []CertConfig{{Domain: tt.raw, Provider: "cloudflare"}},
			}
			err := validateConfig(&cfg)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected validation error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Certificates[0].Domain; got != tt.want {
				t.Fatalf("expected normalized domain %q, got %q", tt.want, got)
			}
		})
	}

	duplicate := Config{
		Email:       "admin@example.com",
		StoragePath: t.TempDir(),
		Certificates: []CertConfig{
			{Domain: "example.com", Provider: "cloudflare"},
			{Domain: "EXAMPLE.COM.", Provider: "cloudflare"},
		},
	}
	if err := validateConfig(&duplicate); err == nil {
		t.Fatal("expected normalized duplicate error")
	}
}

func TestWithEnvironmentRestoresPreviousValues(t *testing.T) {
	const existingKey = "CERTGOT_TEST_EXISTING_ENV"
	const newKey = "CERTGOT_TEST_NEW_ENV"
	t.Setenv(existingKey, "before")
	_ = os.Unsetenv(newKey)

	err := withEnvironment(map[string]string{existingKey: "during", newKey: "created"}, func() error {
		if got := os.Getenv(existingKey); got != "during" {
			t.Fatalf("expected temporary existing value, got %q", got)
		}
		if got := os.Getenv(newKey); got != "created" {
			t.Fatalf("expected temporary new value, got %q", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv(existingKey); got != "before" {
		t.Fatalf("expected existing value restored, got %q", got)
	}
	if _, exists := os.LookupEnv(newKey); exists {
		t.Fatal("expected new environment value removed")
	}
}

func TestWithEnvironmentRejectsInvalidName(t *testing.T) {
	if err := withEnvironment(map[string]string{"BAD=NAME": "value"}, func() error { return nil }); err == nil {
		t.Fatal("expected invalid environment name error")
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

func TestCheckCertificatePairValidatesSANAndKey(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		DNSNames:     []string{"example.com", "*.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(60 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	resource := &certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	if err := saveToDisk(dir, resource, CertConfig{}); err != nil {
		t.Fatal(err)
	}
	check := checkCertificatePair(dir, "example.com")
	if check.status != certificateValid {
		t.Fatalf("expected valid pair, got %s", check.status)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalECPrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "current", "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if check := checkCertificatePair(dir, "example.com"); check.status != certificateKeyMismatch {
		t.Fatalf("expected key mismatch, got %s", check.status)
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
	certs := newTestCertificateResource(t, "example.com")

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

func TestSaveToDiskKeepsCurrentReleaseOnInvalidResource(t *testing.T) {
	dir := t.TempDir()
	valid := newTestCertificateResource(t, "example.com")
	if err := saveToDisk(dir, valid, CertConfig{Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	currentBefore, err := filepath.EvalSymlinks(filepath.Join(dir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	invalid := &certificate.Resource{Certificate: []byte("not a certificate"), PrivateKey: []byte("not a key")}
	if err := saveToDisk(dir, invalid, CertConfig{Domain: "example.com"}); err == nil {
		t.Fatal("expected invalid resource to fail")
	}
	currentAfter, err := filepath.EvalSymlinks(filepath.Join(dir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if currentAfter != currentBefore {
		t.Fatalf("current release changed after failed publish: %s -> %s", currentBefore, currentAfter)
	}
	if check := checkCertificatePair(dir, "example.com"); check.status != certificateValid {
		t.Fatalf("previous release is no longer valid: %s", check.status)
	}
}

func newTestCertificateResource(t *testing.T, domain string) *certificate.Resource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		DNSNames:     []string{domain, "*." + domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(60 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &certificate.Resource{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
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

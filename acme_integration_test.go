//go:build integration

package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"gopkg.in/yaml.v3"
)

const pebbleDirectoryURLEnv = "CERTGOT_PEBBLE_DIRECTORY_URL"

type pebbleDNSProvider struct {
	presented int
	cleaned   int
}

func (provider *pebbleDNSProvider) Present(_, _, _ string) error {
	provider.presented++
	return nil
}

func (provider *pebbleDNSProvider) CleanUp(_, _, _ string) error {
	provider.cleaned++
	return nil
}

type pebbleCertificateIssuer struct {
	client   *lego.Client
	provider *pebbleDNSProvider
}

func (issuer *pebbleCertificateIssuer) Process(cfg CertConfig, certDir string, force bool, renewalWindow time.Duration) CheckResult {
	return processDomainWithProviderFactory(issuer.client, cfg, certDir, force, renewalWindow, func(CertConfig) (DNSProviderConfig, error) {
		return DNSProviderConfig{
			Provider: issuer.provider,
			Options:  []dns01.ChallengeOption{dns01.PropagationWait(0, true)},
		}, nil
	})
}

func newPebbleCertificateIssuer(directoryURL string, provider *pebbleDNSProvider) CertificateIssuerFactory {
	return func(user *MyUser, _ ACMEOptions) (CertificateIssuer, error) {
		config := lego.NewConfig(user)
		config.CADirURL = directoryURL
		config.Certificate.KeyType = certcrypto.EC256
		config.Certificate.Timeout = 20 * time.Second
		config.HTTPClient = &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				// #nosec G402 -- Pebble creates a local ephemeral test CA.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		client, err := lego.NewClient(config)
		if err != nil {
			return nil, err
		}
		if user.Registration == nil {
			registrationResource, registerErr := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
			if registerErr != nil {
				return nil, registerErr
			}
			user.Registration = registrationResource
		}
		return &pebbleCertificateIssuer{client: client, provider: provider}, nil
	}
}

func TestPebbleDNS01Workflow(t *testing.T) {
	directoryURL := os.Getenv(pebbleDirectoryURLEnv)
	if directoryURL == "" {
		t.Skipf("set %s after starting the local Pebble test CA", pebbleDirectoryURLEnv)
	}

	// macOS exposes its default test temp directory through /var, a symlink to
	// /private/var. Production storage rejects symlink components deliberately,
	// so keep this integration fixture under the same non-symlinked temp root
	// used by the test command caches.
	root, err := os.MkdirTemp("/private/tmp", "certgot-pebble-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	storagePath := filepath.Join(root, "state")
	configPath := filepath.Join(root, "config.yml")
	configData, err := yaml.Marshal(Config{
		Email:       "integration@example.com",
		StoragePath: storagePath,
		// Pebble can issue its short-lived six-day profile during a forced renewal.
		// Keep the test focused on ACME, atomic publication, and renewal mechanics.
		RenewBefore: "1h",
		Certificates: []CertConfig{{
			Domain:      "example.com",
			Provider:    "integration",
			Permissions: "0640",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatal(err)
	}

	provider := &pebbleDNSProvider{}
	deps := defaultApplicationDependencies()
	deps.NewIssuer = newPebbleCertificateIssuer(directoryURL, provider)
	deps.Notifier = discardNotifier{}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	var firstRun bytes.Buffer
	if err := runAppWithDependencies(configPath, RunOptions{Render: RenderOptions{Format: OutputJSON}}, &firstRun, logger, deps); err != nil {
		t.Fatalf("initial Pebble issuance: %v", err)
	}
	if provider.presented == 0 || provider.cleaned == 0 {
		t.Fatalf("DNS provider was not used: present=%d cleanup=%d", provider.presented, provider.cleaned)
	}

	var statusOutput bytes.Buffer
	if err := runStatus(configPath, "example.com", RenderOptions{Format: OutputJSON}, &statusOutput); err != nil {
		t.Fatalf("status after issue: %v\n%s", err, statusOutput.String())
	}
	if !bytes.Contains(statusOutput.Bytes(), []byte(`"status": "valid"`)) {
		t.Fatalf("status does not report a valid certificate: %s", statusOutput.String())
	}

	var renewRun bytes.Buffer
	if err := runAppWithDependencies(configPath, RunOptions{
		Render:    RenderOptions{Format: OutputJSON},
		Domains:   []string{"example.com"},
		Force:     true,
		Operation: "renew",
	}, &renewRun, logger, deps); err != nil {
		t.Fatalf("forced Pebble renewal: %v", err)
	}
	releases, err := os.ReadDir(filepath.Join(storagePath, "certs", "example.com", "releases"))
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) < 2 {
		t.Fatalf("expected two atomically published releases, got %d", len(releases))
	}
}

type discardNotifier struct{}

func (discardNotifier) Notify(string, []CheckResult, string, time.Duration) error { return nil }

var _ challenge.Provider = (*pebbleDNSProvider)(nil)

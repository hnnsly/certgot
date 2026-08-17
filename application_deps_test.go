package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeClock struct {
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.now = clock.now.Add(time.Second)
	return clock.now
}

type fakeCertificateStore struct {
	root string
	seen *[]StateNamespace
}

func (store fakeCertificateStore) Prepare(_ string, namespace StateNamespace) (string, string, error) {
	if store.seen != nil {
		*store.seen = append(*store.seen, namespace)
	}
	certDir := filepath.Join(store.root, "certs")
	accountDir := filepath.Join(store.root, "accounts")
	if namespace.Key != "" {
		certDir = filepath.Join(store.root, "certs-"+namespace.Key)
		accountDir = filepath.Join(store.root, "accounts", namespace.Key)
	}
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return "", "", err
	}
	return certDir, accountDir, nil
}

func (fakeCertificateStore) Lock(string) (io.Closer, error) {
	return nopCloser{}, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type fakeIssuer struct {
	processed []CertConfig
	dirs      []string
}

func (issuer *fakeIssuer) Process(cfg CertConfig, certDir string, _ bool, _ time.Duration) CheckResult {
	issuer.processed = append(issuer.processed, cfg)
	issuer.dirs = append(issuer.dirs, certDir)
	if err := os.MkdirAll(filepath.Join(certDir, cfg.Domain), 0755); err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}
	return CheckResult{Type: ResultSuccess, Domain: cfg.Domain, DaysLeft: 75, Until: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func TestStagingRunUsesIsolatedStateAndSkipsReload(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yml")
	config := `email: admin@example.com
storage_path: ./state
certificates:
  - domain: example.com
    provider: cloudflare
    reload_units: [nginx.service]
`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	storeRoot := filepath.Join(root, "store")
	productionAccountDir := filepath.Join(storeRoot, "accounts")
	if err := os.MkdirAll(productionAccountDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(productionAccountDir, "account.key"), []byte("corrupt production key"), 0600); err != nil {
		t.Fatal(err)
	}
	productionCurrent := filepath.Join(storeRoot, "certs", "example.com", "current")
	if err := os.MkdirAll(filepath.Dir(productionCurrent), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(productionCurrent, []byte("production"), 0600); err != nil {
		t.Fatal(err)
	}

	issuer := &fakeIssuer{}
	var namespaces []StateNamespace
	reloadCalled := false
	dependencies := ApplicationDependencies{
		Clock: &fakeClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
		Store: fakeCertificateStore{root: storeRoot, seen: &namespaces},
		NewIssuer: func(user *MyUser, options ACMEOptions) (CertificateIssuer, error) {
			if user.Registration != nil {
				t.Fatal("staging issuer received production registration")
			}
			if !options.Staging {
				t.Fatal("staging option not passed")
			}
			return issuer, nil
		},
		Notifier: &fakeNotifier{},
		NewServiceManager: func() (ServiceManager, error) {
			reloadCalled = true
			return recordingServiceManager{}, nil
		},
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	var output bytes.Buffer
	if err := runAppWithDependencies(configPath, RunOptions{Staging: true, Force: true, Operation: "renew", Render: RenderOptions{Format: OutputJSON}}, &output, logger, dependencies); err != nil {
		t.Fatal(err)
	}
	if reloadCalled {
		t.Fatal("staging run called reload manager")
	}
	if len(namespaces) != 1 || namespaces[0].Key != "staging" || namespaces[0].Mode != "staging" {
		t.Fatalf("namespaces = %#v", namespaces)
	}
	if len(issuer.dirs) != 1 || issuer.dirs[0] != filepath.Join(storeRoot, "certs-staging") {
		t.Fatalf("issuer directories = %#v", issuer.dirs)
	}
	if !strings.Contains(output.String(), `"mode": "staging"`) {
		t.Fatalf("staging mode missing: %s", output.String())
	}
	data, err := os.ReadFile(productionCurrent)
	if err != nil || string(data) != "production" {
		t.Fatalf("production current changed: %q, %v", data, err)
	}
	stagingKey := filepath.Join(storeRoot, "accounts", "staging", "account.key")
	firstKey, err := os.ReadFile(stagingKey)
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := runAppWithDependencies(configPath, RunOptions{Staging: true, Force: true, Operation: "renew", Render: RenderOptions{Format: OutputJSON}}, &output, logger, dependencies); err != nil {
		t.Fatal(err)
	}
	secondKey, err := os.ReadFile(stagingKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstKey, secondKey) {
		t.Fatal("staging account key was not reused")
	}
}

func TestCustomDirectoryNamespaceIsStableAndIsolated(t *testing.T) {
	first := stateNamespace(ACMEOptions{DirectoryURL: "https://ca.example/dir"})
	second := stateNamespace(ACMEOptions{DirectoryURL: "https://ca.example/dir"})
	other := stateNamespace(ACMEOptions{DirectoryURL: "https://other.example/dir"})
	if first.Mode != "custom" || first.Key == "" || first != second || first == other {
		t.Fatalf("unexpected namespaces: %#v %#v %#v", first, second, other)
	}
}

func TestValidateACMEOptionsRejectsStagingWithCustomDirectory(t *testing.T) {
	err := validateACMEOptions(ACMEOptions{Staging: true, DirectoryURL: "https://ca.example/dir"})
	if err == nil || !strings.Contains(err.Error(), "--staging cannot be used with acme_directory_url") {
		t.Fatalf("expected conflicting ACME mode error, got %v", err)
	}
	for _, options := range []ACMEOptions{{Staging: true}, {DirectoryURL: "https://ca.example/dir"}, {}} {
		if err := validateACMEOptions(options); err != nil {
			t.Fatalf("valid options %#v rejected: %v", options, err)
		}
	}
}

type fakeNotifier struct {
	called bool
}

func (notifier *fakeNotifier) Notify(_ TelegramConfig, _ []CheckResult, _ string, _ time.Duration) error {
	notifier.called = true
	return nil
}

type recordingServiceManager struct {
	units *[]string
}

func (manager recordingServiceManager) Reload(unit string) error {
	*manager.units = append(*manager.units, unit)
	return nil
}

func TestRunAppWithDependenciesAvoidsExternalAdapters(t *testing.T) {
	root := testSafeTempDir(t)
	t.Setenv("TELEGRAM_BOT_TOKEN", "token")
	configPath := filepath.Join(root, "config.yml")
	config := `email: admin@example.com
storage_path: ./state
notifications:
  on: [always]
  telegram:
    bot_token: ${TELEGRAM_BOT_TOKEN}
    chat_id: 1
certificates:
  - domain: example.com
    provider: cloudflare
    reload_units: [nginx.service]
`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	issuer := &fakeIssuer{}
	notifier := &fakeNotifier{}
	var reloaded []string
	dependencies := ApplicationDependencies{
		Clock:     &fakeClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
		Store:     fakeCertificateStore{root: filepath.Join(root, "store")},
		NewIssuer: func(*MyUser, ACMEOptions) (CertificateIssuer, error) { return issuer, nil },
		Notifier:  notifier,
		NewServiceManager: func() (ServiceManager, error) {
			return recordingServiceManager{units: &reloaded}, nil
		},
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	err := runAppWithDependencies(configPath, RunOptions{Render: RenderOptions{Format: OutputJSON}}, &output, logger, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if len(issuer.processed) != 1 || issuer.processed[0].Domain != "example.com" {
		t.Fatalf("issuer processed %#v", issuer.processed)
	}
	if !notifier.called {
		t.Fatal("notifier was not called")
	}
	if got := strings.Join(reloaded, ","); got != "nginx.service" {
		t.Fatalf("reloaded units = %q", got)
	}
	if !strings.Contains(output.String(), `"status": "renewed"`) {
		t.Fatalf("unexpected output: %s", output.String())
	}
	if !strings.Contains(output.String(), `"status": "reloaded"`) {
		t.Fatalf("reload result missing from output: %s", output.String())
	}
}

func testSafeTempDir(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if runtime.GOOS == "darwin" {
		base = "/private/tmp"
	}
	root, err := os.MkdirTemp(base, "certgot-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

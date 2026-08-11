package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorUsesConfiguredACMEDirectory(t *testing.T) {
	var requestedURL string
	var requestedMethod string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestedURL = request.URL.String()
		requestedMethod = request.Method
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})}
	check := checkACMEDirectoryWithClient("https://pebble.example.test/dir", client)
	if check.Status != "ok" {
		t.Fatalf("unexpected ACME check: %#v", check)
	}
	if requestedURL != "https://pebble.example.test/dir" {
		t.Fatalf("doctor requested %q", requestedURL)
	}
	if requestedMethod != http.MethodGet {
		t.Fatalf("doctor used %s, want GET", requestedMethod)
	}
}

func TestDoctorRejectsACMEDirectory4xx(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("not found"))}, nil
	})}
	check := checkACMEDirectoryWithClient("https://ca.example/dir", client)
	if check.Status == "ok" {
		t.Fatalf("4xx was treated as reachable: %#v", check)
	}
}

func TestNotificationsOnValidation(t *testing.T) {
	cfg := &Config{Email: "admin@example.com", StoragePath: "/tmp/state", Notifications: &NotificationConfig{On: []string{"Renewed", "error"}}, Certificates: []CertConfig{{Domain: "example.com", Provider: "cloudflare"}}}
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.Notifications.On, ",") != "renewed,error" {
		t.Fatalf("events not normalized: %#v", cfg.Notifications.On)
	}
	for _, events := range [][]string{{"typo"}, {"error", "ERROR"}} {
		copyCfg := *cfg
		copyCfg.Notifications = &NotificationConfig{On: append([]string(nil), events...)}
		if err := validateConfig(&copyCfg); err == nil {
			t.Fatalf("expected invalid events %#v", events)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestDoctorReportsMissingProviderCredentialsAsError(t *testing.T) {
	check := checkProviderCredentials(CertConfig{Domain: "example.com", Provider: "cloudflare"})
	if check.Status != "error" || !strings.Contains(check.Message, "missing") {
		t.Fatalf("unexpected credential check: %#v", check)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	data := `email: admin@example.com
storage_path: ./state
unknown_field: true
certificates:
  - domain: example.com
    provider: cloudflare
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "unknown_field") {
		t.Fatalf("expected strict YAML error, got %v", err)
	}
}

func TestIsManagedMode(t *testing.T) {
	if !isManagedMode(managedConfigPath, &Config{StoragePath: "/tmp/state"}) {
		t.Fatal("managed config path was not detected")
	}
	if !isManagedMode("./config.yml", &Config{StoragePath: managedStoragePath}) {
		t.Fatal("managed storage path was not detected")
	}
	if isManagedMode("./config.yml", &Config{StoragePath: "/tmp/state"}) {
		t.Fatal("manual config was detected as managed")
	}
}

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseSetupInterval(t *testing.T) {
	tests := []struct {
		raw          string
		wantDays     int
		wantInterval string
		wantErr      bool
	}{
		{raw: "1d", wantDays: 1, wantInterval: "1d"},
		{raw: "2w", wantDays: 14, wantInterval: "14d"},
		{raw: "1m", wantDays: 30, wantInterval: "30d"},
		{raw: "", wantErr: true},
		{raw: "0d", wantErr: true},
		{raw: "1y", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			gotDays, gotInterval, err := parseSetupInterval(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if gotDays != tt.wantDays || gotInterval != tt.wantInterval {
				t.Fatalf("expected (%d, %q), got (%d, %q)", tt.wantDays, tt.wantInterval, gotDays, gotInterval)
			}
		})
	}
}

func TestNonInteractiveSetupValidation(t *testing.T) {
	tests := []struct {
		name           string
		nonInteractive bool
		interval       string
		euid           int
		wantError      string
	}{
		{name: "missing interval", nonInteractive: true, euid: 0, wantError: "requires --setup-interval"},
		{name: "not root", nonInteractive: true, interval: "2w", euid: 1000, wantError: "requires root"},
		{name: "root", nonInteractive: true, interval: "2w", euid: 0},
		{name: "interactive", interval: "", euid: 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSetupMode(tt.nonInteractive, tt.interval, tt.euid)
			if tt.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("expected %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestNonInteractiveSetupDoesNotReadStdin(t *testing.T) {
	input, interval, err := resolveSetupInterval(nil, "2w", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if input != "2w" || interval != "14d" {
		t.Fatalf("unexpected interval: input=%q duration=%q", input, interval)
	}
}

func TestInteractiveSetupStillPromptsForInterval(t *testing.T) {
	input, interval, err := resolveSetupInterval(bufio.NewReader(strings.NewReader("2w\n")), "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if input != "2w" || interval != "14d" {
		t.Fatalf("unexpected interval: input=%q duration=%q", input, interval)
	}
}

func TestServiceTemplateHardening(t *testing.T) {
	for _, fragment := range []string{
		"User=certgot",
		"Group=certgot",
		"NoNewPrivileges=true",
		"PrivateTmp=true",
		"ProtectSystem=strict",
		"ProtectHome=true",
		"ReadWritePaths=/var/lib/certgot",
	} {
		if !strings.Contains(serviceTpl, fragment) {
			t.Fatalf("service template missing %q", fragment)
		}
	}
}

func TestPrepareManagedConfigMigratesSecrets(t *testing.T) {
	root := t.TempDir()
	relativeEnv := filepath.Join(root, "relative.env")
	absoluteEnv := filepath.Join(root, "absolute.env")
	if err := os.WriteFile(relativeEnv, []byte("TOKEN=relative\nSHARED=file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absoluteEnv, []byte("TOKEN=absolute\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.yml")
	configText := fmt.Sprintf("email: admin@example.com\nstorage_path: ./state\ncertificates:\n  - domain: relative.example.com\n    provider: cloudflare\n    env_file: ./relative.env\n    env:\n      SHARED: inline\n  - domain: absolute.example.com\n    provider: cloudflare\n    env_file: %s\n  - domain: inline.example.com\n    provider: cloudflare\n    env:\n      TOKEN: inline\n", absoluteEnv)
	if err := os.WriteFile(configPath, []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}

	written := map[string]map[string]string{}
	installed, err := prepareManagedConfig(cfg, "/etc/certgot/secrets", 123, func(path string, values map[string]string, gid int) error {
		if gid != 123 {
			t.Fatalf("unexpected gid %d", gid)
		}
		written[path] = values
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if installed.StoragePath != managedStoragePath {
		t.Fatalf("storage path = %q", installed.StoragePath)
	}
	for index, cert := range installed.Certificates {
		wantPath := filepath.Join(managedSecretsDir, fmt.Sprintf("%02d-%s.env", index, cert.Domain))
		if cert.EnvFile != wantPath || len(cert.Env) != 0 {
			t.Fatalf("certificate %d was not migrated: %+v", index, cert)
		}
	}
	if got := written[installed.Certificates[0].EnvFile]["SHARED"]; got != "inline" {
		t.Fatalf("inline env must override env_file, got %q", got)
	}
	if cfg.Certificates[0].EnvFile != relativeEnv || cfg.Certificates[0].Env["SHARED"] != "inline" {
		t.Fatal("source config was mutated")
	}
	data, err := yaml.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{"relative", "absolute", "inline"} {
		if strings.Contains(text, "TOKEN: "+secret) {
			t.Fatalf("installed YAML contains secret %q: %s", secret, text)
		}
	}
	if strings.Contains(text, root) {
		t.Fatalf("installed YAML references source directory: %s", text)
	}
}

func TestPrepareManagedConfigMissingEnvFile(t *testing.T) {
	cfg := &Config{Certificates: []CertConfig{{Domain: "example.com", EnvFile: filepath.Join(t.TempDir(), "missing.env")}}}
	_, err := prepareManagedConfig(cfg, managedSecretsDir, 1, func(string, map[string]string, int) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "load env_file") {
		t.Fatalf("expected env_file error, got %v", err)
	}
}

func TestConfiguredConsumerGroups(t *testing.T) {
	cfg := &Config{Certificates: []CertConfig{
		{Group: "www-data"},
		{Group: ""},
		{Group: "nginx"},
		{Group: "www-data"},
	}}
	lookup := func(name string) (*user.Group, error) { return &user.Group{Name: name}, nil }
	groups, err := configuredConsumerGroups(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(groups, " "); got != "nginx www-data" {
		t.Fatalf("groups = %q", got)
	}
	service, err := renderTpl(serviceTpl, map[string]string{
		"BinPath": managedBinaryPath, "ConfigPath": managedConfigPath, "SupplementaryGroups": strings.Join(groups, " "),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(service, "SupplementaryGroups=nginx www-data") {
		t.Fatalf("service missing groups: %s", service)
	}
}

func TestConfiguredConsumerGroupsSkipsPrimaryManagedGroup(t *testing.T) {
	lookupCalled := false
	groups, err := configuredConsumerGroups(&Config{Certificates: []CertConfig{{Group: managedStorageGroup}}}, func(string) (*user.Group, error) {
		lookupCalled = true
		return nil, fmt.Errorf("not created yet")
	})
	if err != nil {
		t.Fatal(err)
	}
	if lookupCalled || len(groups) != 0 {
		t.Fatalf("managed primary group should not be supplementary: %#v", groups)
	}
}

func TestConfiguredConsumerGroupsRejectsInvalidOrMissing(t *testing.T) {
	tests := []struct {
		name  string
		group string
		found bool
	}{
		{name: "invalid", group: "www data", found: true},
		{name: "missing", group: "missing", found: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lookup := func(name string) (*user.Group, error) {
				if !test.found {
					return nil, fmt.Errorf("not found")
				}
				return &user.Group{Name: name}, nil
			}
			_, err := configuredConsumerGroups(&Config{Certificates: []CertConfig{{Group: test.group}}}, lookup)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestServiceTemplateWithoutConsumerGroups(t *testing.T) {
	service, err := renderTpl(serviceTpl, map[string]string{"BinPath": managedBinaryPath, "ConfigPath": managedConfigPath})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(service, "SupplementaryGroups=") {
		t.Fatalf("unexpected supplementary groups: %s", service)
	}
}

func TestManagedSetupRejectsReloadUnits(t *testing.T) {
	err := validateManagedReloadPolicy(&Config{Certificates: []CertConfig{{Domain: "example.com", ReloadUnits: []string{"nginx.service"}}}})
	if err == nil || !strings.Contains(err.Error(), "disabled in managed mode") {
		t.Fatalf("expected managed reload rejection, got %v", err)
	}
	if err := validateManagedReloadPolicy(&Config{Certificates: []CertConfig{{Domain: "example.com"}}}); err != nil {
		t.Fatal(err)
	}
}

func TestTelegramReferenceRemainsRawAndMovesToManagedEnvironment(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "secret-token")
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yml")
	data := `email: admin@example.com
storage_path: ./state
notifications:
  on: [error]
  telegram:
    bot_token: ${TELEGRAM_BOT_TOKEN}
    chat_id: -100123
    topic_id: 42
certificates:
  - domain: example.com
    provider: cloudflare
`
	if err := os.WriteFile(configPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := telegramConfig(cfg).BotToken; got != "${TELEGRAM_BOT_TOKEN}" {
		t.Fatalf("raw reference was resolved during load: %q", got)
	}
	var telegramValues map[string]string
	installed, err := prepareManagedConfig(cfg, managedSecretsDir, 123, func(path string, values map[string]string, _ int) error {
		if path == managedTelegramEnvPath {
			telegramValues = values
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if telegramValues["TELEGRAM_BOT_TOKEN"] != "secret-token" {
		t.Fatalf("managed Telegram environment not written: %#v", telegramValues)
	}
	marshaled, err := yaml.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(marshaled), "secret-token") || !strings.Contains(string(marshaled), "${TELEGRAM_BOT_TOKEN}") || !strings.Contains(string(marshaled), "chat_id: -100123") {
		t.Fatalf("installed config leaked or lost reference: %s", marshaled)
	}
	service, err := renderTpl(serviceTpl, map[string]string{
		"BinPath": managedBinaryPath, "ConfigPath": managedConfigPath, "EnvironmentFile": managedTelegramEnvPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(service, "EnvironmentFile="+managedTelegramEnvPath) {
		t.Fatalf("service missing Telegram environment: %s", service)
	}
}

func TestTelegramReferenceResolutionAndDoctorMissing(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "token")
	resolved, err := resolveEnvironmentReference("${TELEGRAM_BOT_TOKEN}")
	if err != nil || resolved != "token" {
		t.Fatalf("resolved=%q err=%v", resolved, err)
	}
	if err := os.Unsetenv("TELEGRAM_BOT_TOKEN"); err != nil {
		t.Fatal(err)
	}
	check := checkTelegram(&TelegramConfig{BotToken: "${TELEGRAM_BOT_TOKEN}", ChatID: 123})
	if check.Status != "error" || !strings.Contains(check.Remediation, "TELEGRAM_BOT_TOKEN is not available") {
		t.Fatalf("unexpected doctor check: %#v", check)
	}
	if _, err := resolveEnvironmentReference("${BAD-NAME}"); err == nil {
		t.Fatal("expected invalid reference error")
	}
}

func TestTelegramConfigRejectsPlainBotToken(t *testing.T) {
	cfg := &Config{
		Email: "admin@example.com", StoragePath: "/tmp/state",
		Notifications: &NotificationConfig{Telegram: &TelegramConfig{BotToken: "plain-secret", ChatID: 123}},
		Certificates:  []CertConfig{{Domain: "example.com", Provider: "cloudflare"}},
	}
	err := validateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "must be an environment reference") {
		t.Fatalf("expected plaintext token rejection, got %v", err)
	}
}

func TestSystemdFixturesMatchRuntimeTemplates(t *testing.T) {
	service, err := renderTpl(serviceTpl, map[string]string{
		"BinPath": managedBinaryPath, "ConfigPath": managedConfigPath,
		"SupplementaryGroups": "www-data",
	})
	if err != nil {
		t.Fatal(err)
	}
	timer, err := renderTpl(timerTpl, map[string]string{"Interval": "14d"})
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		filepath.Join(".github", "systemd", "certgot.service"): service,
		filepath.Join(".github", "systemd", "certgot.timer"):   timer,
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("fixture %s drifted\nwant:\n%s\ngot:\n%s", path, want, got)
		}
	}
}

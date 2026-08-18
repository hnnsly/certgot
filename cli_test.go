package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIHelpAndVersionMetadata(t *testing.T) {
	var output bytes.Buffer
	if err := runCLI([]string{"--help"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"certgot run", "certgot doctor", "certgot status", "certgot renew"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("help missing %q", want)
		}
	}
	output.Reset()
	oldVersion, oldCommit, oldBuild := version, commit, buildTime
	version, commit, buildTime = "v0.4.0", "abc1234", "2026-08-11T12:00:00Z"
	t.Cleanup(func() { version, commit, buildTime = oldVersion, oldCommit, oldBuild })
	if err := runCLI([]string{"version"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "commit: abc1234") || !strings.Contains(output.String(), "built: 2026-08-11T12:00:00Z") {
		t.Fatalf("version metadata missing: %s", output.String())
	}
}

func TestCommandHelpIsSpecificAndSuccessful(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "renew", want: "-domain"},
		{command: "doctor", want: "-offline"},
		{command: "status", want: "-domain"},
		{command: "setup", want: "-setup-interval"},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := runCLI([]string{test.command, "--help"}, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			combined := stdout.String() + stderr.String()
			if !strings.Contains(combined, "Usage of "+test.command) || !strings.Contains(combined, test.want) {
				t.Fatalf("unexpected %s help: %s", test.command, combined)
			}
			if strings.Contains(combined, "Legacy aliases:") {
				t.Fatalf("%s returned global help", test.command)
			}
		})
	}
}

func TestParseNonInteractiveSetupFlags(t *testing.T) {
	opts, err := parseSetupOptions([]string{
		"--config", "/etc/certgot/source.yml",
		"--setup-interval", "2w",
		"--non-interactive",
		"--yes",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if opts.configPath != "/etc/certgot/source.yml" || opts.interval != "2w" || !opts.nonInteractive || !opts.yes {
		t.Fatalf("unexpected setup options: %#v", opts)
	}
}

func TestCommonFlagsRejectInvalidLogFormat(t *testing.T) {
	var output bytes.Buffer
	err := runCLI([]string{"status", "--log-format", "binary"}, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "log-format") {
		t.Fatalf("expected invalid log-format error, got %v", err)
	}
}

func TestDoctorAndRenewDryRunUseNoACME(t *testing.T) {
	fixtureDir := t.TempDir()
	configData, err := os.ReadFile("testdata/config.yml")
	if err != nil {
		t.Fatal(err)
	}
	envData, err := os.ReadFile("testdata/cloudflare.env")
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(fixtureDir, "config.yml")
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "cloudflare.env"), envData, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runCLI([]string{"doctor", "--config", configPath, "--offline", "--output", "json"}, &output, &output); err != nil {
		t.Fatalf("doctor should report warnings without failing: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), `"operation": "doctor"`) {
		t.Fatalf("unexpected doctor output: %s", output.String())
	}
	output.Reset()
	if err := runCLI([]string{"renew", "--config", configPath, "--domain", "example.com", "--dry-run", "--output", "json"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"status": "would-renew"`) {
		t.Fatalf("unexpected renew output: %s", output.String())
	}
	output.Reset()
	if err := runCLI([]string{"status", "--config", configPath, "--domain", "example.com", "--output", "json"}, &output, &output); err == nil {
		t.Fatal("status should fail for missing certificate")
	}
	if !strings.Contains(output.String(), `"status": "missing"`) {
		t.Fatalf("unexpected status output: %s", output.String())
	}
}

func TestInitCreatesMinimalConfigWithoutSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	var output bytes.Buffer
	args := []string{
		"init", "--config", path,
		"--email", "admin@example.com",
		"--domain", "example.com",
		"--provider", "cloudflare",
		"--env-file", "./cloudflare.env",
	}
	if err := runCLI(args, &output, &output); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Certificates[0].Env != nil || loaded.Certificates[0].EnvFile == "" {
		t.Fatalf("expected env-file config, got %#v", loaded.Certificates[0])
	}
}

func TestInitCreatesExplicitTelegramConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yml")
	var output bytes.Buffer
	err := runCLI([]string{
		"init", "--config", configPath,
		"--email", "admin@example.com",
		"--domain", "example.com",
		"--provider", "cloudflare",
		"--env-file", "./cloudflare.env",
		"--group", "www-data",
		"--storage-path", "./state",
		"--telegram-bot-token-env", "TELEGRAM_BOT_TOKEN",
		"--telegram-chat-id", "-100123",
		"--telegram-topic-id", "42",
	}, &output, &output)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bot_token: ${TELEGRAM_BOT_TOKEN}", "chat_id: -100123", "topic_id: 42"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("generated config missing %q: %s", want, data)
		}
	}

	err = runInit(initOptions{
		ConfigPath:       filepath.Join(t.TempDir(), "config.yml"),
		Email:            "admin@example.com",
		Domain:           "example.com",
		Provider:         "cloudflare",
		EnvFile:          "./cloudflare.env",
		Group:            "www-data",
		Permissions:      "0640",
		StoragePath:      "./state",
		TelegramTokenEnv: "BAD-NAME",
		TelegramChatID:   1,
	}, strings.NewReader(""), &output)
	if err == nil || !strings.Contains(err.Error(), "environment variable name") {
		t.Fatalf("expected invalid Telegram environment name, got %v", err)
	}
}

func TestDefaultConfigPathHonorsEnvironment(t *testing.T) {
	want := filepath.Join(t.TempDir(), "certgot.yml")
	t.Setenv("CERTGOT_CONFIG", want)
	if got := defaultConfigPath(); got != want {
		t.Fatalf("default config path = %q, want %q", got, want)
	}
}

func TestLegacyTelegramURLIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	data := `email: admin@example.com
storage_path: /tmp/state
telegram_url: telegram://legacy
certificates:
  - domain: example.com
    provider: cloudflare
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "telegram_url") {
		t.Fatalf("expected legacy telegram_url rejection, got %v", err)
	}
}

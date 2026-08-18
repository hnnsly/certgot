package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type initOptions struct {
	ConfigPath       string
	Email            string
	Domain           string
	Provider         string
	EnvFile          string
	Group            string
	Permissions      string
	TelegramTokenEnv string
	TelegramChatID   int64
	TelegramTopicID  int64
	StoragePath      string
	ACMEDirectoryURL string
	Force            bool
}

func initCommandCLI(args []string, in io.Reader, out, stderr io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	opts := initOptions{}
	flags.StringVar(&opts.ConfigPath, "config", defaultConfigPath(), "Path for the new config")
	flags.StringVar(&opts.Email, "email", "", "ACME email")
	flags.StringVar(&opts.Domain, "domain", "", "Base domain")
	flags.StringVar(&opts.Provider, "provider", "", "DNS provider")
	flags.StringVar(&opts.EnvFile, "env-file", "", "Provider env-file path")
	flags.StringVar(&opts.Group, "group", "", "Certificate group")
	flags.StringVar(&opts.Permissions, "permissions", "0640", "Certificate permissions")
	flags.StringVar(&opts.TelegramTokenEnv, "telegram-bot-token-env", "", "Environment variable containing the Telegram bot token")
	flags.Int64Var(&opts.TelegramChatID, "telegram-chat-id", 0, "Telegram chat ID")
	flags.Int64Var(&opts.TelegramTopicID, "telegram-topic-id", 0, "Optional Telegram topic ID")
	flags.StringVar(&opts.StoragePath, "storage-path", defaultStoragePath(), "Certificate state path")
	flags.StringVar(&opts.ACMEDirectoryURL, "acme-directory-url", "", "Optional ACME directory URL for local testing")
	flags.BoolVar(&opts.Force, "force", false, "Overwrite an existing config")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	return runInit(opts, in, out)
}

func runInit(opts initOptions, in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)
	var err error
	if opts.Email == "" {
		opts.Email, err = promptValue(reader, out, "ACME email: ")
		if err != nil {
			return err
		}
	}
	if opts.Domain == "" {
		opts.Domain, err = promptValue(reader, out, "Domain: ")
		if err != nil {
			return err
		}
	}
	if opts.Provider == "" {
		opts.Provider, err = promptValue(reader, out, "DNS provider: ")
		if err != nil {
			return err
		}
	}
	if opts.EnvFile == "" {
		opts.EnvFile, err = promptValue(reader, out, "Provider env-file path (optional): ")
		if err != nil {
			return err
		}
	}
	if opts.Group == "" {
		opts.Group, err = promptValue(reader, out, "Certificate group (optional): ")
		if err != nil {
			return err
		}
	}
	normalizedDomain, err := normalizeDomain(opts.Domain)
	if err != nil {
		return err
	}
	if _, err := os.Stat(opts.ConfigPath); err == nil && !opts.Force {
		return fmt.Errorf("config %s already exists; use --force to replace it", opts.ConfigPath)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	cfg := Config{
		Email:            strings.TrimSpace(opts.Email),
		StoragePath:      opts.StoragePath,
		ACMEDirectoryURL: strings.TrimSpace(opts.ACMEDirectoryURL),
		Certificates: []CertConfig{{
			Domain:      normalizedDomain,
			Provider:    strings.TrimSpace(opts.Provider),
			EnvFile:     strings.TrimSpace(opts.EnvFile),
			Permissions: opts.Permissions,
			Group:       strings.TrimSpace(opts.Group),
		}},
	}
	telegramEnv := strings.TrimSpace(opts.TelegramTokenEnv)
	if telegramEnv != "" || opts.TelegramChatID != 0 || opts.TelegramTopicID != 0 {
		if !validEnvironmentName(telegramEnv) {
			return fmt.Errorf("--telegram-bot-token-env must be a valid environment variable name")
		}
		if opts.TelegramChatID == 0 {
			return fmt.Errorf("--telegram-chat-id is required when Telegram is configured")
		}
		cfg.Notifications = &NotificationConfig{
			On: []string{"renewed", "error"},
			Telegram: &TelegramConfig{
				BotToken: "${" + telegramEnv + "}",
				ChatID:   opts.TelegramChatID,
				TopicID:  opts.TelegramTopicID,
			},
		}
	}
	if err := validateConfig(&cfg); err != nil {
		return err
	}
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opts.ConfigPath), 0700); err != nil {
		return err
	}
	if err := writeFileAtomic(opts.ConfigPath, data, 0600); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Created %s\n\nNext:\n  certgot doctor --config %s\n  sudo certgot setup --config %s --setup-interval 2w --yes\n", opts.ConfigPath, opts.ConfigPath, opts.ConfigPath); err != nil {
		return err
	}
	return nil
}

func promptValue(reader *bufio.Reader, out io.Writer, prompt string) (string, error) {
	if _, err := io.WriteString(out, prompt); err != nil {
		return "", err
	}
	value, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

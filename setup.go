package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	internalstorage "github.com/hnnsly/certgot/internal/storage"
	"gopkg.in/yaml.v3"
)

const serviceTpl = `[Unit]
Description=ACME DNS certgot
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart={{.BinPath}} --config {{.ConfigPath}}
User=certgot
Group=certgot
{{if .SupplementaryGroups}}SupplementaryGroups={{.SupplementaryGroups}}
{{end}}{{if .EnvironmentFile}}EnvironmentFile={{.EnvironmentFile}}
{{end}}UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/certgot
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
`

const timerTpl = `[Unit]
Description=ACME DNS certgot interval timer

[Timer]
OnBootSec=5m
OnUnitActiveSec={{.Interval}}
Persistent=true
Unit=certgot.service

[Install]
WantedBy=timers.target
`

func runSystemdWizard(configRelPath, setupInterval string, confirmLong, nonInteractive bool) error {
	if err := validateSetupMode(nonInteractive, setupInterval, os.Geteuid()); err != nil {
		return err
	}
	fmt.Println("Setup wizard for CertGOt")
	fmt.Println("----------------------------")

	absConfigPath, err := filepath.Abs(configRelPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	cfg, err := loadConfig(absConfigPath)
	if err != nil {
		if os.Geteuid() == 0 || !errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("could not read config %s: %w", absConfigPath, err)
		}
		restarted, privilegeErr := ensureSetupPrivileges(absConfigPath, setupInterval, confirmLong, nil)
		if privilegeErr != nil {
			return privilegeErr
		}
		if restarted {
			return nil
		}
		return fmt.Errorf("could not read config %s: %w", absConfigPath, err)
	}
	restarted, err := ensureSetupPrivileges(absConfigPath, setupInterval, confirmLong, configEnvironmentReferences(cfg))
	if err != nil {
		return err
	}
	if restarted {
		return nil
	}

	var reader *bufio.Reader
	if !nonInteractive {
		reader = bufio.NewReader(os.Stdin)
	}
	intervalInput, intervalSpan, err := resolveSetupInterval(reader, setupInterval, confirmLong, nonInteractive)
	if err != nil {
		return err
	}

	fmt.Printf("Config source: %s\n", absConfigPath)
	fmt.Printf("Install path:  %s\n", managedBinaryPath)
	fmt.Printf("Storage path:  %s\n", managedStoragePath)
	fmt.Printf("Interval:      %s\n", intervalInput)
	fmt.Println("----------------------------")

	if err := installSetup(absConfigPath, cfg, intervalSpan); err != nil {
		return err
	}

	fmt.Println("Setup completed.")
	fmt.Printf("Binary installed: %s\n", managedBinaryPath)
	fmt.Printf("Config installed: %s\n", managedConfigPath)
	fmt.Printf("Timer interval:   %s\n", intervalInput)
	return nil
}

func validateSetupMode(nonInteractive bool, setupInterval string, euid int) error {
	if !nonInteractive {
		return nil
	}
	if strings.TrimSpace(setupInterval) == "" {
		return fmt.Errorf("--non-interactive requires --setup-interval")
	}
	if euid != 0 {
		return fmt.Errorf("non-interactive setup requires root; run with sudo")
	}
	return nil
}

func resolveSetupInterval(reader *bufio.Reader, setupInterval string, confirmLong, nonInteractive bool) (string, string, error) {
	if strings.TrimSpace(setupInterval) == "" {
		if nonInteractive {
			return "", "", fmt.Errorf("--non-interactive requires --setup-interval")
		}
		if reader == nil {
			return "", "", fmt.Errorf("setup input is unavailable")
		}
		return promptSetupInterval(reader)
	}
	days, intervalSpan, err := parseSetupInterval(setupInterval)
	if err != nil {
		return "", "", err
	}
	if days > 45 && !confirmLong {
		return "", "", fmt.Errorf("intervals above 45 days require --yes")
	}
	return strings.TrimSpace(setupInterval), intervalSpan, nil
}

func ensureSetupPrivileges(absConfigPath, setupInterval string, confirmLong bool, preserveEnvironment []string) (bool, error) {
	if os.Geteuid() == 0 {
		return false, nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("resolve executable path: %w", err)
	}

	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return false, fmt.Errorf("setup requires root and sudo is not available")
	}

	fmt.Println("Setup requires root privileges. Requesting sudo access...")

	args := make([]string, 0, 8)
	if len(preserveEnvironment) > 0 {
		args = append(args, "--preserve-env="+strings.Join(preserveEnvironment, ","))
	}
	args = append(args, exePath, "--setup", "--config", absConfigPath)
	if strings.TrimSpace(setupInterval) != "" {
		args = append(args, "--setup-interval", setupInterval)
	}
	if confirmLong {
		args = append(args, "--yes")
	}
	cmd := exec.Command(sudoPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		return true, fmt.Errorf("sudo setup failed: %w", err)
	}

	return true, nil
}

func configEnvironmentReferences(cfg *Config) []string {
	telegram := telegramConfig(cfg)
	if telegram == nil {
		return nil
	}
	name, isReference, err := environmentReferenceName(telegram.BotToken)
	if err != nil || !isReference {
		return nil
	}
	return []string{name}
}

func promptSetupInterval(reader *bufio.Reader) (string, string, error) {
	warnedLongInterval := false

	fmt.Println("How often should certgot run?")
	fmt.Println("Enter an interval in format <number><d|w|m>.")
	fmt.Println("Examples: 1d, 2w, 1m")

	for {
		fmt.Print("Interval [default: 2w]: ")

		raw, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", "", fmt.Errorf("read interval: %w", err)
		}

		raw = strings.TrimSpace(raw)
		if raw == "" {
			raw = "2w"
		}

		days, systemdInterval, err := parseSetupInterval(raw)
		if err != nil {
			fmt.Printf("Invalid interval: %v\n\n", err)
			if err == io.EOF {
				return "", "", err
			}
			continue
		}

		if days > 45 && !warnedLongInterval {
			fmt.Println("Warning: intervals above 45 days not recommended. Run certgot more often if possible.")
			fmt.Println("Enter interval again to confirm, or give shorter one.")
			fmt.Println("")
			warnedLongInterval = true
			continue
		}

		return raw, systemdInterval, nil
	}
}

func parseSetupInterval(raw string) (int, string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if len(raw) < 2 {
		return 0, "", fmt.Errorf("expected format like 1d, 2w, or 1m")
	}

	unit := raw[len(raw)-1]
	value, err := strconv.Atoi(raw[:len(raw)-1])
	if err != nil || value <= 0 {
		return 0, "", fmt.Errorf("expected positive number before unit")
	}

	var days int
	switch unit {
	case 'd':
		days = value
	case 'w':
		days = value * 7
	case 'm':
		days = value * 30
	default:
		return 0, "", fmt.Errorf("unsupported unit %q; use d, w, or m", string(unit))
	}

	return days, fmt.Sprintf("%dd", days), nil
}

func installSetup(configPath string, cfg *Config, interval string) error {
	if err := validateManagedReloadPolicy(cfg); err != nil {
		return err
	}
	consumerGroups, err := configuredConsumerGroups(cfg, user.LookupGroup)
	if err != nil {
		return err
	}

	fmt.Println("Installing binary...")
	if err := installBinary(managedBinaryPath); err != nil {
		return err
	}

	fmt.Println("Ensuring group exists...")
	if err := ensureGroupExists(managedStorageGroup); err != nil {
		return err
	}
	if err := ensureUserExists(managedRuntimeUser, managedStorageGroup); err != nil {
		return err
	}

	fmt.Println("Installing config...")
	if err := installConfig(configPath, cfg); err != nil {
		return err
	}

	fmt.Println("Creating storage directories...")
	if err := installStorageLayout(); err != nil {
		return err
	}

	fmt.Println("Writing systemd unit files...")
	telegramEnvironment := telegramConfig(cfg) != nil
	if err := installSystemdUnits(interval, consumerGroups, telegramEnvironment); err != nil {
		return err
	}

	fmt.Println("Reloading systemd and starting timer...")
	if err := runCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := runCommand("systemctl", "enable", "--now", "certgot.timer"); err != nil {
		return err
	}
	if err := runCommand("systemctl", "restart", "certgot.timer"); err != nil {
		return err
	}

	return nil
}

func validateManagedReloadPolicy(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is required")
	}
	for _, cert := range cfg.Certificates {
		if len(cert.ReloadUnits) > 0 {
			return fmt.Errorf("reload_units for %s are disabled in managed mode; use an external root-owned systemd path/service or remove reload_units", cert.Domain)
		}
	}
	return nil
}

func installBinary(targetPath string) error {
	sourcePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("create binary directory: %w", err)
	}

	if filepath.Clean(sourcePath) != filepath.Clean(targetPath) {
		if err := copyFile(sourcePath, targetPath, 0755); err != nil {
			return fmt.Errorf("install binary to %s: %w", targetPath, err)
		}
	}

	if err := os.Chmod(targetPath, 0755); err != nil {
		return fmt.Errorf("chmod binary %s: %w", targetPath, err)
	}
	if err := os.Chown(targetPath, 0, 0); err != nil {
		return fmt.Errorf("chown binary %s: %w", targetPath, err)
	}

	return nil
}

func ensureGroupExists(groupName string) error {
	if _, err := user.LookupGroup(groupName); err == nil {
		return nil
	}

	var cmd *exec.Cmd
	if groupaddPath, err := exec.LookPath("groupadd"); err == nil {
		cmd = exec.Command(groupaddPath, "--system", groupName)
	} else if addgroupPath, err := exec.LookPath("addgroup"); err == nil {
		cmd = exec.Command(addgroupPath, "--system", groupName)
	} else {
		return fmt.Errorf("could not find groupadd or addgroup to create group %s", groupName)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if _, lookupErr := user.LookupGroup(groupName); lookupErr == nil {
			return nil
		}
		return fmt.Errorf("create group %s: %v: %s", groupName, err, strings.TrimSpace(string(output)))
	}

	return nil
}

func ensureUserExists(userName, groupName string) error {
	if _, err := user.Lookup(userName); err == nil {
		return nil
	}
	const noLoginShell = "/usr/sbin/nologin"
	var cmd *exec.Cmd
	if useraddPath, err := exec.LookPath("useradd"); err == nil {
		cmd = exec.Command(useraddPath, "--system", "--no-create-home", "--shell", noLoginShell, "--gid", groupName, userName)
	} else if adduserPath, err := exec.LookPath("adduser"); err == nil {
		cmd = exec.Command(adduserPath, "--system", "--no-create-home", "--shell", noLoginShell, "--ingroup", groupName, userName)
	} else {
		return fmt.Errorf("could not find useradd or adduser to create user %s", userName)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if _, lookupErr := user.Lookup(userName); lookupErr == nil {
			return nil
		}
		return fmt.Errorf("create user %s: %v: %s", userName, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func installConfig(configPath string, cfg *Config) error {
	if err := os.MkdirAll(managedConfigDir, 0750); err != nil {
		return fmt.Errorf("create config directory %s: %w", managedConfigDir, err)
	}
	if err := os.Chmod(managedConfigDir, 0750); err != nil {
		return fmt.Errorf("chmod config directory %s: %w", managedConfigDir, err)
	}
	group, err := user.Lookup(managedStorageGroup)
	if err != nil {
		return fmt.Errorf("lookup runtime group: %w", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return fmt.Errorf("invalid runtime group id: %w", err)
	}
	if err := os.Chown(managedConfigDir, 0, gid); err != nil {
		return fmt.Errorf("chown config directory %s: %w", managedConfigDir, err)
	}
	if err := os.MkdirAll(managedSecretsDir, 0750); err != nil {
		return fmt.Errorf("create secrets directory %s: %w", managedSecretsDir, err)
	}
	if err := os.Chmod(managedSecretsDir, 0750); err != nil {
		return fmt.Errorf("chmod secrets directory %s: %w", managedSecretsDir, err)
	}
	if err := os.Chown(managedSecretsDir, 0, gid); err != nil {
		return fmt.Errorf("chown secrets directory %s: %w", managedSecretsDir, err)
	}

	installedConfig, err := prepareManagedConfig(cfg, managedSecretsDir, gid, writeEnvironmentFile)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(installedConfig)
	if err != nil {
		return fmt.Errorf("marshal config %s: %w", configPath, err)
	}

	if err := backupExistingFile(managedConfigPath); err != nil {
		return fmt.Errorf("backup config %s: %w", managedConfigPath, err)
	}
	if err := writeFileAtomic(managedConfigPath, data, 0600); err != nil {
		return fmt.Errorf("write config %s: %w", managedConfigPath, err)
	}
	if err := os.Chmod(managedConfigPath, 0640); err != nil {
		return fmt.Errorf("chmod config %s: %w", managedConfigPath, err)
	}
	if err := os.Chown(managedConfigPath, 0, gid); err != nil {
		return fmt.Errorf("chown config %s: %w", managedConfigPath, err)
	}

	return nil
}

type managedSecretWriter func(path string, values map[string]string, gid int) error

func prepareManagedConfig(cfg *Config, secretsDir string, gid int, writeSecret managedSecretWriter) (*Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	installed := *cfg
	installed.StoragePath = managedStoragePath
	installed.Certificates = append([]CertConfig(nil), cfg.Certificates...)
	for index := range installed.Certificates {
		source := cfg.Certificates[index]
		cert := &installed.Certificates[index]
		values := map[string]string{}
		if source.EnvFile != "" {
			fileValues, err := loadEnvironmentFile(source.EnvFile)
			if err != nil {
				return nil, fmt.Errorf("load env_file for %s: %w", source.Domain, err)
			}
			values = mergeEnvironment(values, fileValues)
		}
		values = mergeEnvironment(values, source.Env)
		if source.EnvFile == "" && len(source.Env) == 0 {
			continue
		}
		envPath := filepath.Join(secretsDir, fmt.Sprintf("%02d-%s.env", index, source.Domain))
		if err := writeSecret(envPath, values, gid); err != nil {
			return nil, err
		}
		cert.EnvFile = envPath
		cert.Env = nil
	}
	if telegram := telegramConfig(cfg); telegram != nil {
		resolved, err := resolveEnvironmentReference(telegram.BotToken)
		if err != nil {
			return nil, fmt.Errorf("resolve Telegram bot token: %w", err)
		}
		name, isReference, err := environmentReferenceName(telegram.BotToken)
		if err != nil {
			return nil, err
		}
		if !isReference {
			return nil, fmt.Errorf("Telegram bot token must be an environment reference")
		}
		if err := writeSecret(filepath.Join(secretsDir, filepath.Base(managedTelegramEnvPath)), map[string]string{name: resolved}, gid); err != nil {
			return nil, err
		}
	}
	return &installed, nil
}

func writeEnvironmentFile(path string, values map[string]string, gid int) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var content strings.Builder
	for _, key := range keys {
		if !validEnvironmentName(key) || strings.ContainsAny(values[key], "\x00\n\r") {
			return fmt.Errorf("invalid environment file value for %q", key)
		}
		content.WriteString(key)
		content.WriteByte('=')
		content.WriteString(values[key])
		content.WriteByte('\n')
	}
	if err := writeFileAtomic(path, []byte(content.String()), 0640); err != nil {
		return fmt.Errorf("write environment file %s: %w", path, err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return fmt.Errorf("chown environment file %s: %w", path, err)
	}
	return nil
}

func backupExistingFile(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return copyFile(path, path+".bak", 0600)
}

func installStorageLayout() error {
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{path: managedStoragePath, mode: 0755},
		{path: filepath.Join(managedStoragePath, "certs"), mode: 0750},
		{path: filepath.Join(managedStoragePath, "accounts"), mode: 0700},
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir.path, dir.mode); err != nil {
			return fmt.Errorf("create storage directory %s: %w", dir.path, err)
		}
		if err := os.Chmod(dir.path, dir.mode); err != nil {
			return fmt.Errorf("chmod storage directory %s: %w", dir.path, err)
		}
	}

	if err := setManagedStorageOwnership(managedStoragePath); err != nil {
		return err
	}

	return nil
}

func installSystemdUnits(interval string, consumerGroups []string, telegramEnvironment bool) error {
	telegramEnvironmentFile := ""
	if telegramEnvironment {
		telegramEnvironmentFile = managedTelegramEnvPath
	}
	serviceData := map[string]string{
		"BinPath":             managedBinaryPath,
		"ConfigPath":          managedConfigPath,
		"SupplementaryGroups": strings.Join(consumerGroups, " "),
		"EnvironmentFile":     telegramEnvironmentFile,
	}
	timerData := map[string]string{
		"Interval": interval,
	}

	serviceText, err := renderTpl(serviceTpl, serviceData)
	if err != nil {
		return fmt.Errorf("render service unit: %w", err)
	}
	timerText, err := renderTpl(timerTpl, timerData)
	if err != nil {
		return fmt.Errorf("render timer unit: %w", err)
	}
	if err := backupExistingFile(managedServicePath); err != nil {
		return fmt.Errorf("backup service unit: %w", err)
	}
	if err := backupExistingFile(managedTimerPath); err != nil {
		return fmt.Errorf("backup timer unit: %w", err)
	}
	if err := writeFileAtomic(managedServicePath, []byte(serviceText), 0644); err != nil {
		return fmt.Errorf("write service unit %s: %w", managedServicePath, err)
	}
	if err := writeFileAtomic(managedTimerPath, []byte(timerText), 0644); err != nil {
		return fmt.Errorf("write timer unit %s: %w", managedTimerPath, err)
	}
	if err := os.Chown(managedServicePath, 0, 0); err != nil {
		return fmt.Errorf("chown service unit %s: %w", managedServicePath, err)
	}
	if err := os.Chown(managedTimerPath, 0, 0); err != nil {
		return fmt.Errorf("chown timer unit %s: %w", managedTimerPath, err)
	}

	return nil
}

var systemGroupNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`)

func validSystemGroupName(name string) bool {
	return len(name) <= 32 && systemGroupNamePattern.MatchString(name)
}

func configuredConsumerGroups(cfg *Config, lookup func(string) (*user.Group, error)) ([]string, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	seen := make(map[string]struct{})
	for _, cert := range cfg.Certificates {
		groupName := strings.TrimSpace(cert.Group)
		if groupName == "" {
			continue
		}
		if !validSystemGroupName(groupName) {
			return nil, fmt.Errorf("invalid certificate consumer group %q", groupName)
		}
		if groupName == managedStorageGroup {
			continue
		}
		if _, exists := seen[groupName]; exists {
			continue
		}
		if _, err := lookup(groupName); err != nil {
			return nil, fmt.Errorf("certificate consumer group %q does not exist: %w", groupName, err)
		}
		seen[groupName] = struct{}{}
	}
	groups := make([]string, 0, len(seen))
	for groupName := range seen {
		groups = append(groups, groupName)
	}
	sort.Strings(groups)
	return groups, nil
}

func copyFile(sourcePath, targetPath string, mode os.FileMode) error {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	tempFile, err := os.CreateTemp(filepath.Dir(targetPath), filepath.Base(targetPath)+".tmp-*")
	if err != nil {
		return err
	}

	tempPath := tempFile.Name()
	success := false
	defer func() {
		_ = tempFile.Close()
		if !success {
			_ = os.Remove(tempPath)
		}
	}()

	if _, err := io.Copy(tempFile, sourceFile); err != nil {
		return err
	}
	if err := tempFile.Chmod(mode); err != nil {
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, targetPath); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(targetPath)); err != nil {
		return err
	}

	success = true
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	return internalstorage.WriteFileAtomic(path, data, mode)
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func renderTpl(tplStr string, data map[string]string) (string, error) {
	t, err := template.New("t").Parse(tplStr)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := t.Execute(&sb, data); err != nil {
		return "", err
	}
	return sb.String(), nil
}

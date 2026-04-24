package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

const serviceTpl = `[Unit]
Description=ACME DNS certGOt
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={{.BinPath}} --config {{.ConfigPath}}

[Install]
WantedBy=multi-user.target
`

const timerTpl = `[Unit]
Description=ACME DNS certGOt interval timer

[Timer]
OnBootSec=5m
OnUnitActiveSec={{.Interval}}
Persistent=true
Unit=certgot.service

[Install]
WantedBy=timers.target
`

func runSystemdWizard(configRelPath string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Setup wizard for CertGOt")
	fmt.Println("----------------------------")

	absConfigPath, _ := filepath.Abs(configRelPath)
	restarted, err := ensureSetupPrivileges(absConfigPath)
	if err != nil {
		panic(fmt.Sprintf("Setup failed: %v", err))
	}
	if restarted {
		return
	}

	cfg, err := loadConfig(absConfigPath)
	if err != nil {
		panic(fmt.Sprintf("Setup failed: could not read config %s: %v", absConfigPath, err))
	}

	intervalInput, intervalSpan, err := promptSetupInterval(reader)
	if err != nil {
		panic(fmt.Sprintf("Setup failed: %v", err))
	}

	fmt.Printf("Config source: %s\n", absConfigPath)
	fmt.Printf("Install path:  %s\n", managedBinaryPath)
	fmt.Printf("Storage path:  %s\n", managedStoragePath)
	fmt.Printf("Interval:      %s\n", intervalInput)
	fmt.Println("----------------------------")

	if err := installSetup(absConfigPath, cfg, intervalSpan); err != nil {
		panic(fmt.Sprintf("Setup failed: %v", err))
	}

	fmt.Println("Setup completed.")
	fmt.Printf("Binary installed: %s\n", managedBinaryPath)
	fmt.Printf("Config installed: %s\n", managedConfigPath)
	fmt.Printf("Timer interval:   %s\n", intervalInput)
}

func ensureSetupPrivileges(absConfigPath string) (bool, error) {
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

	cmd := exec.Command(sudoPath, exePath, "--setup", "--config", absConfigPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		return true, fmt.Errorf("sudo setup failed: %w", err)
	}

	return true, nil
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
	fmt.Println("Installing binary...")
	if err := installBinary(managedBinaryPath); err != nil {
		return err
	}

	fmt.Println("Ensuring group exists...")
	if err := ensureGroupExists(managedStorageGroup); err != nil {
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
	if err := installSystemdUnits(interval); err != nil {
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

func installConfig(configPath string, cfg *Config) error {
	if err := os.MkdirAll(managedConfigDir, 0750); err != nil {
		return fmt.Errorf("create config directory %s: %w", managedConfigDir, err)
	}
	if err := os.Chmod(managedConfigDir, 0750); err != nil {
		return fmt.Errorf("chmod config directory %s: %w", managedConfigDir, err)
	}
	if err := os.Chown(managedConfigDir, 0, 0); err != nil {
		return fmt.Errorf("chown config directory %s: %w", managedConfigDir, err)
	}

	cfg.StoragePath = managedStoragePath
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config %s: %w", configPath, err)
	}

	if err := writeFileAtomic(managedConfigPath, data, 0600); err != nil {
		return fmt.Errorf("write config %s: %w", managedConfigPath, err)
	}
	if err := os.Chown(managedConfigPath, 0, 0); err != nil {
		return fmt.Errorf("chown config %s: %w", managedConfigPath, err)
	}

	return nil
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

func installSystemdUnits(interval string) error {
	serviceData := map[string]string{
		"BinPath":    managedBinaryPath,
		"ConfigPath": managedConfigPath,
	}
	timerData := map[string]string{
		"Interval": interval,
	}

	if err := writeFileAtomic(managedServicePath, []byte(renderTpl(serviceTpl, serviceData)), 0644); err != nil {
		return fmt.Errorf("write service unit %s: %w", managedServicePath, err)
	}
	if err := writeFileAtomic(managedTimerPath, []byte(renderTpl(timerTpl, timerData)), 0644); err != nil {
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

	success = true
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tempFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
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

	if _, err := tempFile.Write(data); err != nil {
		return err
	}
	if err := tempFile.Chmod(mode); err != nil {
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}

	success = true
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func renderTpl(tplStr string, data map[string]string) string {
	t, _ := template.New("t").Parse(tplStr)
	var sb strings.Builder
	_ = t.Execute(&sb, data)
	return sb.String()
}

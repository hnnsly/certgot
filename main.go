package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"gopkg.in/yaml.v3"
)

// --- Config Structs ---
type Config struct {
	Email        string       `yaml:"email"`
	TelegramURL  string       `yaml:"telegram_url"`
	StoragePath  string       `yaml:"storage_path"`
	Certificates []CertConfig `yaml:"certificates"`
}

type CertConfig struct {
	Domain      string            `yaml:"domain"`
	Provider    string            `yaml:"provider"`
	Env         map[string]string `yaml:"env"`
	Permissions string            `yaml:"permissions"`
	Group       string            `yaml:"group"`
}

// --- Report Structs ---
type ResultType int

const (
	ResultSuccess ResultType = iota
	ResultValid
	ResultError
)

const (
	managedStoragePath  = "/var/lib/certgot"
	managedStorageOwner = "root"
	managedStorageGroup = "certgot"
	managedBinaryPath   = "/usr/local/bin/certgot"
	managedConfigDir    = "/etc/certgot"
	managedConfigPath   = "/etc/certgot/config.yml"
	managedServicePath  = "/etc/systemd/system/certgot.service"
	managedTimerPath    = "/etc/systemd/system/certgot.timer"
)

type CheckResult struct {
	Type     ResultType
	Domain   string
	DaysLeft int
	Until    time.Time
	Error    error
}

// --- ACME User ---
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string                        { return u.Email }
func (u *MyUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *MyUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// --- Main ---

func main() {
	enforceLongOnlySetupFlag(os.Args[1:])

	configPath := flag.String("config", "config.yaml", "Path to the config (alias: -c)")
	configPathShort := flag.String("c", "", "Path to the config (shorthand for --config)")
	setupMode := flag.Bool("setup", false, "Run the Systemd unit creation wizard")
	flag.Parse()

	if strings.TrimSpace(*configPathShort) != "" {
		configPath = configPathShort
	}

	if *setupMode {
		runSystemdWizard(*configPath)
		return
	}

	absConfigPath, _ := filepath.Abs(*configPath)
	cfg, err := loadConfig(absConfigPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Init Directories
	certDir := filepath.Join(cfg.StoragePath, "certs")
	accountDir := filepath.Join(cfg.StoragePath, "accounts")
	os.MkdirAll(certDir, 0755)
	os.MkdirAll(accountDir, 0700)
	ensureManagedStorageOwnership(cfg.StoragePath)

	// Init User & Lego
	user, err := getOrCreateUser(cfg.Email, accountDir)
	if err != nil {
		log.Fatalf("User error: %v", err)
	}
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = lego.LEDirectoryProduction
	legoConfig.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		log.Fatalf("Client error: %v", err)
	}
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatalf("Registration error: %v", err)
		}
		user.Registration = reg
	}

	// Process
	var results []CheckResult
	for _, certCfg := range cfg.Certificates {
		res := processDomain(client, certCfg, certDir)
		results = append(results, res)
		fmt.Println(formatOneLineConsole(res))
	}
	ensureManagedStorageOwnership(cfg.StoragePath)

	// Send Report
	if err := sendTelegramDirect(cfg.TelegramURL, results); err != nil {
		log.Printf("Failed to send telegram: %v", err)
	} else {
		log.Println("Report sent to Telegram")
	}
}

func enforceLongOnlySetupFlag(args []string) {
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		if strings.HasPrefix(trimmed, "-setup") && !strings.HasPrefix(trimmed, "--setup") {
			log.Fatalf("Use --setup (single-dash -setup is not supported)")
		}
	}
}

// --- Logic ---

func processDomain(client *lego.Client, cfg CertConfig, certDir string) CheckResult {
	domainDir := filepath.Join(certDir, cfg.Domain)
	os.MkdirAll(domainDir, 0755)

	pemPath := filepath.Join(domainDir, "fullchain.pem")

	daysLeft, expiry, exists := checkCertFile(pemPath)
	if exists && daysLeft > 30 {
		return CheckResult{Type: ResultValid, Domain: cfg.Domain, DaysLeft: daysLeft, Until: expiry}
	}

	// Set ENV
	for k, v := range cfg.Env {
		os.Setenv(k, v)
	}
	defer func() {
		for k := range cfg.Env {
			os.Unsetenv(k)
		}
	}()

	provider, err := dns.NewDNSChallengeProviderByName(cfg.Provider)
	if err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}

	request := certificate.ObtainRequest{
		Domains: []string{cfg.Domain, "*." + cfg.Domain},
		Bundle:  true,
	}

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}

	if err := saveToDisk(domainDir, cfg.Domain, certs, cfg); err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: fmt.Errorf("save failed: %w", err)}
	}

	newDays, newExpiry, _ := checkCertFile(pemPath)
	return CheckResult{Type: ResultSuccess, Domain: cfg.Domain, DaysLeft: newDays, Until: newExpiry}
}

func checkCertFile(path string) (int, time.Time, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, time.Time{}, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return 0, time.Time{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, time.Time{}, false
	}
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return daysLeft, cert.NotAfter, true
}

func saveToDisk(dir, domain string, certs *certificate.Resource, cfg CertConfig) error {
	pemPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	fullChain := append(certs.Certificate, certs.IssuerCertificate...)
	if err := os.WriteFile(pemPath, fullChain, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
		return err
	}

	// Apply file access control (permissions and group)
	if err := applyFileAccess(dir, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", dir, err)
	}
	if err := applyFileAccess(pemPath, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", pemPath, err)
	}
	if err := applyFileAccess(keyPath, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", keyPath, err)
	}

	return nil
}

// applyFileAccess applies permissions and group ownership to a certificate file
func applyFileAccess(path string, cfg CertConfig) error {
	// Apply permissions if specified
	if cfg.Permissions != "" {
		mode, err := strconv.ParseUint(cfg.Permissions, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid permissions format '%s': %w", cfg.Permissions, err)
		}
		if err := os.Chmod(path, os.FileMode(mode)); err != nil {
			return fmt.Errorf("chmod failed: %w", err)
		}
	}

	// Apply group ownership if specified
	if cfg.Group != "" {
		// Get current owner
		stat, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat failed: %w", err)
		}

		// Get group ID by name
		grp, err := user.LookupGroup(cfg.Group)
		if err != nil {
			return fmt.Errorf("group '%s' not found: %w", cfg.Group, err)
		}

		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			return fmt.Errorf("invalid group id: %w", err)
		}

		// Get current uid from stat
		uid := int(stat.Sys().(*syscall.Stat_t).Uid)

		// Change group ownership
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("chown failed: %w", err)
		}
	}

	return nil
}

func ensureManagedStorageOwnership(storagePath string) {
	if err := setManagedStorageOwnership(storagePath); err != nil {
		log.Printf("Warning: could not apply ownership %s:%s to %s: %v", managedStorageOwner, managedStorageGroup, storagePath, err)
	}
}

func setManagedStorageOwnership(storagePath string) error {
	if filepath.Clean(storagePath) != managedStoragePath {
		return nil
	}

	uid, gid, err := resolveUserGroupIDs(managedStorageOwner, managedStorageGroup)
	if err != nil {
		return err
	}

	return chownRecursive(storagePath, uid, gid)
}

func resolveUserGroupIDs(userName, groupName string) (int, int, error) {
	usr, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup user %q: %w", userName, err)
	}

	grp, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup group %q: %w", groupName, err)
	}

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid uid for %q: %w", userName, err)
	}

	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid gid for %q: %w", groupName, err)
	}

	return uid, gid, nil
}

func chownRecursive(rootPath string, uid, gid int) error {
	return filepath.WalkDir(rootPath, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}

		return nil
	})
}

// --- Formatting & Notification (Direct API) ---

func formatOneLineConsole(r CheckResult) string {
	switch r.Type {
	case ResultSuccess:
		return fmt.Sprintf("[ISSUED] %s (%dd left)", r.Domain, r.DaysLeft)
	case ResultValid:
		return fmt.Sprintf("[VALID] %s (%dd left)", r.Domain, r.DaysLeft)
	case ResultError:
		return fmt.Sprintf("[ERROR] %s: %v", r.Domain, r.Error)
	}
	return ""
}

// escapeMarkdown escapes special characters in Legacy Markdown
func escapeMarkdown(text string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"`", "\\`",
	)
	return replacer.Replace(text)
}

func formatOneLineMarkdown(r CheckResult) string {
	dateStr := r.Until.Format("02.01.2006")
	safeDomain := escapeMarkdown(r.Domain)

	switch r.Type {
	case ResultSuccess:
		return fmt.Sprintf("✅ *Certificate issued:* %s • %dd until %s", safeDomain, r.DaysLeft, dateStr)
	case ResultValid:
		return fmt.Sprintf("🕒 *Certificate valid:* %s • %dd until %s", safeDomain, r.DaysLeft, dateStr)
	case ResultError:
		// Escape error text as it may contain underscores (e.g., acme_challenge)
		safeErr := escapeMarkdown(r.Error.Error())

		// Format as a quote
		errLines := strings.Split(safeErr, "\n")
		var quotedErr strings.Builder
		for _, line := range errLines {
			quotedErr.WriteString(fmt.Sprintf("> %s\n", line))
		}
		return fmt.Sprintf("❌ *Certificate error:* %s\n%s", safeDomain, quotedErr.String())
	}
	return ""
}

// sendTelegramDirect parses shoutrrr-style URL and sends a direct request to the Telegram API
func sendTelegramDirect(rawURL string, results []CheckResult) error {
	// 1. Parse URL: telegram://TOKEN@telegram?chats=CHAT_ID
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid telegram url: %w", err)
	}

	token := u.User.String() // This is the "TOKEN" part before @telegram

	chatParam := u.Query().Get("chats")
	if chatParam == "" {
		return fmt.Errorf("missing 'chats' query param in telegram url")
	}

	// Extract chat_id and message_thread_id (if present)
	var chatID string
	var threadID string
	parts := strings.Split(chatParam, ":")
	chatID = parts[0]
	if len(parts) > 1 {
		threadID = parts[1]
	}

	// Get node FQDN
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// 2. Build the message
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*CertGOt Report |* %s\n\n", escapeMarkdown(hostname)))
	for _, r := range results {
		sb.WriteString(formatOneLineMarkdown(r) + "\n")
	}
	messageText := sb.String()

	// 3. Send JSON request
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       messageText,
		"parse_mode": "Markdown", // Legacy Markdown
	}

	// Add message_thread_id if present
	if threadID != "" {
		payload["message_thread_id"] = threadID
	}

	jsonBody, _ := json.Marshal(payload)

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("http post failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read the response to understand the error
		var body bytes.Buffer
		body.ReadFrom(resp.Body)
		return fmt.Errorf("telegram api error (%d): %s", resp.StatusCode, body.String())
	}

	return nil
}

// --- Helpers ---
func loadConfig(path string) (*Config, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(f, &cfg)
	return &cfg, err
}

func getOrCreateUser(email, dir string) (*MyUser, error) {
	keyFile := filepath.Join(dir, "account.key")
	var privateKey crypto.PrivateKey
	if keyBytes, err := os.ReadFile(keyFile); err == nil {
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			privateKey, _ = x509.ParseECPrivateKey(block.Bytes)
		}
	}
	if privateKey == nil {
		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		privateKey = newKey
		keyBytes, _ := x509.MarshalECPrivateKey(newKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		os.WriteFile(keyFile, pemBytes, 0600)
	}
	return &MyUser{Email: email, key: privateKey}, nil
}

// --- Systemd Wizard ---

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
		log.Fatalf("Setup failed: %v", err)
	}
	if restarted {
		return
	}

	cfg, err := loadConfig(absConfigPath)
	if err != nil {
		log.Fatalf("Setup failed: could not read config %s: %v", absConfigPath, err)
	}

	intervalInput, intervalSpan, err := promptSetupInterval(reader)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	fmt.Printf("Config source: %s\n", absConfigPath)
	fmt.Printf("Install path:  %s\n", managedBinaryPath)
	fmt.Printf("Storage path:  %s\n", managedStoragePath)
	fmt.Printf("Interval:      %s\n", intervalInput)
	fmt.Println("----------------------------")

	if err := installSetup(absConfigPath, cfg, intervalSpan); err != nil {
		log.Fatalf("Setup failed: %v", err)
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
	fmt.Println("Enter an interval in the format <number><d|w|m>.")
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
			fmt.Println("Warning: intervals above 45 days are not recommended. Run certgot more frequently if possible.")
			fmt.Println("Enter the interval again to confirm, or provide a shorter one.")
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
		return 0, "", fmt.Errorf("expected a positive number before the unit")
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
		tempFile.Close()
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
		tempFile.Close()
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
	t.Execute(&sb, data)
	return sb.String()
}

func escapeEcho(s string) string {
	return strings.ReplaceAll(s, "\n", "\\n")
}
